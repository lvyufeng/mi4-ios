/* Original one-shot DWC3 identity probe; no controller/PHY/clock/mux writes. */
#include "stage90.h"

#ifndef STAGE90_DWC3_READONLY
#define STAGE90_DWC3_READONLY 0
#endif
#ifndef STAGE90_DWC3_TARGET_READS
#define STAGE90_DWC3_TARGET_READS 0
#endif
#ifndef STAGE90_DWC3_CLOCK_SNAPSHOT
#define STAGE90_DWC3_CLOCK_SNAPSHOT 0
#endif
#ifndef STAGE90_DWC3_ROOT_SNAPSHOT
#define STAGE90_DWC3_ROOT_SNAPSHOT 0
#endif
#ifndef STAGE90_GUARDED_STORE_SELFTEST
#define STAGE90_GUARDED_STORE_SELFTEST 0
#endif
#if STAGE90_GUARDED_STORE_SELFTEST != 0 && STAGE90_GUARDED_STORE_SELFTEST != 1
#error STAGE90_GUARDED_STORE_SELFTEST_must_be_zero_or_one
#endif
#if STAGE90_GUARDED_STORE_SELFTEST && (!defined(STAGE90_GUARDED_STORE32) || STAGE90_GUARDED_STORE32 != 1 || !defined(STAGE90_GUARDED_IRQ_ONLY) || STAGE90_GUARDED_IRQ_ONLY != 1 || STAGE90_DWC3_READONLY != 1 || STAGE90_DWC3_TARGET_READS != 0 || STAGE90_DWC3_ROOT_SNAPSHOT != 0 || STAGE90_DWC3_CLOCK_SNAPSHOT != 0)
#error STAGE90_GUARDED_STORE_SELFTEST_requires_STORE32_IRQ_ONLY_READONLY_and_no_TARGET_READS
#endif
#if STAGE90_DWC3_ROOT_SNAPSHOT != 0 && STAGE90_DWC3_ROOT_SNAPSHOT != 1
#error STAGE90_DWC3_ROOT_SNAPSHOT_must_be_zero_or_one
#endif
#if STAGE90_DWC3_ROOT_SNAPSHOT && (!STAGE90_DWC3_CLOCK_SNAPSHOT || !STAGE90_DWC3_READONLY || !STAGE90_DWC3_TARGET_READS)
#error STAGE90_DWC3_ROOT_SNAPSHOT_requires_CLOCK_SNAPSHOT_READONLY_and_TARGET_READS
#endif
#if STAGE90_DWC3_CLOCK_SNAPSHOT != 0 && STAGE90_DWC3_CLOCK_SNAPSHOT != 1
#error STAGE90_DWC3_CLOCK_SNAPSHOT_must_be_zero_or_one
#endif
#if STAGE90_DWC3_CLOCK_SNAPSHOT && (!STAGE90_DWC3_READONLY || !STAGE90_DWC3_TARGET_READS)
#error STAGE90_DWC3_CLOCK_SNAPSHOT_requires_READONLY_and_TARGET_READS
#endif
#if STAGE90_DWC3_TARGET_READS != 0 && STAGE90_DWC3_TARGET_READS != 1
#error STAGE90_DWC3_TARGET_READS_must_be_zero_or_one
#endif
#if STAGE90_DWC3_READONLY != 0 && STAGE90_DWC3_READONLY != 1
#error STAGE90_DWC3_READONLY_must_be_zero_or_one
#endif

#if STAGE90_DWC3_READONLY
#include "dwc3_identify.h"
#include "stage90_guarded_read32.h"

extern uint8_t stage90_vectors[];

/* This is an address whitelist, not an MMIO-completion guarantee. */
static int dwc3_probe_address_allowed(uint32_t address)
{
    switch (address) {
    case UINT32_C(0xfc400108):
    case UINT32_C(0xfc4003c8):
    case UINT32_C(0xfc4003d0):
    case UINT32_C(0xfc4003cc):
    case UINT32_C(0xfc4004ac):
    case UINT32_C(0xfc4003c0):
    case UINT32_C(0xfc4003d4):
#if STAGE90_DWC3_ROOT_SNAPSHOT
    case UINT32_C(0xfc4003d8):
    case UINT32_C(0xfc4003dc):
    case UINT32_C(0xfc4003e0):
    case UINT32_C(0xfc4003e4):
    case UINT32_C(0xfc40001c):
    case UINT32_C(0xfc401480):
#endif
#if !STAGE90_DWC3_CLOCK_SNAPSHOT
    case UINT32_C(0xf920c120):
    case UINT32_C(0xf920c110):
    case UINT32_C(0xf920c140):
    case UINT32_C(0xf920c144):
    case UINT32_C(0xf920c200):
    case UINT32_C(0xf920c700):
    case UINT32_C(0xf920c704):
    case UINT32_C(0xf920c70c):
#endif
        return 1;
    default:
        return 0;
    }
}

static int dwc3_probe_guard_selftest(uint32_t *table)
{
    static const uint32_t pattern = UINT32_C(0x47524450);
    const uint32_t unmapped = UINT32_C(0xdeadc000);
    uint32_t sample = UINT32_C(0xa55a12ed);
    int result;

    if (table[unmapped >> 20] != 0u) {
        xnu_log_puts("dwc3_ro skipped: guard selftest address is mapped\n");
        return 0;
    }
    xnu_log_kv32("dwc3_ro_guard_ram_address", (uint32_t)(uintptr_t)&pattern);
    result = stage90_guarded_read32((uint32_t)(uintptr_t)&pattern, &sample);
    xnu_log_kv32("dwc3_ro_guard_ram_result", (uint32_t)result);
    xnu_log_kv32("dwc3_ro_guard_cpsr_before", stage90_guarded_read32_state.cpsr_before_mask);
    xnu_log_kv32("dwc3_ro_guard_cpsr_after", stage90_guarded_read32_state.cpsr_after_mask);
    if (result || sample != pattern) {
        xnu_log_puts("dwc3_ro skipped: guard RAM selftest failed\n");
        return 0;
    }
    sample = UINT32_C(0xa55a12ed);
    xnu_log_kv32("dwc3_ro_guard_fault_address", unmapped);
    result = stage90_guarded_read32(unmapped, &sample);
    xnu_log_kv32("dwc3_ro_guard_fault_result", (uint32_t)result);
    xnu_log_kv32("dwc3_ro_guard_fault_dfsr", stage90_guarded_read32_state.fault_dfsr);
    xnu_log_kv32("dwc3_ro_guard_fault_dfar", stage90_guarded_read32_state.fault_dfar);
    xnu_log_kv32("dwc3_ro_guard_fault_pc", stage90_guarded_read32_state.observed_pc);
    xnu_log_kv32("dwc3_ro_guard_fault_spsr", stage90_guarded_read32_state.observed_spsr);
    xnu_log_kv32("dwc3_ro_guard_fault_count", stage90_guarded_read32_state.fault_count);
    xnu_log_kv32("dwc3_ro_guard_fault_active", stage90_guarded_read32_state.active);
    xnu_log_kv32("dwc3_ro_guard_fault_status", stage90_guarded_read32_state.status);
    xnu_log_kv32("dwc3_ro_guard_fault_output", sample);
    xnu_log_kv32("dwc3_ro_guard_fault_expected_pc", (uint32_t)(uintptr_t)stage90_guarded_read32_fault);
    xnu_log_kv32("dwc3_ro_guard_fault_cpsr_before", stage90_guarded_read32_state.cpsr_before_mask);
    xnu_log_kv32("dwc3_ro_guard_fault_cpsr_after", stage90_guarded_read32_state.cpsr_after_mask);
    if (result != STAGE90_GUARDED_FAULT || sample != UINT32_C(0xa55a12ed) ||
        stage90_guarded_read32_state.active != 0u ||
        stage90_guarded_read32_state.status != STAGE90_GUARDED_FAULT ||
        stage90_guarded_read32_state.fault_count != 1u ||
        stage90_guarded_read32_state.expected_address != unmapped ||
        stage90_guarded_read32_state.fault_dfar != unmapped ||
        (stage90_guarded_read32_state.fault_dfsr & UINT32_C(0x40f)) != 5u ||
        stage90_guarded_read32_state.observed_pc !=
            (uint32_t)(uintptr_t)stage90_guarded_read32_fault
#if STAGE90_GUARDED_IRQ_ONLY
        || (stage90_guarded_read32_state.cpsr_after_mask & UINT32_C(0x010002bf)) != UINT32_C(0x93)
        || ((stage90_guarded_read32_state.cpsr_before_mask ^
             stage90_guarded_read32_state.cpsr_after_mask) & UINT32_C(0x0100037f)) != 0u
        || ((stage90_guarded_read32_state.observed_spsr ^
             stage90_guarded_read32_state.cpsr_after_mask) & STAGE90_GUARD_STABLE_CPSR) != 0u
#endif
        ) {
        xnu_log_puts("dwc3_ro skipped: guard translation-fault selftest failed\n");
        return 0;
    }
    xnu_log_puts("dwc3_ro guard selftest passed: RAM and translation-fault recovery\n");
    return 1;
}

#if STAGE90_GUARDED_STORE_SELFTEST
/* Exclusively owned ordinary RAM, never a controller register or rollback. */
static uint32_t dwc3_probe_store_word = UINT32_C(0xa55a12ed);

static int dwc3_probe_store_context_ok(uint32_t restored)
{
    uint32_t before = stage90_guarded_read32_state.cpsr_before_mask;
    uint32_t after = stage90_guarded_read32_state.cpsr_after_mask;
    return (after & UINT32_C(0x010002bf)) == UINT32_C(0x93) &&
        ((before ^ after) & UINT32_C(0x0100037f)) == 0u &&
        ((before ^ restored) & UINT32_C(0x010003ff)) == 0u;
}

static int dwc3_probe_store_selftest(uint32_t *table)
{
    const uint32_t address = (uint32_t)(uintptr_t)&dwc3_probe_store_word;
    const uint32_t unmapped = UINT32_C(0xdeadc000);
    const uint32_t intent = UINT32_C(0x53545231);
    uint32_t sample = 0, restored;
    int result;

    if (table[unmapped >> 20] != 0u) {
        xnu_log_puts("dwc3_ro skipped: guard STORE translation-fault selftest failed\n");
        return 0;
    }
    xnu_log_kv32("dwc3_store_ram_address", address);
    result = stage90_guarded_read32(address, &sample);
    xnu_log_kv32("dwc3_store_ram_before_result", (uint32_t)result);
    if (!result) xnu_log_kv32("dwc3_store_ram_before_value", sample);
    if (result || sample != UINT32_C(0xa55a12ed)) {
        xnu_log_puts("dwc3_ro skipped: guard STORE RAM selftest failed\n");
        return 0;
    }
    xnu_log_kv32("dwc3_store_ram_value", intent);
    result = stage90_guarded_write32(address, intent);
    restored = stage90_guarded_read32_cpsr_read();
    xnu_log_kv32("dwc3_store_ram_result", (uint32_t)result);
    xnu_log_kv32("dwc3_store_ram_active", stage90_guarded_read32_state.active);
    xnu_log_kv32("dwc3_store_ram_status", stage90_guarded_read32_state.status);
    xnu_log_kv32("dwc3_store_ram_count", stage90_guarded_read32_state.fault_count);
    xnu_log_kv32("dwc3_store_ram_operation", stage90_guarded_read32_state.operation);
    xnu_log_kv32("dwc3_store_ram_cpsr_before", stage90_guarded_read32_state.cpsr_before_mask);
    xnu_log_kv32("dwc3_store_ram_cpsr_after", stage90_guarded_read32_state.cpsr_after_mask);
    xnu_log_kv32("dwc3_store_cpsr_restored", restored);
    if (result || stage90_guarded_read32_state.active != 0u ||
        stage90_guarded_read32_state.status != STAGE90_GUARDED_OK ||
        stage90_guarded_read32_state.fault_count != 0u ||
        stage90_guarded_read32_state.operation != 1u ||
        !dwc3_probe_store_context_ok(restored)) {
        xnu_log_puts("dwc3_ro skipped: guard STORE RAM selftest failed\n");
        return 0;
    }
    sample = 0;
    result = stage90_guarded_read32(address, &sample);
    xnu_log_kv32("dwc3_store_ram_readback_result", (uint32_t)result);
    if (!result) xnu_log_kv32("dwc3_store_ram_readback_value", sample);
    if (result || sample != intent) {
        xnu_log_puts("dwc3_ro skipped: guard STORE RAM selftest failed\n");
        return 0;
    }
    xnu_log_kv32("dwc3_store_fault_address", unmapped);
    xnu_log_kv32("dwc3_store_fault_value", UINT32_C(0xfeed1234));
    result = stage90_guarded_write32(unmapped, UINT32_C(0xfeed1234));
    restored = stage90_guarded_read32_cpsr_read();
    xnu_log_kv32("dwc3_store_fault_result", (uint32_t)result);
    xnu_log_kv32("dwc3_store_fault_dfsr", stage90_guarded_read32_state.fault_dfsr);
    xnu_log_kv32("dwc3_store_fault_dfar", stage90_guarded_read32_state.fault_dfar);
    xnu_log_kv32("dwc3_store_fault_pc", stage90_guarded_read32_state.observed_pc);
    xnu_log_kv32("dwc3_store_fault_expected_pc", (uint32_t)(uintptr_t)stage90_guarded_write32_fault);
    xnu_log_kv32("dwc3_store_fault_spsr", stage90_guarded_read32_state.observed_spsr);
    xnu_log_kv32("dwc3_store_fault_count", stage90_guarded_read32_state.fault_count);
    xnu_log_kv32("dwc3_store_fault_active", stage90_guarded_read32_state.active);
    xnu_log_kv32("dwc3_store_fault_status", stage90_guarded_read32_state.status);
    xnu_log_kv32("dwc3_store_fault_operation", stage90_guarded_read32_state.operation);
    xnu_log_kv32("dwc3_store_fault_cpsr_before", stage90_guarded_read32_state.cpsr_before_mask);
    xnu_log_kv32("dwc3_store_fault_cpsr_after", stage90_guarded_read32_state.cpsr_after_mask);
    xnu_log_kv32("dwc3_store_fault_cpsr_restored", restored);
    if (result != STAGE90_GUARDED_WRITE_FAULT || stage90_guarded_read32_state.active != 0u ||
        stage90_guarded_read32_state.status != STAGE90_GUARDED_WRITE_FAULT ||
        stage90_guarded_read32_state.operation != 1u ||
        stage90_guarded_read32_state.fault_count != 1u ||
        stage90_guarded_read32_state.expected_address != unmapped ||
        stage90_guarded_read32_state.fault_dfar != unmapped ||
        (stage90_guarded_read32_state.fault_dfsr & UINT32_C(0xc0f)) != UINT32_C(0x805) ||
        (stage90_guarded_read32_state.fault_dfsr & ~UINT32_C(0x1cff)) != 0u ||
        stage90_guarded_read32_state.observed_pc != (uint32_t)(uintptr_t)stage90_guarded_write32_fault ||
        ((stage90_guarded_read32_state.observed_spsr ^ stage90_guarded_read32_state.cpsr_after_mask) &
            STAGE90_GUARD_STABLE_CPSR) != 0u ||
        !dwc3_probe_store_context_ok(restored)) {
        xnu_log_puts("dwc3_ro skipped: guard STORE translation-fault selftest failed\n");
        return 0;
    }
    return 1;
}
#endif

struct dwc3_probe_context { unsigned attempted; uint64_t start; };

static int dwc3_probe_read(void *opaque, uint32_t address, uint32_t *value)
{
    struct dwc3_probe_context *context = opaque;
    int result;
    if (!value || !context || !dwc3_probe_address_allowed(address) ||
#if STAGE90_DWC3_ROOT_SNAPSHOT
        context->attempted >= 13u ||
#elif STAGE90_DWC3_CLOCK_SNAPSHOT
        context->attempted >= 7u ||
#else
        context->attempted >= 15u ||
#endif
        timebase_elapsed_us(context->start, timebase_ticks()) > 10000u)
        return -1;
    ++context->attempted;
    xnu_log_kv32("dwc3_ro_read_index", context->attempted);
    xnu_log_kv32("dwc3_ro_read_address", address);
    result = stage90_guarded_read32(address, value);
    xnu_log_kv32("dwc3_ro_read_result", (uint32_t)result);
    if (!result) xnu_log_kv32("dwc3_ro_read_value", *value);
    return result;
}

void stage90_dwc3_readonly_probe(void)
{
    const struct stage90_hw_watchdog_result *watchdog;
    struct mi4_dwc3_identity identity;
#if STAGE90_DWC3_ROOT_SNAPSHOT
    struct mi4_dwc3_root_snapshot root_snapshot;
#endif
    struct dwc3_probe_context context;
    uint32_t cpsr, sctlr, vbar, ttbr0, ttbcr, dacr;
    uint32_t *table;
    uint32_t enable = 0, count_first = 0, count_second = 0;
    static unsigned attempted;

    if (attempted) return;
    attempted = 1;
#if STAGE90_GUARDED_STORE_SELFTEST
    xnu_log_puts("DWC3 guarded RAM store selftest; no MMIO target writes\n");
#elif STAGE90_DWC3_ROOT_SNAPSHOT
    xnu_log_puts("DWC3 read-only GCC root snapshot; no DWC3 core reads\n");
#elif STAGE90_DWC3_CLOCK_SNAPSHOT
    xnu_log_puts("DWC3 read-only GCC clock snapshot; no DWC3 core reads\n");
#else
    xnu_log_puts("DWC3 read-only identity probe; no USB initialization\n");
#endif
    __asm__ volatile("mrs %0, cpsr" : "=r"(cpsr));
    __asm__ volatile("mrc p15, 0, %0, c1, c0, 0" : "=r"(sctlr));
    __asm__ volatile("mrc p15, 0, %0, c12, c0, 0" : "=r"(vbar));
    __asm__ volatile("mrc p15, 0, %0, c2, c0, 0" : "=r"(ttbr0));
    __asm__ volatile("mrc p15, 0, %0, c2, c0, 2" : "=r"(ttbcr));
    __asm__ volatile("mrc p15, 0, %0, c3, c0, 0" : "=r"(dacr));
    table = mmu_l1_table();
    if ((cpsr & UINT32_C(0x0100023f)) != UINT32_C(0x13) ||
        (sctlr & UINT32_C(0x52002005)) != 1u || ttbcr != 0u || !table ||
        (dacr & 3u) != 3u ||
        (ttbr0 & UINT32_C(0xffffc000)) != (uint32_t)(uintptr_t)table ||
        vbar != (uint32_t)(uintptr_t)stage90_vectors) {
        xnu_log_puts("dwc3_ro skipped: CPU/MMU/vector precondition\n");
        return;
    }
    if (table[UINT32_C(0xf9200000) >> 20] !=
            (UINT32_C(0xf9200000) | STAGE90_PMAP_DESC_SECTION_SO) ||
        table[UINT32_C(0xfc400000) >> 20] !=
            (UINT32_C(0xfc400000) | STAGE90_PMAP_DESC_SECTION_SO)) {
        xnu_log_puts("dwc3_ro skipped: identity MMIO mapping mismatch\n");
        return;
    }
    watchdog = stage90_hw_watchdog_result();
    if (!watchdog || !watchdog->enabled || !watchdog->counter_running ||
        !watchdog->countdown_plausible || !watchdog->readback_ok ||
        watchdog->bite_truncated || !stage90_deadman_armed()) {
        xnu_log_puts("dwc3_ro skipped: recovery net not confirmed\n");
        return;
    }
#if STAGE90_GUARDED_STORE_SELFTEST
    if (watchdog->countdown_second <= watchdog->countdown_first ||
        watchdog->countdown_second >= watchdog->bark_ticks ||
        watchdog->bark_ticks - watchdog->countdown_second < UINT32_C(65530)) {
        xnu_log_puts("dwc3_ro skipped: recovery net not confirmed\n");
        return;
    }
#endif
    if (!dwc3_probe_guard_selftest(table)) return;
#if STAGE90_GUARDED_STORE_SELFTEST
    if (!dwc3_probe_store_selftest(table)) return;
    xnu_log_puts("dwc3_ro store selftest passed; RAM writes only; controller target reads inhibited\n");
    return;
#endif
#if !STAGE90_DWC3_TARGET_READS
    xnu_log_puts("dwc3_ro recovery verified; controller target reads inhibited\n");
    return;
#endif
    /* Known watchdog reads also use the guarded load; no new watchdog writes. */
    xnu_log_kv32("dwc3_ro_watchdog_read_address", UINT32_C(0xf9017008));
    if (stage90_guarded_read32(UINT32_C(0xf9017008), &enable) ||
        (enable & 1u) == 0u) {
        xnu_log_puts("dwc3_ro skipped: watchdog disabled or unreadable\n");
        return;
    }
    xnu_log_kv32("dwc3_ro_watchdog_read_address", UINT32_C(0xf901700c));
    if (stage90_guarded_read32(UINT32_C(0xf901700c), &count_first)) return;
    delay_us(500u);
    if (stage90_guarded_read32(UINT32_C(0xf901700c), &count_second)) return;
    count_first = (count_first >> 1) & UINT32_C(0xfffff);
    count_second = (count_second >> 1) & UINT32_C(0xfffff);
    xnu_log_kv32("dwc3_ro_watchdog_count_first", count_first);
    xnu_log_kv32("dwc3_ro_watchdog_count_second", count_second);
    if (count_second <= count_first || count_second >= watchdog->bark_ticks ||
        watchdog->bark_ticks - count_second < UINT32_C(65530)) {
        xnu_log_puts("dwc3_ro skipped: watchdog not advancing or insufficient headroom\n");
        return;
    }
    context.attempted = 0;
    context.start = timebase_ticks();
#if STAGE90_DWC3_ROOT_SNAPSHOT
    (void)mi4_dwc3_root_snapshot(dwc3_probe_read, &context, &root_snapshot);
    identity = root_snapshot.clocks;
#elif STAGE90_DWC3_CLOCK_SNAPSHOT
    (void)mi4_dwc3_clock_snapshot(dwc3_probe_read, &context, &identity);
#else
    (void)mi4_dwc3_identify(dwc3_probe_read, &context, &identity);
#endif
    xnu_log_kv32("dwc3_ro_status", (uint32_t)identity.status);
    xnu_log_kv32("dwc3_ro_completed_reads", identity.completed_reads);
    xnu_log_kv32("dwc3_ro_valid_clocks", identity.valid_clocks);
    xnu_log_kv32("dwc3_ro_valid_registers", identity.valid_registers);
#if STAGE90_DWC3_CLOCK_SNAPSHOT
    xnu_log_kv32("dwc3_ro_bcr_valid", identity.bcr_valid);
    xnu_log_kv32("dwc3_ro_root_valid", identity.root_valid);
#endif
#if STAGE90_DWC3_ROOT_SNAPSHOT
    xnu_log_kv32("dwc3_ro_root_extra_valid", root_snapshot.valid_extra);
#endif
    xnu_log_kv32("dwc3_ro_failed_slot", identity.failed_slot);
    xnu_log_kv32("dwc3_ro_elapsed_us", timebase_elapsed_us(context.start, timebase_ticks()));
#if STAGE90_DWC3_ROOT_SNAPSHOT
    xnu_log_puts("dwc3_ro finished; GCC root snapshot only; no DWC3 core reads\n");
#elif STAGE90_DWC3_CLOCK_SNAPSHOT
    xnu_log_puts("dwc3_ro finished; GCC clock snapshot only; no DWC3 core reads\n");
#else
    xnu_log_puts("dwc3_ro finished; identification is not a USB link\n");
#endif
}
#else
void stage90_dwc3_readonly_probe(void) { }
#endif
