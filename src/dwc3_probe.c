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
#ifndef STAGE90_RPM_RBCPR_SNAPSHOT
#define STAGE90_RPM_RBCPR_SNAPSHOT 0
#endif
#ifndef STAGE90_SPMI_S2_READ
#define STAGE90_SPMI_S2_READ 0
#endif
#if STAGE90_SPMI_S2_READ != 0 && STAGE90_SPMI_S2_READ != 1
#error STAGE90_SPMI_S2_READ_must_be_zero_or_one
#endif
#if STAGE90_SPMI_S2_READ && (STAGE90_DWC3_READONLY != 1 || STAGE90_DWC3_TARGET_READS != 1 || !defined(STAGE90_GUARDED_IRQ_ONLY) || STAGE90_GUARDED_IRQ_ONLY != 1 || !defined(STAGE90_GUARDED_STORE32) || STAGE90_GUARDED_STORE32 != 1 || STAGE90_GUARDED_STORE_SELFTEST != 0 || STAGE90_DWC3_CLOCK_SNAPSHOT != 0 || STAGE90_DWC3_ROOT_SNAPSHOT != 0 || STAGE90_RPM_RBCPR_SNAPSHOT != 0)
#error STAGE90_SPMI_S2_READ_requires_READONLY_IRQ_TARGET_STORE_and_no_SELFTEST_CLOCK_ROOT_RPM
#endif
#if STAGE90_RPM_RBCPR_SNAPSHOT != 0 && STAGE90_RPM_RBCPR_SNAPSHOT != 1
#error STAGE90_RPM_RBCPR_SNAPSHOT_must_be_zero_or_one
#endif
#if STAGE90_RPM_RBCPR_SNAPSHOT && (STAGE90_DWC3_READONLY != 1 || STAGE90_DWC3_TARGET_READS != 1 || !defined(STAGE90_GUARDED_IRQ_ONLY) || STAGE90_GUARDED_IRQ_ONLY != 1 || STAGE90_GUARDED_STORE_SELFTEST != 0 || STAGE90_DWC3_CLOCK_SNAPSHOT != 0 || STAGE90_DWC3_ROOT_SNAPSHOT != 0)
#error STAGE90_RPM_RBCPR_SNAPSHOT_requires_READONLY_IRQ_ONLY_TARGET_and_no_STORE_CLOCK_ROOT
#endif
#if STAGE90_RPM_RBCPR_SNAPSHOT && defined(STAGE90_GUARDED_STORE32) && STAGE90_GUARDED_STORE32 != 0
#error STAGE90_RPM_RBCPR_SNAPSHOT_requires_STORE32_zero
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
#if STAGE90_SPMI_S2_READ
#include "spmi_s2_read.h"
#elif STAGE90_RPM_RBCPR_SNAPSHOT
#include "rpm_rbcpr_snapshot.h"
#else
#include "dwc3_identify.h"
#endif
#include "stage90_guarded_read32.h"

extern uint8_t stage90_vectors[];

#if !STAGE90_RPM_RBCPR_SNAPSHOT && !STAGE90_SPMI_S2_READ
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
#endif

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

#if STAGE90_GUARDED_STORE_SELFTEST || STAGE90_SPMI_S2_READ
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

#if STAGE90_SPMI_S2_READ
struct spmi_probe_context { uint64_t start; unsigned reads, writes, stopped; };

static int spmi_probe_address_allowed(uint32_t address)
{
    return address == UINT32_C(0xfc4cf000) || address == UINT32_C(0xfc4cf808) ||
        address == UINT32_C(0xfc4caf20) || address == UINT32_C(0xfc4cf818);
}

static int spmi_probe_read(void *opaque, uint32_t address, uint32_t *value)
{
    struct spmi_probe_context *context = opaque;
    int result;
    if (!context) return -1;
    if (!value || context->stopped || !spmi_probe_address_allowed(address) ||
        context->reads >= 207u ||
        timebase_elapsed_us(context->start, timebase_ticks()) >= 10000u) {
        context->stopped = 1u;
        return -1;
    }
    ++context->reads;
    xnu_log_kv32("spmi_ro_read_index", context->reads);
    xnu_log_kv32("spmi_ro_read_address", address);
    result = stage90_guarded_read32(address, value);
    xnu_log_kv32("spmi_ro_read_result", (uint32_t)result);
    if (!result) xnu_log_kv32("spmi_ro_read_value", *value);
    else context->stopped = 1u;
    return result;
}

static int spmi_probe_write(void *opaque, uint32_t address, uint32_t value)
{
    struct spmi_probe_context *context = opaque;
    int result;
    if (!context) return -1;
    if (context->stopped || context->writes >= 2u || address != UINT32_C(0xfc4cf800) ||
        value != (context->writes == 0u ? UINT32_C(0x08517401) : UINT32_C(0x08517451)) ||
        timebase_elapsed_us(context->start, timebase_ticks()) >= 10000u) {
        context->stopped = 1u;
        return -1;
    }
    ++context->writes;
    xnu_log_kv32("spmi_ro_write_index", context->writes);
    xnu_log_kv32("spmi_ro_write_address", address);
    xnu_log_kv32("spmi_ro_write_value", value);
    result = stage90_guarded_write32(address, value);
    if (!result && (stage90_guarded_read32_state.active != 0u ||
        stage90_guarded_read32_state.status != STAGE90_GUARDED_OK ||
        stage90_guarded_read32_state.operation != 1u)) result = -1;
    xnu_log_kv32("spmi_ro_write_result", (uint32_t)result);
    if (result) context->stopped = 1u;
    return result;
}

static int spmi_probe_time(void *opaque, uint64_t *value)
{
    struct spmi_probe_context *context = opaque;
    if (!context || !value || context->stopped) return -1;
    *value = (uint64_t)timebase_elapsed_us(context->start, timebase_ticks());
    return 0;
}

static int spmi_probe_delay(void *opaque, uint32_t usec)
{
    struct spmi_probe_context *context = opaque;
    if (!context) return -1;
    if (context->stopped || usec != 1u ||
        timebase_elapsed_us(context->start, timebase_ticks()) >= 10000u) {
        context->stopped = 1u;
        return -1;
    }
    delay_us(1u);
    return 0;
}
#elif STAGE90_RPM_RBCPR_SNAPSHOT
struct rpm_probe_context { unsigned attempted, phase, stopped; uint32_t block; uint64_t start; };
static const uint32_t rpm_probe_offsets[10] = {
    0u, 4u, 8u, 12u, 20u, 92u, 164u, 232u, 236u, 4u
};

static int rpm_probe_address_allowed(const struct rpm_probe_context *context, uint32_t address)
{
    if (context->phase == 0u || context->phase == 11u)
        return address == UINT32_C(0xfc190010);
    return context->phase <= 10u && context->block != 0u &&
        address == context->block + rpm_probe_offsets[context->phase - 1u];
}

static int rpm_probe_read(void *opaque, uint32_t address, uint32_t *value)
{
    struct rpm_probe_context *context = opaque;
    int result;
    if (!value || !context || context->stopped || !rpm_probe_address_allowed(context, address) ||
        context->attempted >= 24u ||
        timebase_elapsed_us(context->start, timebase_ticks()) >= 10000u)
        return -1;
    ++context->attempted;
    xnu_log_kv32("rpm_ro_read_index", context->attempted);
    xnu_log_kv32("rpm_ro_read_address", address);
    result = stage90_guarded_read32(address, value);
    xnu_log_kv32("rpm_ro_read_result", (uint32_t)result);
    if (!result) {
        xnu_log_kv32("rpm_ro_read_value", *value);
        if (address == UINT32_C(0xfc190010) && !context->block &&
            *value >= UINT32_C(0x00190014) && *value <= UINT32_C(0x0019f7fc) &&
            (*value & 3u) == 0u)
            context->block = UINT32_C(0xfc000000) + *value;
        context->phase = (context->phase + 1u) % 12u;
    } else context->stopped = 1u;
    return result;
}
#else
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
#endif

void stage90_dwc3_readonly_probe(void)
{
    const struct stage90_hw_watchdog_result *watchdog;
#if STAGE90_SPMI_S2_READ
    static struct spmi_s2_output spmi_snapshot;
    struct spmi_probe_context context;
#elif STAGE90_RPM_RBCPR_SNAPSHOT
    struct mi4_rpm_rbcpr_snapshot rpm_snapshot;
    struct rpm_probe_context context;
#else
    struct mi4_dwc3_identity identity;
#if STAGE90_DWC3_ROOT_SNAPSHOT
    struct mi4_dwc3_root_snapshot root_snapshot;
#endif
    struct dwc3_probe_context context;
#endif
    uint32_t cpsr, sctlr, vbar, ttbr0, ttbcr, dacr;
    uint32_t *table;
    uint32_t enable = 0, count_first = 0, count_second = 0;
    static unsigned attempted;

    if (attempted) return;
    attempted = 1;
#if STAGE90_SPMI_S2_READ
    xnu_log_puts("SPMI PM8841 S2 read transactions; no PMIC voltage writes\n");
#elif STAGE90_RPM_RBCPR_SNAPSHOT
    xnu_log_puts("RPM RBCPR V2 read-only snapshot; no clock or supply writes\n");
#elif STAGE90_GUARDED_STORE_SELFTEST
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
#if STAGE90_RPM_RBCPR_SNAPSHOT
    if (table[UINT32_C(0xfc100000) >> 20] !=
            (UINT32_C(0xfc100000) | STAGE90_PMAP_DESC_SECTION_SO)) {
        xnu_log_puts("dwc3_ro skipped: RPM data mapping mismatch\n");
        return;
    }
#endif
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
#if STAGE90_SPMI_S2_READ
    if (dwc3_probe_store_selftest(table) == 0) return;
#endif
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
#if !STAGE90_SPMI_S2_READ
    context.attempted = 0;
#endif
    context.start = timebase_ticks();
#if STAGE90_SPMI_S2_READ
    {
        const struct spmi_s2_callbacks callbacks = {
            spmi_probe_read, spmi_probe_write, spmi_probe_time, spmi_probe_delay
        };
        context.reads = context.writes = context.stopped = 0;
        (void)spmi_s2_read(&callbacks, &context, &spmi_snapshot);
    }
    xnu_log_kv32("spmi_ro_status", (uint32_t)spmi_snapshot.result);
    xnu_log_kv32("spmi_ro_read_attempts", spmi_snapshot.read_attempts);
    xnu_log_kv32("spmi_ro_completed_reads", spmi_snapshot.read_completed);
    xnu_log_kv32("spmi_ro_write_attempts", spmi_snapshot.write_attempted);
    xnu_log_kv32("spmi_ro_completed_writes", spmi_snapshot.write_completed);
    xnu_log_kv32("spmi_ro_indeterminate", spmi_snapshot.indeterminate);
    xnu_log_kv32("spmi_ro_valid_mask", spmi_snapshot.valid_mask);
    if (spmi_snapshot.sample_valid[0]) xnu_log_kv32("spmi_ro_data_zero", spmi_snapshot.data_raw[0]);
    if (spmi_snapshot.sample_valid[1]) xnu_log_kv32("spmi_ro_data_one", spmi_snapshot.data_raw[1]);
    if (spmi_snapshot.decoded) {
        xnu_log_kv32("spmi_ro_range_raw", spmi_snapshot.range_raw);
        xnu_log_kv32("spmi_ro_vset_raw", spmi_snapshot.vset_raw);
        xnu_log_kv32("spmi_ro_setpoint_uv", spmi_snapshot.setpoint_uv);
        xnu_log_kv32("spmi_ro_mode_raw", spmi_snapshot.mode_raw);
        xnu_log_kv32("spmi_ro_enable_raw", spmi_snapshot.enable_raw);
    }
    xnu_log_puts("spmi_ro finished; programmed setpoint only; no clock-write authorization\n");
#elif STAGE90_RPM_RBCPR_SNAPSHOT
    context.phase = context.stopped = 0;
    context.block = 0;
    (void)mi4_rpm_rbcpr_snapshot(rpm_probe_read, &context, &rpm_snapshot);
    xnu_log_kv32("rpm_ro_status", (uint32_t)rpm_snapshot.result);
    xnu_log_kv32("rpm_ro_completed_reads", rpm_snapshot.successful_reads);
    /* Core attempts include adapter preflight failures; read_index is actual loads only. */
    xnu_log_kv32("rpm_ro_attempted_reads", rpm_snapshot.attempted_reads);
    xnu_log_kv32("rpm_ro_failed_slot", rpm_snapshot.failed_slot);
    xnu_log_kv32("rpm_ro_sample_zero_valid", rpm_snapshot.samples[0].valid_mask);
    xnu_log_kv32("rpm_ro_sample_one_valid", rpm_snapshot.samples[1].valid_mask);
    xnu_log_puts("rpm_ro finished; sampled telemetry only; no clock-write authorization\n");
#else
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
#endif
}
#else
void stage90_dwc3_readonly_probe(void) { }
#endif
