/* Host-only: executes the ACTUAL production-candidate C policy/wrapper.
 * No MMIO dereference, ARM execution, Apple code execution, or exception claim.
 */
#include "stage90_guarded_read32.h"
#include <setjmp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

_Alignas(4) const unsigned char stage90_guarded_read32_fault[4] = {0};
_Alignas(4) const unsigned char stage90_guarded_read32_recovery[4] = {0};
static unsigned cases, checks, leaf_calls, saves, restores, parks;
static uint32_t fake_cpsr, masks, restore_value, value;
static int behavior, park_expected, ineffective_mask;
static jmp_buf park_jump;
#define CHECK(x) do { ++checks; if (!(x)) { \
    fprintf(stderr, "FAIL line %d: %s\n", __LINE__, #x); exit(1); } } while (0)
#define CASE() do { ++cases; } while (0)
static uint32_t fault_pc(void) { return (uint32_t)(uintptr_t)stage90_guarded_read32_fault; }
static uint32_t recovery_pc(void) { return (uint32_t)(uintptr_t)stage90_guarded_read32_recovery; }
static uint32_t dfsr_code(unsigned code) { return (code & 15u) | ((code & 16u) << 6); }
static int documented(unsigned code)
{
    return code == 3 || code == 5 || code == 6 || code == 7 || code == 8 ||
           code == 9 || code == 11 || code == 12 || code == 13 || code == 14 || code == 15;
}
static struct stage90_guarded_read32_state armed(void)
{
    struct stage90_guarded_read32_state s = {0};
    s.active = 1; s.expected_address = 0xf9000100u;
    s.fault_pc = fault_pc(); s.recovery_pc = recovery_pc();
    s.status = STAGE90_GUARDED_ARMED;
    return s;
}
static void frame_init(uint32_t *frame)
{
    for (unsigned i = 0; i < 6; ++i) frame[i] = 0x11220000u + i;
    frame[5] = fault_pc();
}
uint32_t stage90_guarded_read32_irq_save(void)
{
    ++saves;
    if ((fake_cpsr & 0x0100023fu) == 0x13u)
        masks = (fake_cpsr | 0xc0u) & ~(uint32_t)ineffective_mask;
    return fake_cpsr;
}
uint32_t stage90_guarded_read32_cpsr_read(void) { return masks; }
void stage90_guarded_read32_irq_restore(uint32_t saved)
{
    ++restores; restore_value = saved; masks = (masks & ~0xc0u) | (saved & 0xc0u);
}
_Noreturn void stage90_guarded_read32_park(void)
{
    ++parks;
    CHECK(park_expected);
    longjmp(park_jump, 1);
}
int stage90_guarded_read32_load_arm(uint32_t address, uint32_t *sample)
{
    uint32_t frame[6];
    enum stage90_guarded_abort_result got;
    ++leaf_calls;
    CHECK(stage90_guarded_read32_state.active == 1);
    CHECK(stage90_guarded_read32_state.expected_address == address);
    CHECK((masks & 0xc0u) == 0xc0u);
    if (behavior == 0) { *sample = value; return 0; }
    if (behavior == 5) {
        CHECK(stage90_guarded_read32(address, sample) == STAGE90_GUARDED_BUSY);
        *sample = value; return 0;
    }
    frame_init(frame);
    if (behavior == 2) frame[5] += 4;
    got = stage90_guarded_read32_abort_policy(&stage90_guarded_read32_state,
        frame, behavior == 3 ? dfsr_code(0x16) : 5u, address, masks);
    if (got != STAGE90_GUARDED_RECOVERED) stage90_guarded_read32_park();
    CHECK(frame[5] == recovery_pc());
    /* behavior 4 violates the assembly contract; wrapper MUST NOT trust it. */
    if (behavior == 4) { *sample = value; return 0; }
    return STAGE90_GUARDED_FAULT;
}
static void reset(void)
{
    struct stage90_guarded_read32_state zero = {0};
    stage90_guarded_read32_state = zero;
    leaf_calls = saves = restores = parks = 0;
    fake_cpsr = masks = 0x13u; restore_value = 0; value = 0xa5a55a5au;
    behavior = park_expected = ineffective_mask = 0;
}
static void status_matrix(void)
{
    for (unsigned code = 0; code < 32; ++code) {
        for (unsigned write = 0; write < 2; ++write) {
            CASE();
            /* Every 8-bit low DFSR combination: 16 domain nibbles per code.
             * Same FS bits with WnR=0/1, including FS[4] for 0x16.
             */
            for (unsigned domain = 0; domain < 16; ++domain) {
                struct stage90_guarded_read32_state s = armed();
                uint32_t frame[6], before[6]; frame_init(frame);
                memcpy(before, frame, sizeof(frame));
                uint32_t dfsr = dfsr_code(code) | (domain << 4) | (write << 11);
                int accept = documented(code) && !write;
                enum stage90_guarded_abort_result got = stage90_guarded_read32_abort_policy(
                    &s, frame, dfsr, s.expected_address, 0xd3u);
                CHECK(got == (accept ? STAGE90_GUARDED_RECOVERED : STAGE90_GUARDED_UNSUPPORTED));
                CHECK(frame[5] == (accept ? recovery_pc() : fault_pc()));
                CHECK(memcmp(frame, before, 5 * sizeof(uint32_t)) == 0);
                CHECK(s.fault_dfsr == dfsr && s.fault_dfar == s.expected_address);
                CHECK(s.active == 1 && s.fault_count == 1);
                CHECK(s.status == (accept ? STAGE90_GUARDED_FAULT : STAGE90_GUARDED_UNSUPPORTED_STATUS));
            }
        }
    }
}
static void negative_policy(void)
{
    for (unsigned mutation = 0; mutation < 19; ++mutation) {
        CASE(); struct stage90_guarded_read32_state s = armed();
        uint32_t frame[6], dfsr = 5u, dfar = s.expected_address, cpsr = 0xd3u;
        frame_init(frame);
        switch (mutation) {
        case 0: frame[5] += 4; break;
        case 1: frame[5] -= 4; break;
        case 2: dfar += 4; break;
        case 3: s.active = 2; break;
        case 4: s.expected_address |= 1; dfar = s.expected_address; break;
        case 5: s.fault_pc += 4; frame[5] = s.fault_pc; break;
        case 6: s.recovery_pc += 4; break;
        case 7: s.status = STAGE90_GUARDED_FAULT; break;
        case 8: s.fault_count = 1; break;
        case 9: cpsr = 0xd0u; break; /* user */
        case 10: cpsr = 0xd7u; break; /* abort */
        case 11: cpsr |= 0x20u; break; /* Thumb */
        case 12: cpsr |= 0x200u; break; /* big endian */
        case 13: cpsr |= 0x01000000u; break; /* Jazelle */
        case 14: cpsr &= ~0x80u; break; /* IRQ not masked */
        case 15: cpsr &= ~0x40u; break; /* FIQ not masked */
        case 16: dfsr |= 0x200u; break; /* LPAE */
        case 17: dfsr |= 0x10000u; break; /* FnV */
        case 18: dfsr |= 0x2000u; break; /* cache maintenance */
        }
        uint32_t original_pc = frame[5];
        CHECK(stage90_guarded_read32_abort_policy(&s, frame, dfsr, dfar, cpsr) == STAGE90_GUARDED_UNSUPPORTED);
        CHECK(frame[5] == original_pc);
        CHECK(s.status == STAGE90_GUARDED_UNSUPPORTED_STATUS && s.active != 0u);
        CHECK(s.breadcrumb == 0x47524458u);
    }
    CASE(); /* inactive must leave EVERY byte unchanged */
    struct stage90_guarded_read32_state s = armed(), snapshot;
    uint32_t frame[6], before[6]; frame_init(frame); s.active = 0; snapshot = s;
    memcpy(before, frame, sizeof(frame));
    CHECK(stage90_guarded_read32_abort_policy(&s, frame, 0xffffffffu, 0, 0) == STAGE90_GUARDED_NOT_HANDLED);
    CHECK(memcmp(&s, &snapshot, sizeof(s)) == 0 && memcmp(frame, before, sizeof(frame)) == 0);
    CASE(); s = armed();
    CHECK(stage90_guarded_read32_abort_policy(&s, 0, 5, s.expected_address, 0xd3) == STAGE90_GUARDED_UNSUPPORTED);
    CHECK(s.status == STAGE90_GUARDED_UNSUPPORTED_STATUS);
    CASE(); /* ExT is implementation-defined and not a synchronous class bit */
    s = armed(); frame_init(frame);
    CHECK(stage90_guarded_read32_abort_policy(&s, frame, 0x1008u, s.expected_address, 0xd3) == STAGE90_GUARDED_RECOVERED);
    CASE(); /* no second accepted fault even with coincidental exact PC */
    frame[5] = fault_pc();
    CHECK(stage90_guarded_read32_abort_policy(&s, frame, 8, s.expected_address, 0xd3) == STAGE90_GUARDED_UNSUPPORTED);
    CHECK(s.fault_count == 1 && frame[5] == fault_pc());
}
static void lifecycle(void)
{
    uint32_t out;
    CASE(); reset(); out = 0x12345678u;
    CHECK(stage90_guarded_read32(0xf9000100u, &out) == 0 && out == value);
    CHECK(leaf_calls == 1 && stage90_guarded_read32_state.active == 0);
    CHECK(stage90_guarded_read32_state.status == STAGE90_GUARDED_OK && restores == 1 && restore_value == fake_cpsr);
    CASE(); reset(); out = 0x12345678u; behavior = 1;
    CHECK(stage90_guarded_read32(0xf9000100u, &out) != 0 && out == 0x12345678u);
    CHECK(leaf_calls == 1 && stage90_guarded_read32_state.active == 0);
    CHECK(stage90_guarded_read32_state.status == STAGE90_GUARDED_FAULT && stage90_guarded_read32_state.fault_count == 1);
    CASE(); /* success after previous fault resets per-call state */
    behavior = 0; value = 0;
    CHECK(stage90_guarded_read32(0xf9000104u, &out) == 0 && out == 0);
    CHECK(stage90_guarded_read32_state.fault_count == 0 && stage90_guarded_read32_state.fault_dfsr == 0);
    CASE(); reset(); CHECK(stage90_guarded_read32(0xf9000100u, 0) != 0 && leaf_calls == 0 && saves == 0);
    CASE(); reset(); out = 9; CHECK(stage90_guarded_read32(0xf9000101u, &out) != 0 && out == 9 && leaf_calls == 0);
    CASE(); reset(); _Alignas(4) unsigned char bytes[8];
    CHECK(stage90_guarded_read32(0xf9000100u, (uint32_t *)(void *)(bytes + 1)) != 0 && leaf_calls == 0);
    CASE(); reset(); stage90_guarded_read32_state.active = 1; out = 9;
    CHECK(stage90_guarded_read32(0xf9000100u, &out) == STAGE90_GUARDED_BUSY && out == 9 && leaf_calls == 0);
    CHECK(stage90_guarded_read32_state.active == 1 && restores == 1);
    CASE(); reset(); fake_cpsr = masks = 0x10u; out = 9;
    CHECK(stage90_guarded_read32(0xf9000100u, &out) == STAGE90_GUARDED_BAD_CONTEXT && out == 9 && leaf_calls == 0 && restores == 0);
    CASE(); reset(); fake_cpsr = masks = 0x93u; behavior = 5;
    CHECK(stage90_guarded_read32(0xf9000100u, &out) == 0 && restores == 2 && (masks & 0xc0u) == 0x80u);
    for (unsigned bit = 0x40u; bit <= 0xc0u; bit += 0x40u) {
        CASE(); reset(); out = 0x12345678u; ineffective_mask = (int)bit;
        CHECK(stage90_guarded_read32(0xf9000100u, &out) == STAGE90_GUARDED_BAD_CONTEXT);
        CHECK(out == 0x12345678u && leaf_calls == 0 && restores == 1);
        CHECK(stage90_guarded_read32_state.active == 0u);
        CHECK(stage90_guarded_read32_state.cpsr_before_mask == fake_cpsr);
        CHECK(stage90_guarded_read32_state.cpsr_after_mask == (0xd3u & ~bit));
        CHECK((masks & 0xc0u) == (fake_cpsr & 0xc0u));
    }
    for (behavior = 2; behavior <= 4; ++behavior) {
        int selected = behavior; CASE(); reset(); behavior = selected; park_expected = 1; out = 0x12345678u;
        if (setjmp(park_jump) == 0) { (void)stage90_guarded_read32(0xf9000100u, &out); CHECK(0); }
        CHECK(parks == 1 && out == 0x12345678u && restores == 0);
        CHECK(stage90_guarded_read32_state.active == 1 && stage90_guarded_read32_state.status == STAGE90_GUARDED_UNSUPPORTED_STATUS);
    }
}
int main(void)
{
    status_matrix(); negative_policy(); lifecycle();
    printf("PASS: %u meaningful cases, %u assertions; actual C + fake ARM leaf (no hardware)\n", cases, checks);
    return 0;
}
