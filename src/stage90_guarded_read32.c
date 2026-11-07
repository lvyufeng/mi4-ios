#include "stage90_guarded_read32.h"

volatile struct stage90_guarded_read32_state stage90_guarded_read32_state;

static void compiler_barrier(void)
{
    __asm__ volatile ("" ::: "memory");
}

static int svc_arm_little_endian(uint32_t cpsr)
{
    /* Mode=SVC, T=0, E=0, J=0. Preserve A and all prior IRQ/FIQ state. */
    return (cpsr & 0x0100023fu) == 0x13u;
}

#if STAGE90_GUARDED_IRQ_ONLY
static int irq_only_context(uint32_t before, uint32_t after)
{
    return svc_arm_little_endian(before) && svc_arm_little_endian(after) &&
        (after & 0x80u) != 0u &&
        ((before ^ after) & (STAGE90_GUARD_STABLE_CPSR & ~0x80u)) == 0u &&
        ((before ^ after) & 0x100u) == 0u; /* helper must preserve A too */
}
#endif

static int supported_read_fault(uint32_t dfsr)
{
    uint32_t status = (dfsr & 0x0fu) | ((dfsr >> 6) & 0x10u);
    /* ARMv7 short descriptor only. Reject WnR, LPAE, CM, FnV,
     * reserved/RAS bits. Domain and implementation-defined ExT are ignored.
     * This is intentionally stricter than a general exception handler.
     */
    if ((dfsr & ~0x000014ffu) != 0u)
        return 0;
    switch (status) {
    case 0x03u: /* access flag, section */
    case 0x06u: /* access flag, page */
    case 0x05u: /* translation, section */
    case 0x07u: /* translation, page */
    case 0x09u: /* domain, section */
    case 0x0bu: /* domain, page */
    case 0x0du: /* permission, section */
    case 0x0fu: /* permission, page */
    case 0x08u: /* synchronous external, not a table walk */
    case 0x0cu: /* synchronous external, table walk level 1 */
    case 0x0eu: /* synchronous external, table walk level 2 */
        return 1;
    default: /* includes debug, alignment, imprecise external 0x16 */
        return 0;
    }
}

enum stage90_guarded_abort_result stage90_guarded_read32_abort_policy(
    volatile struct stage90_guarded_read32_state *state,
    uint32_t *frame, uint32_t dfsr, uint32_t dfar, uint32_t saved_cpsr)
{
    int accepted;
    if (state == 0)
        return STAGE90_GUARDED_UNSUPPORTED;
    if (state->active == 0u)
        return STAGE90_GUARDED_NOT_HANDLED;

    accepted = state->active == 1u && frame != 0 &&
        state->status == STAGE90_GUARDED_ARMED && state->fault_count == 0u &&
        state->fault_pc == (uint32_t)(uintptr_t)stage90_guarded_read32_fault &&
        state->recovery_pc == (uint32_t)(uintptr_t)stage90_guarded_read32_recovery &&
        frame[5] == state->fault_pc &&
        (state->expected_address & 3u) == 0u &&
        dfar == state->expected_address &&
#if STAGE90_GUARDED_IRQ_ONLY
        irq_only_context(state->cpsr_before_mask, state->cpsr_after_mask) &&
        ((saved_cpsr ^ state->cpsr_after_mask) & STAGE90_GUARD_STABLE_CPSR) == 0u &&
#else
        svc_arm_little_endian(saved_cpsr) && (saved_cpsr & 0xc0u) == 0xc0u &&
#endif
        supported_read_fault(dfsr);

    /* RAM breadcrumb before returning a disposition; no logger can fault here.
     * Any fault in this capture is off-LDR and MUST fail-stop, never +4 skip.
     */
    state->fault_dfsr = dfsr;
    state->fault_dfar = dfar;
    state->observed_pc = frame != 0 ? frame[5] : 0u;
    state->observed_spsr = saved_cpsr;
    state->fault_count = 1u; /* at most one recorded fault per call */
    state->status = accepted ? STAGE90_GUARDED_FAULT : STAGE90_GUARDED_UNSUPPORTED_STATUS;
    state->breadcrumb = accepted ? 0x47524431u : 0x47524458u; /* GRD1 / GRDX */
    compiler_barrier();
    if (!accepted)
        return STAGE90_GUARDED_UNSUPPORTED;
    frame[5] = state->recovery_pc;
    return STAGE90_GUARDED_RECOVERED;
}

int stage90_guarded_read32(uint32_t address, uint32_t *out)
{
    volatile struct stage90_guarded_read32_state *state = &stage90_guarded_read32_state;
    uint32_t saved_cpsr;
    uint32_t sample; /* only used after successful assembly store, NOT a fixup */
    int rc;

    if (out == 0 || (address & 3u) != 0u || ((uintptr_t)out & 3u) != 0u)
        return STAGE90_GUARDED_BAD_ARGUMENT;
#if STAGE90_GUARDED_IRQ_ONLY
    /* An assembler contract must resolve; linked opcode/VBAR audit still needed. */
    __asm__ volatile ("" : : "r" (stage90_guarded_fiq_hook_contract) : "memory");
#endif
    saved_cpsr = stage90_guarded_read32_irq_save();
    if (!svc_arm_little_endian(saved_cpsr))
        return STAGE90_GUARDED_BAD_CONTEXT; /* save did not change masks */
    if (state->active != 0u) {
        stage90_guarded_read32_irq_restore(saved_cpsr);
        return STAGE90_GUARDED_BUSY;
    }

    state->cpsr_before_mask = saved_cpsr;
    state->cpsr_after_mask = stage90_guarded_read32_cpsr_read();
#if STAGE90_GUARDED_IRQ_ONLY
    if (!irq_only_context(saved_cpsr, state->cpsr_after_mask)) {
#else
    if (!svc_arm_little_endian(state->cpsr_after_mask) ||
        (state->cpsr_after_mask & 0xc0u) != 0xc0u) {
#endif
        state->status = STAGE90_GUARDED_BAD_CONTEXT;
        stage90_guarded_read32_irq_restore(saved_cpsr);
        return STAGE90_GUARDED_BAD_CONTEXT;
    }
    state->expected_address = address;
    state->fault_pc = (uint32_t)(uintptr_t)stage90_guarded_read32_fault;
    state->recovery_pc = (uint32_t)(uintptr_t)stage90_guarded_read32_recovery;
    state->fault_dfsr = 0u;
    state->fault_dfar = 0u;
    state->fault_count = 0u;
    state->observed_pc = 0u;
    state->observed_spsr = 0u;
    state->breadcrumb = 0u;
    state->status = STAGE90_GUARDED_ARMED;
    compiler_barrier();
    state->active = 1u;
    compiler_barrier();

    rc = stage90_guarded_read32_load_arm(address, &sample);
    compiler_barrier();
    if (rc == 0 && state->active == 1u && state->status == STAGE90_GUARDED_ARMED &&
        state->fault_count == 0u) {
        /* Still active during RAM commit: unexpected output-store abort parks. */
        *out = sample;
        state->status = STAGE90_GUARDED_OK;
    } else if (rc != 0 && state->active == 1u &&
               state->status == STAGE90_GUARDED_FAULT && state->fault_count == 1u) {
        rc = STAGE90_GUARDED_FAULT;
    } else {
        state->status = STAGE90_GUARDED_UNSUPPORTED_STATUS;
        state->breadcrumb = 0x47524458u;
        stage90_guarded_read32_park(); /* no fallthrough after broken contract */
    }
    compiler_barrier();
    state->active = 0u;
    compiler_barrier();
    stage90_guarded_read32_irq_restore(saved_cpsr);
    return rc;
}
