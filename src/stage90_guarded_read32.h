#ifndef STAGE90_GUARDED_READ32_H
#define STAGE90_GUARDED_READ32_H

#include <stdint.h>
#include <stddef.h>
#include "stage90_guarded_profile.h"

/* Single CPU/thread, pre-XNU only. Not a whitelist or a bus timeout.
 * Parent owns address allowlist, live watchdog, mapping and trusted RAM checks.
 * No retries. out must be valid writable ordinary RAM, not MMIO.
 * 0 commits one result; every returned nonzero leaves *out unchanged.
 */
enum stage90_guarded_read32_status {
    STAGE90_GUARDED_IDLE = 0,
    STAGE90_GUARDED_ARMED = 1,
    STAGE90_GUARDED_FAULT = 2,
    STAGE90_GUARDED_OK = 3,
    STAGE90_GUARDED_BAD_ARGUMENT = 4,
    STAGE90_GUARDED_BUSY = 5,
    STAGE90_GUARDED_BAD_CONTEXT = 6,
    STAGE90_GUARDED_UNSUPPORTED_STATUS = 7
};

enum stage90_guarded_abort_result {
    STAGE90_GUARDED_NOT_HANDLED = 0,
    STAGE90_GUARDED_RECOVERED = 1,
    STAGE90_GUARDED_UNSUPPORTED = 2
};

/* Fixed-width RAM-only breadcrumb; not an MMIO log or persistent-storage API. */
struct stage90_guarded_read32_state {
    uint32_t active;
    uint32_t expected_address;
    uint32_t fault_pc;
    uint32_t recovery_pc;
    uint32_t fault_dfsr;
    uint32_t fault_dfar;
    uint32_t status;
    uint32_t fault_count;
    uint32_t observed_pc;
    uint32_t observed_spsr;
    uint32_t breadcrumb;
    uint32_t cpsr_before_mask;
    uint32_t cpsr_after_mask;
};

_Static_assert(offsetof(struct stage90_guarded_read32_state, active) == STAGE90_GUARD_ACTIVE_OFFSET, "FIQ active offset");
_Static_assert(offsetof(struct stage90_guarded_read32_state, status) == STAGE90_GUARD_STATUS_OFFSET, "FIQ status offset");
_Static_assert(offsetof(struct stage90_guarded_read32_state, breadcrumb) == STAGE90_GUARD_BREADCRUMB_OFFSET, "FIQ breadcrumb offset");
_Static_assert(STAGE90_GUARDED_UNSUPPORTED_STATUS == STAGE90_GUARD_UNSUPPORTED, "FIQ status value");
#if STAGE90_GUARDED_IRQ_ONLY
/* Link obligation, NOT runtime proof of the installed VBAR/routing/opcodes. */
extern const unsigned char stage90_guarded_fiq_hook_contract[];
#endif

extern volatile struct stage90_guarded_read32_state stage90_guarded_read32_state;
int stage90_guarded_read32(uint32_t address, uint32_t *out);

/* Pure fault policy: no hardware reads, no log calls, no generic PC increment.
 * frame[5] is the adjusted ARM fault PC in the unchanged vectors.S layout.
 * active==0: state/frame unchanged and NOT_HANDLED.
 * accepted: exact recovery PC, one fault recorded; wrapper clears active later.
 * unsupported nonzero active: PC unchanged; RAM evidence retained, then caller
 * MUST park, never invoke the old generic +4 handler. No recovery on second fault.
 */
enum stage90_guarded_abort_result stage90_guarded_read32_abort_policy(
    volatile struct stage90_guarded_read32_state *state,
    uint32_t *frame, uint32_t dfsr, uint32_t dfar, uint32_t saved_cpsr);

/* Internal ARM ABI, also supplied by the host-only fake for C tests. */
extern const unsigned char stage90_guarded_read32_fault[];
extern const unsigned char stage90_guarded_read32_recovery[];
int stage90_guarded_read32_load_arm(uint32_t address, uint32_t *sample);
uint32_t stage90_guarded_read32_irq_save(void);
uint32_t stage90_guarded_read32_cpsr_read(void);
void stage90_guarded_read32_irq_restore(uint32_t saved_cpsr);
_Noreturn void stage90_guarded_read32_park(void);

#endif
