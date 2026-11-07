/* ARMv7-A ARM state only. No literal-pool loads, MMIO writes, or C init fixup.
 * r0=address, r1=trusted RAM sample pointer. Leaf uses only volatile registers.
 * Existing vectors preserve r0-r3/r12/lr and SPSR_abt on exception return.
 */
#include "stage90_guarded_profile.h"
.syntax unified
.arch armv7-a
.cpu cortex-a15
.arm
.text
.align 2
.global stage90_guarded_read32_load_arm
.type stage90_guarded_read32_load_arm, %function
stage90_guarded_read32_load_arm:
    dsb sy                  /* ordering only; NOT a bus timeout */
    isb sy
    mov r2, #0              /* architectural register initialization */
.global stage90_guarded_read32_fault
.type stage90_guarded_read32_fault, %function
stage90_guarded_read32_fault:
    ldr r2, [r0]            /* THE ONLY target-address load, exactly 32 bits */
.size stage90_guarded_read32_fault, 4
    dsb sy                  /* imprecise abort here is off-PC: MUST park */
    isb sy
    str r2, [r1]            /* trusted RAM sample only, not caller out */
    mov r0, #0
    bx lr
.global stage90_guarded_read32_recovery
.type stage90_guarded_read32_recovery, %function
stage90_guarded_read32_recovery:
    mov r0, #2              /* nonzero: NO sample/out store on fault */
    bx lr
.size stage90_guarded_read32_recovery, . - stage90_guarded_read32_recovery
.size stage90_guarded_read32_load_arm, . - stage90_guarded_read32_load_arm

.align 2
.global stage90_guarded_read32_irq_save
.type stage90_guarded_read32_irq_save, %function
stage90_guarded_read32_irq_save:
    mrs r0, cpsr
    and r1, r0, #0x1f
    cmp r1, #0x13           /* only SVC caller, not arbitrary exception modes */
    bxne lr
    tst r0, #0x20          /* reject Thumb */
    bxne lr
    tst r0, #0x200         /* reject big endian */
    bxne lr
    tst r0, #0x01000000    /* reject Jazelle */
    bxne lr
#if STAGE90_GUARDED_IRQ_ONLY
    cpsid i                /* do not attempt F or A changes */
#else
    cpsid if               /* preserve A, mode, and all other CPSR fields */
#endif
    isb sy
    bx lr
.size stage90_guarded_read32_irq_save, . - stage90_guarded_read32_irq_save

.align 2
.global stage90_guarded_read32_irq_restore
.type stage90_guarded_read32_irq_restore, %function
stage90_guarded_read32_irq_restore:
    mrs r1, cpsr
#if STAGE90_GUARDED_IRQ_ONLY
    bic r1, r1, #0x80
    and r0, r0, #0x80
#else
    bic r1, r1, #0xc0
    and r0, r0, #0xc0
#endif
    orr r1, r1, r0
    msr cpsr_c, r1          /* restore only selected original mask bit(s) */
    isb sy
    bx lr
.size stage90_guarded_read32_irq_restore, . - stage90_guarded_read32_irq_restore

.align 2
.global stage90_guarded_read32_cpsr_read
.type stage90_guarded_read32_cpsr_read, %function
stage90_guarded_read32_cpsr_read:
    mrs r0, cpsr
    bx lr
.size stage90_guarded_read32_cpsr_read, . - stage90_guarded_read32_cpsr_read

.align 2
.global stage90_guarded_read32_park
.type stage90_guarded_read32_park, %function
stage90_guarded_read32_park:
    cpsid if
1:  wfe                    /* already-armed external watchdog may bite */
    b 1b                   /* deliberately no logger/control/MMIO writes */
.size stage90_guarded_read32_park, . - stage90_guarded_read32_park
.section .note.GNU-stack,"",%progbits
