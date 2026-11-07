#ifndef STAGE90_GUARDED_PROFILE_H
#define STAGE90_GUARDED_PROFILE_H

/* Future-only opt-in. Existing strict IF policy remains the default. */
#ifndef STAGE90_GUARDED_IRQ_ONLY
#define STAGE90_GUARDED_IRQ_ONLY 0
#endif
#if STAGE90_GUARDED_IRQ_ONLY != 0 && STAGE90_GUARDED_IRQ_ONLY != 1
#error "STAGE90_GUARDED_IRQ_ONLY must be 0 or 1"
#endif
#if STAGE90_GUARDED_IRQ_ONLY && (!defined(STAGE90_DWC3_READONLY) || STAGE90_DWC3_READONLY != 1)
#error "IRQ-only guard requires explicit STAGE90_DWC3_READONLY profile"
#endif

/* Shared by C layout assertions and the assembly-only FIQ prefix/park. */
#define STAGE90_GUARD_ACTIVE_OFFSET 0
#define STAGE90_GUARD_STATUS_OFFSET 24
#define STAGE90_GUARD_BREADCRUMB_OFFSET 40
#define STAGE90_GUARD_UNSUPPORTED 7
#define STAGE90_GUARD_FIQ_BREADCRUMB 0x47524651 /* GRFQ */
#define STAGE90_GUARD_STABLE_CPSR 0x010002ffu /* M/T/E/J/I/F; not NZCV/A */

#endif
