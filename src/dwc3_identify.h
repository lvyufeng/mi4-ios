/* Original read-only inspection core. No MMIO adapter or controller writes. */
#ifndef MI4_DWC3_IDENTIFY_H
#define MI4_DWC3_IDENTIFY_H
#include <stddef.h>
#include <stdint.h>

#define MI4_DWC3_BASE UINT32_C(0xf9200000)
#define MI4_GCC_BASE UINT32_C(0xfc400000)
#define MI4_DWC3_GSNPSID UINT32_C(0xc120)
#define MI4_DWC3_GCTL UINT32_C(0xc110)
#define MI4_DWC3_GHWPARAMS0 UINT32_C(0xc140)
#define MI4_DWC3_GHWPARAMS1 UINT32_C(0xc144)
#define MI4_DWC3_GUSB2PHYCFG0 UINT32_C(0xc200)
#define MI4_DWC3_DCFG UINT32_C(0xc700)
#define MI4_DWC3_DCTL UINT32_C(0xc704)
#define MI4_DWC3_DSTS UINT32_C(0xc70c)
#define MI4_DWC3_ID_MASK UINT32_C(0xffff0000)
#define MI4_DWC3_ID_MAGIC UINT32_C(0x55330000)
#define MI4_DWC3_REVISION_220A UINT32_C(0x5533220a)
#define MI4_DWC3_CLOCK_COUNT 5u
#define MI4_DWC3_REGISTER_COUNT 8u

/* Return zero only when a complete read succeeded. This module cannot recover a
 * stalled bus: the adapter owns mapping, barriers, power, access permissions and
 * watchdog recovery. Clock flags are necessary checks, not a no-hang guarantee.
 * No read callback may write/initialize the controller to satisfy a precondition.
 */
typedef int (*mi4_dwc3_read32)(void *context, uint32_t address, uint32_t *value);
enum mi4_dwc3_identify_status {
    MI4_DWC3_IDENTIFY_OK,
    MI4_DWC3_IDENTIFY_INVALID,
    MI4_DWC3_IDENTIFY_READ_FAILED,
    MI4_DWC3_IDENTIFY_CLOCK_BLOCKED,
    MI4_DWC3_IDENTIFY_RESET_ASSERTED,
    MI4_DWC3_IDENTIFY_ROOT_BLOCKED,
    MI4_DWC3_IDENTIFY_WRONG_ID
};
struct mi4_dwc3_identity {
    enum mi4_dwc3_identify_status status;
    uint32_t clock_values[MI4_DWC3_CLOCK_COUNT];
    uint32_t bcr;
    uint32_t root_command;
    uint32_t registers[MI4_DWC3_REGISTER_COUNT];
    uint32_t valid_clocks;
    uint32_t valid_registers;
    unsigned bcr_valid;
    unsigned root_valid;
    unsigned completed_reads;
    unsigned failed_slot; /* 0..4 clocks, 5 BCR, 6 root, 7..14 core; UINT32_MAX if none */
};
/* Entry 0 of registers is GSNPSID. register indices 1..7 follow header order.
 * All five branch clocks must be explicitly enabled with CBCR[31:28] equal
 * to ON (0x0) or NOC_FSM_ON (0x2); unknown/transitional states are rejected.
 * Reset must be deasserted, and root enabled/running with no update/dirty
 * bits. Only then is GSNPSID read. A bad ID prevents every later core read.
 * Snapshots may race with external power/clock owners; serialize externally.
 * Output is initialized before callbacks, including every failure path.
 * This is identification ONLY, not a functioning USB link or speed measurement.
 */
enum mi4_dwc3_identify_status mi4_dwc3_identify(
    mi4_dwc3_read32 reader, void *context, struct mi4_dwc3_identity *output);

/* Independent GCC-only diagnostic, never calls mi4_dwc3_identify or reads DWC3.
 * The adapter must independently establish that all seven GCC registers remain
 * readable with USB branches disabled; this API does not establish power state.
 * Reads the same five CBCRs, BCR, then root CMD once each, regardless of values.
 * Stops on the first callback error, retaining only fully completed samples.
 * Output initialization/validity and failed_slot follow the identity contract;
 * registers and valid_registers always remain zero. Only INVALID, READ_FAILED
 * and OK are returned. OK means a complete snapshot, NOT controller identity,
 * enabled clocks, safe core access, a functioning USB link or speed proof.
 */
enum mi4_dwc3_identify_status mi4_dwc3_clock_snapshot(
    mi4_dwc3_read32 reader, void *context, struct mi4_dwc3_identity *output);

struct mi4_dwc3_root_snapshot {
    struct mi4_dwc3_identity clocks;
    uint32_t values[6]; /* CFG, M, N, D, GPLL0 status, APCS vote, in that order. */
    uint32_t valid_extra;
};
/* Raw thirteen-GCC-register snapshot; no identity or clock-readiness inference.
 * Reads the seven clock-snapshot addresses once, then CFG/M/N/D, GPLL0 status
 * and APCS vote. The adapter independently owns mapping/readability/guarding.
 * Fully initializes output; stops at the first callback error, preserving only
 * complete samples. clocks.completed_reads counts ALL thirteen slots, and
 * clocks.failed_slot is 0..12 (UINT32_MAX if none); slots 7..12 are values[].
 * clocks.registers/valid_registers remain zero. valid_extra marks only completed
 * extra reads. Returns INVALID, READ_FAILED, or OK (snapshot complete only).
 * Raw PLL status is not a generic lock-bit contract; vote is not ownership.
 */
enum mi4_dwc3_identify_status mi4_dwc3_root_snapshot(
    mi4_dwc3_read32 reader, void *context, struct mi4_dwc3_root_snapshot *output);
#endif
