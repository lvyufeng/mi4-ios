/* Original numeric codec; no vendor structures or hardware access. */
#ifndef MI4_RPM_RBCPR_SNAPSHOT_H
#define MI4_RPM_RBCPR_SNAPSHOT_H
#include <stdbool.h>
#include <stdint.h>
#define MI4_RPM_RBCPR_POINTER_SLOT UINT32_C(0xfc190010)
#define MI4_RPM_RBCPR_MAX_READS 24u
#define MI4_RPM_RBCPR_NO_FAILED_SLOT 24u
/* Status is a change counter, NOT a version, magic or odd/even seqlock. */
enum mi4_rpm_rbcpr_result {
    MI4_RPM_RBCPR_INVALID = 0, MI4_RPM_RBCPR_OK,
    MI4_RPM_RBCPR_READ_FAILED, MI4_RPM_RBCPR_BAD_POINTER,
    MI4_RPM_RBCPR_BAD_LAYOUT, MI4_RPM_RBCPR_CHANGED
};
/* Callback: zero succeeds; any nonzero fails and its output is ignored.
 * ctx may be NULL. Adapter must whitelist addresses, stop on faults, and
 * enforce its own deadline (10ms probe gate); this pure codec has no clock. */
typedef int (*mi4_rpm_rbcpr_read_cb)(void *ctx, uint32_t address, uint32_t *out);
struct mi4_rpm_rbcpr_sample {
    uint32_t pointer, block_address, num_rails, status_before;
    uint32_t num_corners, num_recommends, programmed_voltage_raw[3];
    uint32_t current_corner, railway_voltage_raw, status_after, pointer_after;
    uint32_t valid_mask; /* bits 0..11 mark successful reads, even invalid values */
    bool valid; /* complete twelve reads AND per-pass checks passed */
};
struct mi4_rpm_rbcpr_snapshot {
    struct mi4_rpm_rbcpr_sample samples[2];
    uint32_t successful_reads, attempted_reads, failed_slot, last_address;
    enum mi4_rpm_rbcpr_result result;
    bool stable_sampled, reported_nominal_or_higher;
    bool write_authorized, live_freshness_proved, supply_floor_proved;
};
/* Exactly two passes, no retries; at most 24 callbacks in this exact order:
 * slot,A+0,A+4,A+8,A+c,A+14,A+5c,A+a4,A+e8,A+ec,A+4,slot.
 * Only the validated first pointer fixes A; subsequent pointers must match.
 * Supports rail count 1/2 (CX/GFX), reads only inline CX, not a remote pointer.
 * CX corners: 0 OFF,1 SVS,2 NOMINAL,3 TURBO; rail stride 0xf0.
 * Shape match is NOT independent firmware-ABI proof; V2 has no magic/version.
 * STABLE_SAMPLED means no observed drift, NOT atomicity/freshness/POWER_SAFE.
 * Programmed/railway values are RAW: source does not guarantee their units.
 * Recommended microvolts is explicitly named in source but is not sampled.
 * No ADC measurement, permanent supply floor, writes or permission bypass.
 * out is cleared before any callback, including invalid-reader calls.
 * Caller must supply nonoverlapping out/context storage and a safe callback.
 */
enum mi4_rpm_rbcpr_result mi4_rpm_rbcpr_snapshot(
    mi4_rpm_rbcpr_read_cb reader, void *ctx, struct mi4_rpm_rbcpr_snapshot *out);
#endif
