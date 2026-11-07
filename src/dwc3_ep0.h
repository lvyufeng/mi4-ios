/* Original offline USB request planner; no controller or event adapter. */
#ifndef DWC3_EP0_H
#define DWC3_EP0_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define DWC3_EP0_MAX_DESCRIPTORS 16u
#define DWC3_EP0_MAX_DESCRIPTOR_BYTES 4096u
#define DWC3_EP0_MAX_PACKET 64u /* Offline HS profile, NOT a register setting. */

struct dwc3_ep0_descriptor {
    uint8_t type, index;
    uint16_t language;
    const uint8_t *bytes;
    size_t length; /* Accessible immutable bytes, not an advertised length. */
};

enum dwc3_ep0_direction { DWC3_EP0_OUT, DWC3_EP0_IN };
enum dwc3_ep0_action {
    DWC3_EP0_STALL, DWC3_EP0_DATA_IN,
    DWC3_EP0_STATUS_IN, DWC3_EP0_STATUS_OUT
};
enum dwc3_ep0_pending {
    DWC3_EP0_PENDING_NONE, DWC3_EP0_PENDING_ADDRESS, DWC3_EP0_PENDING_CONFIG
};
enum dwc3_ep0_phase {
    DWC3_EP0_UNRESET, DWC3_EP0_IDLE, DWC3_EP0_DATA,
    DWC3_EP0_STATUS_PHASE_IN, DWC3_EP0_STATUS_PHASE_OUT
};

struct dwc3_ep0_in_shape {
    size_t length;
    bool data_stage, data_zlp;
    enum dwc3_ep0_direction status_direction;
};
/* A zero response with positive wLength is one zero-length DATA IN packet,
 * NOT an absent data stage. data_zlp means that terminating packet is needed
 * (one packet total if length == 0). wLength == 0 has no DATA and STATUS IN.
 * This arithmetic helper does not create a transaction or bypass validation. */
struct dwc3_ep0_in_shape dwc3_ep0_shape_in(size_t response_length,
                                        uint16_t requested_length);

struct dwc3_ep0_plan {
    enum dwc3_ep0_action action;
    enum dwc3_ep0_direction status_direction; /* Meaningful unless STALL. */
    uint64_t transaction; /* Reject stale completions, including after reset. */
    const uint8_t *data;
    size_t length; /* Always <= wLength AND accessible response bytes. */
    bool data_zlp;
    enum dwc3_ep0_pending pending;
    uint8_t pending_value;
};

/* Caller-owned storage; fields are observable but MUST NOT be modified.
 * Non-copyable, single-owner/non-reentrant. Descriptors/table outlive this
 * object and all returned plans, and remain immutable after init. data points
 * into that table or reply[]; consume before the next setup/reset/completion.
 * Every old plan is invalid after new SETUP/reset, even when its bytes survive.
 */
struct dwc3_ep0 {
    const struct dwc3_ep0_descriptor *descriptors;
    size_t descriptor_count;
    uint64_t transaction;
    uint8_t address, configuration, pending_value, reply[2];
    enum dwc3_ep0_pending pending;
    enum dwc3_ep0_phase phase;
};

/* Caller table profile: config value 1, interface 0/alt 0/vendor class,
 * one HS bulk IN 0x81 (512-byte descriptor MPS), no bulk OUT/remote wakeup.
 * Bounds/shape/topology validated before any SETUP is accepted. No allocation.
 * Init once per lifetime; init is NOT a bus reset. Must call bus_reset before
 * first SETUP. Reinitializing while completions exist violates ownership.
 */
bool dwc3_ep0_init(struct dwc3_ep0 *ep,
                  const struct dwc3_ep0_descriptor *table, size_t count);
void dwc3_ep0_bus_reset(struct dwc3_ep0 *ep);
/* Exact eight accessible bytes required; unaligned inputs allowed, explicit LE.
 * Every new SETUP, including malformed/unsupported, aborts previous pending
 * work. Exhaustion at UINT64_MAX fails closed until a fresh object lifetime.
 */
struct dwc3_ep0_plan dwc3_ep0_setup(struct dwc3_ep0 *ep,
                                  const uint8_t *setup, size_t length);
/* Complete the ENTIRE DATA stage, including any required terminating ZLP.
 * Same-token wrong direction/phase/failure cancels; stale token does nothing.
 * A real adapter must derive success from hardware, never from queuing a TRB.
 */
struct dwc3_ep0_plan dwc3_ep0_data_complete(struct dwc3_ep0 *ep,
    uint64_t transaction, enum dwc3_ep0_direction direction, bool success);
/* Only successful matching STATUS completion commits pending SOFTWARE address/config.
 * Returns true only for that successful completion; false never commits.
 * This does NOT specify when hardware DCFG.DEVADDR is staged or latched; the
 * controller adapter needs its own request/status/reset reconciliation contract.
 * Configuration here is software intent, NOT endpoint readiness or enablement.
 */
bool dwc3_ep0_status_complete(struct dwc3_ep0 *ep, uint64_t transaction,
                            enum dwc3_ep0_direction direction, bool success);

/* Optional ORIGINAL synthetic fixture: 0x1234:0x0001, NOT assigned identities,
 * not for enumeration on hardware. No serial, real device IDs, or copied text.
 * Four descriptors / 63 bytes. Caller may supply a different validated table.
 */
extern const struct dwc3_ep0_descriptor dwc3_ep0_fixture[4];

#endif
