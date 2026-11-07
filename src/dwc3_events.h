/* Original offline parser; numerical wire formats checked against vendor core.h. */
#ifndef MI4_DWC3_EVENTS_H
#define MI4_DWC3_EVENTS_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define DWC3_EVENTS_ENTRY_BYTES 4u
#define DWC3_EVENTS_COUNT_MASK UINT32_C(0xfffc)
#define DWC3_EVENTS_DEV_CATEGORY 0u
#define DWC3_EVENTS_CARKIT_CATEGORY 3u
#define DWC3_EVENTS_I2C_CATEGORY 4u
#define DWC3_EVENTS_DEV_DISCONNECT 0u
#define DWC3_EVENTS_DEV_RESET 1u
#define DWC3_EVENTS_DEV_CONNECT_DONE 2u
#define DWC3_EVENTS_DEV_LINK_CHANGE 3u
#define DWC3_EVENTS_DEV_WAKEUP 4u
#define DWC3_EVENTS_DEV_HIBER_REQ 5u
#define DWC3_EVENTS_DEV_EOPF 6u
#define DWC3_EVENTS_DEV_SOF 7u
#define DWC3_EVENTS_DEV_ERRATIC_ERROR 9u
#define DWC3_EVENTS_DEV_CMD_COMPLETE 10u
#define DWC3_EVENTS_DEV_OVERFLOW 11u
#define DWC3_EVENTS_DEV_TEST_LMP 12u
#define DWC3_EVENTS_EP_XFER_COMPLETE 1u
#define DWC3_EVENTS_EP_XFER_IN_PROGRESS 2u
#define DWC3_EVENTS_EP_XFER_NOT_READY 3u
#define DWC3_EVENTS_EP_FIFO 4u
#define DWC3_EVENTS_EP_STREAM 6u
#define DWC3_EVENTS_EP_CMD_COMPLETE 7u

#define DWC3_EVENTS_DIAG_UNKNOWN UINT32_C(1)
#define DWC3_EVENTS_DIAG_RESERVED UINT32_C(2)
#define DWC3_EVENTS_DIAG_OVERFLOW UINT32_C(4)
#define DWC3_EVENTS_DIAG_UNSUPPORTED_LENGTH UINT32_C(8)

enum dwc3_events_family {
    DWC3_EVENTS_ENDPOINT,
    DWC3_EVENTS_DEVICE,
    DWC3_EVENTS_OTHER
};

struct dwc3_event_decoded {
    uint32_t raw;
    uint32_t diagnostics;
    enum dwc3_events_family family;
    bool known;
    uint8_t category;          /* Full non-endpoint bits 1..7, otherwise zero. */
    uint8_t type;              /* Endpoint bits 6..9 or device bits 8..11. */
    uint8_t endpoint_physical; /* Bits 1..5; logical EP = n/2, IN = n%2. */
    uint8_t status;            /* Endpoint bits 12..15, not interpreted. */
    uint16_t parameters;      /* Endpoint bits 16..31, not interpreted. */
    uint8_t info;              /* Device bits 16..23, not interpreted. */
};

/* raw is the host integer value of a little-endian 32-bit event word.
 * Do not memcpy a little-endian word into uint32_t on a big-endian host.
 * The ring API below performs explicit bytewise little-endian loading.
 * No vendor C bitfields, compiler packing, or native-endian loads are used.
 */
struct dwc3_event_decoded dwc3_events_decode(uint32_t raw);

/* A snapshot of the low 16 count bits, including alignment bits, is returned.
 * High bits are reported separately, NOT guessed to mean overflow. Vendor
 * count mask is 0xfffc; keeping bits 0..1 permits strict validation rather
 * than silently rounding down malformed counts. This helper reads no MMIO.
 */
uint32_t dwc3_events_count_bytes(uint32_t register_snapshot,
                                 uint32_t *uninterpreted_high_bits);

enum dwc3_events_status {
    DWC3_EVENTS_OK,
    DWC3_EVENTS_BUDGET,
    DWC3_EVENTS_PAUSED,
    DWC3_EVENTS_UNSUPPORTED_RECORD,
    DWC3_EVENTS_INVALID_RING,
    DWC3_EVENTS_INVALID_CURSOR,
    DWC3_EVENTS_INVALID_COUNT,
    DWC3_EVENTS_INVALID_CALLBACK
};

/* ACCEPT consumes this entry; PAUSE leaves this entry pending. The event
 * pointer is valid only during the callback; copy fields if retaining them.
 * A pausing callback must not commit side effects for the unaccepted event.
 * A callback must not mutate/free the ring or re-enter with the same
 * integration state.
 */
enum dwc3_events_action { DWC3_EVENTS_ACCEPT, DWC3_EVENTS_PAUSE };
typedef enum dwc3_events_action (*dwc3_events_callback)(
    void *context, const struct dwc3_event_decoded *event);

struct dwc3_events_result {
    enum dwc3_events_status status;
    size_t next_cursor;
    size_t consumed_bytes; /* Proposed acknowledgement BYTES, never events. */
    size_t delivered_events;
    size_t unknown_events;
    size_t overflow_events;
    uint32_t stop_raw;     /* Present only for UNSUPPORTED_RECORD. */
};

/* ring_size: nonzero multiple of 4 (not necessarily power of two).
 * cursor: aligned and strictly below ring_size, even for an empty snapshot.
 * pending_bytes: already extracted byte count, <= ring_size, <= 0xfffc and
 * divisible by 4; passing a raw register snapshot is a caller error.
 * event_budget: maximum accepted callbacks; zero means do no work; SIZE_MAX
 * means no extra budget beyond the snapshot. callback is always required.
 * All inputs are validated before any ring load or callback. Invalid inputs
 * return consumed_bytes=0 and next_cursor=cursor; nothing is acknowledged.
 * No ring or caller cursor mutation occurs, no allocation, MMIO, DMA, reset,
 * controller commands, or acknowledgement callback exists in this module.
 * The caller separately commits the returned cursor and acknowledges exactly
 * consumed_bytes, under its own synchronization/coherency/ownership policy.
 * Unknown fixed-size entries are delivered with UNKNOWN diagnostics and may
 * be accepted as 4 bytes. The known 12-byte test-LMP record stops consumption
 * BEFORE its header and callback; its payload must never be parsed as events.
 * Overflow events are diagnostic only: no recovery or continuity is claimed.
 */
struct dwc3_events_result dwc3_events_consume(
    const uint8_t *ring, size_t ring_size, size_t cursor,
    uint32_t pending_bytes, size_t event_budget,
    dwc3_events_callback callback, void *context);

#endif
