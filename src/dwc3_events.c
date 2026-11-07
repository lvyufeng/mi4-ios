/* Original offline implementation; no vendor function bodies or bitfields. */
#include "dwc3_events.h"

static bool endpoint_type_known(uint8_t type)
{
    switch (type) {
    case DWC3_EVENTS_EP_XFER_COMPLETE:
    case DWC3_EVENTS_EP_XFER_IN_PROGRESS:
    case DWC3_EVENTS_EP_XFER_NOT_READY:
    case DWC3_EVENTS_EP_FIFO:
    case DWC3_EVENTS_EP_STREAM:
    case DWC3_EVENTS_EP_CMD_COMPLETE:
        return true;
    default:
        return false;
    }
}

static bool device_type_known(uint8_t type)
{
    switch (type) {
    case DWC3_EVENTS_DEV_DISCONNECT:
    case DWC3_EVENTS_DEV_RESET:
    case DWC3_EVENTS_DEV_CONNECT_DONE:
    case DWC3_EVENTS_DEV_LINK_CHANGE:
    case DWC3_EVENTS_DEV_WAKEUP:
    case DWC3_EVENTS_DEV_HIBER_REQ:
    case DWC3_EVENTS_DEV_EOPF:
    case DWC3_EVENTS_DEV_SOF:
    case DWC3_EVENTS_DEV_ERRATIC_ERROR:
    case DWC3_EVENTS_DEV_CMD_COMPLETE:
    case DWC3_EVENTS_DEV_OVERFLOW:
    case DWC3_EVENTS_DEV_TEST_LMP:
        return true;
    default:
        return false;
    }
}

struct dwc3_event_decoded dwc3_events_decode(uint32_t raw)
{
    struct dwc3_event_decoded event = {0};

    event.raw = raw;
    if ((raw & UINT32_C(1)) == 0u) {
        event.family = DWC3_EVENTS_ENDPOINT;
        event.endpoint_physical = (uint8_t)((raw >> 1) & UINT32_C(0x1f));
        event.type = (uint8_t)((raw >> 6) & UINT32_C(0xf));
        event.status = (uint8_t)((raw >> 12) & UINT32_C(0xf));
        event.parameters = (uint16_t)(raw >> 16);
        event.known = endpoint_type_known(event.type);
        if ((raw & UINT32_C(0xc00)) != 0u) {
            event.diagnostics |= DWC3_EVENTS_DIAG_RESERVED;
        }
    } else {
        event.category = (uint8_t)((raw >> 1) & UINT32_C(0x7f));
        if (event.category != DWC3_EVENTS_DEV_CATEGORY) {
            event.family = DWC3_EVENTS_OTHER;
        } else {
            event.family = DWC3_EVENTS_DEVICE;
            event.type = (uint8_t)((raw >> 8) & UINT32_C(0xf));
            event.info = (uint8_t)((raw >> 16) & UINT32_C(0xff));
            event.known = device_type_known(event.type);
            if ((raw & UINT32_C(0xff00f000)) != 0u) {
                event.diagnostics |= DWC3_EVENTS_DIAG_RESERVED;
            }
            if (event.type == DWC3_EVENTS_DEV_OVERFLOW) {
                event.diagnostics |= DWC3_EVENTS_DIAG_OVERFLOW;
            }
            if (event.type == DWC3_EVENTS_DEV_TEST_LMP) {
                event.diagnostics |= DWC3_EVENTS_DIAG_UNSUPPORTED_LENGTH;
            }
        }
    }
    if (!event.known) {
        event.diagnostics |= DWC3_EVENTS_DIAG_UNKNOWN;
    }
    return event;
}

uint32_t dwc3_events_count_bytes(uint32_t register_snapshot,
                                 uint32_t *uninterpreted_high_bits)
{
    if (uninterpreted_high_bits != NULL) {
        *uninterpreted_high_bits = register_snapshot & UINT32_C(0xffff0000);
    }
    return register_snapshot & UINT32_C(0xffff);
}

static uint32_t load_le32(const uint8_t *bytes)
{
    return (uint32_t)bytes[0] | ((uint32_t)bytes[1] << 8) |
           ((uint32_t)bytes[2] << 16) | ((uint32_t)bytes[3] << 24);
}

struct dwc3_events_result dwc3_events_consume(
    const uint8_t *ring, size_t ring_size, size_t cursor,
    uint32_t pending_bytes, size_t event_budget,
    dwc3_events_callback callback, void *context)
{
    struct dwc3_events_result result = {0};

    result.next_cursor = cursor;
    if (ring == NULL || ring_size == 0u || ring_size % 4u != 0u) {
        result.status = DWC3_EVENTS_INVALID_RING;
        return result;
    }
    if (cursor >= ring_size || cursor % 4u != 0u) {
        result.status = DWC3_EVENTS_INVALID_CURSOR;
        return result;
    }
    if (pending_bytes > DWC3_EVENTS_COUNT_MASK ||
        pending_bytes > ring_size || pending_bytes % 4u != 0u) {
        result.status = DWC3_EVENTS_INVALID_COUNT;
        return result;
    }
    if (callback == NULL) {
        result.status = DWC3_EVENTS_INVALID_CALLBACK;
        return result;
    }
    while (result.consumed_bytes < pending_bytes) {
        struct dwc3_event_decoded event;

        if (result.delivered_events == event_budget) {
            result.status = DWC3_EVENTS_BUDGET;
            return result;
        }
        event = dwc3_events_decode(load_le32(ring + result.next_cursor));
        if ((event.diagnostics & DWC3_EVENTS_DIAG_UNSUPPORTED_LENGTH) != 0u) {
            result.status = DWC3_EVENTS_UNSUPPORTED_RECORD;
            result.stop_raw = event.raw;
            return result;
        }
        if (callback(context, &event) != DWC3_EVENTS_ACCEPT) {
            result.status = DWC3_EVENTS_PAUSED;
            return result;
        }
        result.consumed_bytes += 4u;
        result.delivered_events += 1u;
        if (!event.known) {
            result.unknown_events += 1u;
        }
        if ((event.diagnostics & DWC3_EVENTS_DIAG_OVERFLOW) != 0u) {
            result.overflow_events += 1u;
        }
        /* ring_size and cursor are aligned, so this cannot overflow size_t. */
        if (result.next_cursor == ring_size - 4u) {
            result.next_cursor = 0u;
        } else {
            result.next_cursor += 4u;
        }
    }
    result.status = DWC3_EVENTS_OK;
    return result;
}
