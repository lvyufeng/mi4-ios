/* Original bytewise codec from numerical TRB contracts, no vendor functions. */
#include "dwc3_trb.h"

static void store_le32(uint8_t *p, uint32_t value)
{
    p[0] = (uint8_t)value;
    p[1] = (uint8_t)(value >> 8);
    p[2] = (uint8_t)(value >> 16);
    p[3] = (uint8_t)(value >> 24);
}

static uint32_t load_le32(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
        ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static bool valid_type(int64_t type)
{
    return type >= DWC3_TRB_TYPE_NORMAL && type <= DWC3_TRB_TYPE_DATA;
}

static bool span_contains(const struct dwc3_trb_span *span,
                          uint64_t address, uint64_t length)
{
    const uint64_t limit = UINT64_C(0x100000000);
    uint64_t end;
    if (!span || span->size == 0 || span->base >= limit ||
        span->size > limit - span->base || address >= limit)
        return false;
    end = span->base + span->size;
    return address >= span->base && address <= end && length <= end - address;
}

bool dwc3_trb_encode(uint8_t *output, size_t output_size,
                     const struct dwc3_trb_span *span,
                     const struct dwc3_trb_request *request)
{
    struct dwc3_trb_request r;
    uint8_t prepared[DWC3_TRB_BYTES];
    size_t i;
    if (!output || output_size != DWC3_TRB_BYTES || !request)
        return false;
    r = *request;
    if (r.length < 0 || r.length > (int64_t)DWC3_TRB_LENGTH_MAX ||
        !valid_type(r.type) || r.flags < 0 ||
        ((uint64_t)r.flags & ~(uint64_t)(DWC3_TRB_FLAG_LAST |
                                        DWC3_TRB_FLAG_IOC)) != 0)
        return false;
    if ((r.type == DWC3_TRB_TYPE_SETUP && r.length != 8) ||
        ((r.type == DWC3_TRB_TYPE_STATUS2 ||
          r.type == DWC3_TRB_TYPE_STATUS3) && r.length != 0) ||
        !span_contains(span, r.address, (uint64_t)r.length))
        return false;
    store_le32(prepared, (uint32_t)r.address);
    store_le32(prepared + 4, 0);
    store_le32(prepared + 8, (uint32_t)r.length);
    store_le32(prepared + 12, ((uint32_t)r.type << 4) | (uint32_t)r.flags);
    for (i = 0; i < DWC3_TRB_BYTES; ++i)
        output[i] = prepared[i];
    return true;
}

bool dwc3_trb_decode(const uint8_t *input, size_t input_size,
                     struct dwc3_trb_decoded *output)
{
    struct dwc3_trb_decoded decoded = {0};
    uint32_t size, control;
    if (!input || input_size != DWC3_TRB_BYTES || !output)
        return false;
    decoded.address = load_le32(input);
    if (load_le32(input + 4) != 0)
        return false;
    size = load_le32(input + 8);
    control = load_le32(input + 12);
    if ((size & UINT32_C(0x0f000000)) != 0 ||
        (control & ~UINT32_C(0x00000bf3)) != 0)
        return false;
    decoded.type = (uint8_t)((control >> 4) & UINT32_C(0x3f));
    decoded.remaining = size & DWC3_TRB_LENGTH_MAX;
    if (!valid_type(decoded.type) ||
        (decoded.type == DWC3_TRB_TYPE_SETUP && decoded.remaining > 8) ||
        ((decoded.type == DWC3_TRB_TYPE_STATUS2 ||
          decoded.type == DWC3_TRB_TYPE_STATUS3) && decoded.remaining != 0))
        return false;
    decoded.status = (uint8_t)(size >> 28);
    decoded.status_known = decoded.status == DWC3_TRB_STATUS_OK ||
        decoded.status == DWC3_TRB_STATUS_SETUP_PENDING;
    decoded.hwo = (control & UINT32_C(1)) != 0;
    decoded.last = (control & DWC3_TRB_FLAG_LAST) != 0;
    decoded.ioc = (control & DWC3_TRB_FLAG_IOC) != 0;
    *output = decoded;
    return true;
}
