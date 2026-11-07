/* Original offline DMA32 TRB codec; no controller or publication adapter. */
#ifndef MI4_DWC3_TRB_H
#define MI4_DWC3_TRB_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define DWC3_TRB_BYTES 16u
#define DWC3_TRB_LENGTH_MAX UINT32_C(0x00ffffff)
#define DWC3_TRB_TYPE_NORMAL 1
#define DWC3_TRB_TYPE_SETUP 2
#define DWC3_TRB_TYPE_STATUS2 3
#define DWC3_TRB_TYPE_STATUS3 4
#define DWC3_TRB_TYPE_DATA 5
#define DWC3_TRB_FLAG_LAST UINT32_C(0x00000002)
#define DWC3_TRB_FLAG_IOC UINT32_C(0x00000800)
#define DWC3_TRB_STATUS_OK 0u
#define DWC3_TRB_STATUS_SETUP_PENDING 2u

/* A caller-declared DMA bus span, NOT proof of physical ownership. The caller
 * proves exclusive ownership, correct DMA translation, accessible CPU storage,
 * coherency, controller-address alignment and lifetime outside this module.
 * No allocation, CPU-pointer conversion or cache/barrier operation occurs here.
 * size must be positive; [base, base + size) must fit within the DMA32 space.
 */
struct dwc3_trb_span {
    uint64_t base;
    uint64_t size;
};

struct dwc3_trb_request {
    uint64_t address; /* DMA bus address, not a CPU pointer. Zero is legal. */
    int64_t length;  /* Validate before narrowing to the 24-bit length field. */
    int64_t type;    /* Exactly one of TYPE_NORMAL through TYPE_DATA. */
    int64_t flags;   /* Only FLAG_LAST and FLAG_IOC; all other bits rejected. */
};

/* Encode exactly 16 accessible bytes, unaligned output allowed, explicit LE.
 * SETUP length is 8; STATUS2/3 length is 0; NORMAL/DATA permit 0..LENGTH_MAX.
 * A zero-length address may equal the declared span end only if it remains
 * representable as uint32_t; nonzero transfers must lie wholly inside the span.
 * Output is unchanged on any rejection (including size != BYTES).
 * Successful output has bph=0, TRBSTS=0, HWO=0 and all unsupported fields clear.
 * This restricted profile does NOT support CHN/CSP/ISP_IMI/PCM1/streams/iso/link.
 * LAST and IOC are encoding intentions only, not endpoint or queue readiness.
 * The caller must separately prove TRB-storage alignment and perform any DMA
 * publication/handoff. This codec never sets HWO, starts or completes a transfer.
 */
bool dwc3_trb_encode(uint8_t *output, size_t output_size,
                     const struct dwc3_trb_span *span,
                     const struct dwc3_trb_request *request);

struct dwc3_trb_decoded {
    uint32_t address;
    uint32_t remaining; /* Raw 24-bit field, NOT independently actual bytes. */
    uint8_t type;
    uint8_t status;     /* All 16 TRBSTS values preserved, including unknown. */
    bool status_known; /* Only OK / SETUP_PENDING named in this profile. */
    bool hwo;
    bool last;
    bool ioc;
};

/* Decode a prepared OR hardware-updated image, not an event/completion API.
 * Exact 16 accessible bytes required; unaligned input allowed, explicit LE.
 * Rejects nonzero bph, unsupported control/size fields and unsupported types.
 * PCM1 bits 25:24 are meaningful to other profiles, not globally reserved.
 * SETUP remaining must be <= 8; STATUS remaining must be 0. Other types may
 * contain any 24-bit remaining value. Unknown TRBSTS values are valid reports.
 * Does not validate span ownership, original length, DMA visibility or events.
 * HWO clear, status_known, and even status==OK do NOT establish USB completion.
 * Output is unchanged on rejection; success replaces the entire decoded value.
 */
bool dwc3_trb_decode(const uint8_t *input, size_t input_size,
                     struct dwc3_trb_decoded *output);

#endif
