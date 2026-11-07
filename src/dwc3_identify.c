/* Original numerical register contract; no vendor function bodies copied. */
#include "dwc3_identify.h"

static enum mi4_dwc3_identify_status finish(
    struct mi4_dwc3_identity *out, enum mi4_dwc3_identify_status status)
{
    out->status = status;
    return status;
}

enum mi4_dwc3_identify_status mi4_dwc3_identify(
    mi4_dwc3_read32 reader, void *context, struct mi4_dwc3_identity *out)
{
    static const uint32_t clocks[MI4_DWC3_CLOCK_COUNT] = {
        UINT32_C(0x0108), UINT32_C(0x03c8), UINT32_C(0x03d0),
        UINT32_C(0x03cc), UINT32_C(0x04ac)
    };
    static const uint32_t regs[MI4_DWC3_REGISTER_COUNT] = {
        MI4_DWC3_GSNPSID, MI4_DWC3_GCTL,
        MI4_DWC3_GHWPARAMS0, MI4_DWC3_GHWPARAMS1,
        MI4_DWC3_GUSB2PHYCFG0, MI4_DWC3_DCFG,
        MI4_DWC3_DCTL, MI4_DWC3_DSTS
    };
    unsigned i;
    uint32_t value;

    if (out == NULL) return MI4_DWC3_IDENTIFY_INVALID;
    *out = (struct mi4_dwc3_identity){0};
    out->failed_slot = UINT32_MAX;
    if (reader == NULL) return finish(out, MI4_DWC3_IDENTIFY_INVALID);
    for (i = 0; i < MI4_DWC3_CLOCK_COUNT; ++i) {
        value = 0;
        if (reader(context, MI4_GCC_BASE + clocks[i], &value) != 0) {
            out->failed_slot = i;
            return finish(out, MI4_DWC3_IDENTIFY_READ_FAILED);
        }
        ++out->completed_reads;
        out->clock_values[i] = value;
        out->valid_clocks |= UINT32_C(1) << i;
        if ((value & UINT32_C(1)) == 0 ||
            ((value & UINT32_C(0xf0000000)) != 0 &&
             (value & UINT32_C(0xf0000000)) != UINT32_C(0x20000000)))
            return finish(out, MI4_DWC3_IDENTIFY_CLOCK_BLOCKED);
    }
    value = 0;
    if (reader(context, MI4_GCC_BASE + UINT32_C(0x03c0), &value) != 0) {
        out->failed_slot = 5;
        return finish(out, MI4_DWC3_IDENTIFY_READ_FAILED);
    }
    ++out->completed_reads;
    out->bcr = value;
    out->bcr_valid = 1;
    if ((value & UINT32_C(1)) != 0)
        return finish(out, MI4_DWC3_IDENTIFY_RESET_ASSERTED);
    value = 0;
    if (reader(context, MI4_GCC_BASE + UINT32_C(0x03d4), &value) != 0) {
        out->failed_slot = 6;
        return finish(out, MI4_DWC3_IDENTIFY_READ_FAILED);
    }
    ++out->completed_reads;
    out->root_command = value;
    out->root_valid = 1;
    if ((value & UINT32_C(0x800000f3)) != UINT32_C(2))
        return finish(out, MI4_DWC3_IDENTIFY_ROOT_BLOCKED);
    for (i = 0; i < MI4_DWC3_REGISTER_COUNT; ++i) {
        value = 0;
        if (reader(context, MI4_DWC3_BASE + regs[i], &value) != 0) {
            out->failed_slot = 7u + i;
            return finish(out, MI4_DWC3_IDENTIFY_READ_FAILED);
        }
        ++out->completed_reads;
        out->registers[i] = value;
        out->valid_registers |= UINT32_C(1) << i;
        if (i == 0 && (value & MI4_DWC3_ID_MASK) != MI4_DWC3_ID_MAGIC)
            return finish(out, MI4_DWC3_IDENTIFY_WRONG_ID);
    }
    return finish(out, MI4_DWC3_IDENTIFY_OK);
}
