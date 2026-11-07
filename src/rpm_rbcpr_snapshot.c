/* Original read-only numeric decoder: no vendor structure overlays. */
#include "rpm_rbcpr_snapshot.h"
#include <stddef.h>

/* Kept as a 40-byte linked contract; indices are the ten block reads. */
static const uint32_t rpm_rbcpr_sample_offsets[10] = {
    0x0u, 0x4u, 0x8u, 0xcu, 0x14u, 0x5cu, 0xa4u, 0xe8u, 0xecu, 0x4u
};

static bool pointer_valid(uint32_t p)
{
    uint64_t a = UINT64_C(0xfc000000) + p;
    return (p & 3u) == 0u && p >= 0x190014u && p <= 0x19f7fcu &&
        a <= UINT32_MAX && a >= UINT64_C(0xfc100000) &&
        a + 0x800u <= UINT64_C(0xfc1a0000);
}

static uint32_t *field(struct mi4_rpm_rbcpr_sample *s, unsigned step)
{
    switch (step) {
    case 0: return &s->pointer;
    case 1: return &s->num_rails;
    case 2: return &s->status_before;
    case 3: return &s->num_corners;
    case 4: return &s->num_recommends;
    case 5: case 6: case 7: return &s->programmed_voltage_raw[step - 5];
    case 8: return &s->current_corner;
    case 9: return &s->railway_voltage_raw;
    case 10: return &s->status_after;
    default: return &s->pointer_after;
    }
}

static bool same_payload(const struct mi4_rpm_rbcpr_sample *a,
                         const struct mi4_rpm_rbcpr_sample *b)
{
    unsigned i;
    if (a->num_rails != b->num_rails || a->status_before != b->status_before ||
        a->num_corners != b->num_corners || a->num_recommends != b->num_recommends ||
        a->current_corner != b->current_corner ||
        a->railway_voltage_raw != b->railway_voltage_raw)
        return false;
    for (i = 0; i < 3; ++i)
        if (a->programmed_voltage_raw[i] != b->programmed_voltage_raw[i])
            return false;
    return true;
}

enum mi4_rpm_rbcpr_result mi4_rpm_rbcpr_snapshot(
    mi4_rpm_rbcpr_read_cb reader, void *ctx, struct mi4_rpm_rbcpr_snapshot *out)
{
    uint32_t block = 0, fixed_pointer = 0;
    unsigned pass, step;
    if (out == NULL)
        return MI4_RPM_RBCPR_INVALID;
    *out = (struct mi4_rpm_rbcpr_snapshot){0};
    out->failed_slot = MI4_RPM_RBCPR_NO_FAILED_SLOT;
    if (reader == NULL)
        return MI4_RPM_RBCPR_INVALID;
    for (pass = 0; pass < 2; ++pass) {
        struct mi4_rpm_rbcpr_sample *s = &out->samples[pass];
        for (step = 0; step < 12; ++step) {
            uint32_t value = 0;
            uint32_t address = (step == 0 || step == 11) ?
                MI4_RPM_RBCPR_POINTER_SLOT : block + rpm_rbcpr_sample_offsets[step - 1];
            out->last_address = address;
            ++out->attempted_reads;
            if (reader(ctx, address, &value) != 0) {
                out->result = MI4_RPM_RBCPR_READ_FAILED;
                goto failed;
            }
            ++out->successful_reads;
            *field(s, step) = value;
            s->valid_mask |= 1u << step;
            if (step == 0) {
                if (pass == 0) {
                    if (!pointer_valid(value)) {
                        out->result = MI4_RPM_RBCPR_BAD_POINTER;
                        goto failed;
                    }
                    fixed_pointer = value;
                    block = (uint32_t)(UINT64_C(0xfc000000) + value);
                } else if (value != fixed_pointer) {
                    out->result = MI4_RPM_RBCPR_CHANGED;
                    goto failed;
                }
                s->block_address = block;
            }
            if ((step == 1 && (value < 1u || value > 2u)) ||
                ((step == 3 || step == 4) && value != 3u) ||
                (step == 8 && value > 3u)) {
                out->result = MI4_RPM_RBCPR_BAD_LAYOUT;
                goto failed;
            }
            if ((step == 10 && value != s->status_before) ||
                (step == 11 && value != fixed_pointer)) {
                out->result = MI4_RPM_RBCPR_CHANGED;
                goto failed;
            }
        }
        s->valid = true;
    }
    if (!same_payload(&out->samples[0], &out->samples[1])) {
        out->result = MI4_RPM_RBCPR_CHANGED;
        out->failed_slot = 23u;
        return out->result;
    }
    out->stable_sampled = true;
    out->reported_nominal_or_higher = out->samples[1].current_corner >= 2u;
    out->result = MI4_RPM_RBCPR_OK;
    return out->result;
failed:
    out->failed_slot = pass * 12u + step;
    return out->result;
}
