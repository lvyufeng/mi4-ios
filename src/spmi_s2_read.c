#include "spmi_s2_read.h"
/* Fixed EXT_READL arb op=1, SID=5, two bytes at 0x1740/0x1745. */
const uint32_t spmi_s2_read_commands[2] = {0x08517401u, 0x08517451u};
const uint32_t spmi_s2_read_registers[4] = {
    0xfc4cf000u, 0xfc4cf808u, 0xfc4caf20u, 0xfc4cf818u
};
struct run { const struct spmi_s2_callbacks *cb; void *ctx; struct spmi_s2_output *o; };
static void event(struct run *r, enum spmi_s2_event_kind k, uint32_t a, uint64_t v, int rc)
{
    struct spmi_s2_output *o = r->o;
    struct spmi_s2_event *e = &o->events[o->event_count++];
    e->kind = k; e->stage = o->stage; e->transaction = o->current_transaction;
    e->address = a; e->value = v; e->result = rc;
}
static enum spmi_s2_result fail(struct run *r, enum spmi_s2_result rc)
{
    r->o->result = rc;
    r->o->indeterminate = r->o->write_attempted != 0u;
    r->o->stage_status[r->o->current_transaction] = rc;
    return rc;
}
static bool clock_gate(struct run *r)
{
    struct spmi_s2_output *o = r->o;
    uint64_t now = 0;
    int rc;
    o->time_attempts++;
    rc = r->cb->time_us(r->ctx, &now);
    event(r, SPMI_S2_TIME, 0u, rc == 0 ? now : 0u, rc);
    if (rc != 0) { (void)fail(r, SPMI_S2_TIME_FAILED); return false; }
    o->time_completed++;
    if (!o->time_valid) {
        o->time_valid = true; o->start_us = now; o->last_us = now;
    } else {
        if (now < o->last_us) { (void)fail(r, SPMI_S2_TIME_LIMIT); return false; }
        o->last_us = now;
        if (now - o->start_us >= 10000u) {
            (void)fail(r, SPMI_S2_TIME_LIMIT); return false;
        }
    }
    return true;
}
static bool read_reg(struct run *r, unsigned slot, uint32_t *dst)
{
    uint32_t raw = 0, address = spmi_s2_read_registers[slot];
    int rc;
    r->o->failed_address = address;
    if (!clock_gate(r)) return false;
    r->o->read_attempts++;
    if (r->o->stage == SPMI_S2_POLL) r->o->polls[r->o->current_transaction]++;
    rc = r->cb->read32(r->ctx, address, &raw);
    event(r, SPMI_S2_READ, address, rc == 0 ? raw : 0u, rc);
    if (rc != 0) { (void)fail(r, SPMI_S2_READ_FAILED); return false; }
    r->o->read_completed++; *dst = raw;
    return true;
}
static bool command(struct run *r, unsigned t)
{
    const uint32_t address = 0xfc4cf800u;
    int rc;
    r->o->failed_address = address;
    if (!clock_gate(r)) return false;
    r->o->write_attempted++;
    rc = r->cb->write32(r->ctx, address, spmi_s2_read_commands[t]);
    event(r, SPMI_S2_WRITE, address, spmi_s2_read_commands[t], rc);
    if (rc != 0) { (void)fail(r, SPMI_S2_WRITE_FAILED); return false; }
    r->o->write_completed++;
    return true;
}
static bool delay(struct run *r)
{
    int rc;
    r->o->failed_address = 0u;
    if (!clock_gate(r)) return false;
    r->o->delay_attempts++;
    rc = r->cb->delay_us(r->ctx, 1u);
    event(r, SPMI_S2_DELAY, 0u, 1u, rc);
    if (rc != 0) { (void)fail(r, SPMI_S2_DELAY_FAILED); return false; }
    r->o->delay_completed++;
    return true;
}
static enum spmi_s2_result bad_status(uint32_t s)
{
    return (s & 4u) != 0u ? SPMI_S2_DENIED : SPMI_S2_BAD_STATUS;
}
enum spmi_s2_result spmi_s2_read(const struct spmi_s2_callbacks *cb, void *ctx,
                               struct spmi_s2_output *o)
{
    struct run r = {cb, ctx, o};
    unsigned t, p;
    if (o == 0) return SPMI_S2_INVALID;
    *o = (struct spmi_s2_output){0};
    o->result = SPMI_S2_INVALID; o->stage = SPMI_S2_VALIDATE;
    o->stage_status[0] = SPMI_S2_NOT_RUN; o->stage_status[1] = SPMI_S2_NOT_RUN;
    if (cb == 0 || cb->read32 == 0 || cb->write32 == 0 ||
        cb->time_us == 0 || cb->delay_us == 0) return SPMI_S2_INVALID;
    if (!clock_gate(&r)) return o->result;
    o->stage = SPMI_S2_VERSION;
    if (!read_reg(&r, 0u, &o->version)) return o->result;
    o->valid_mask = 1u;
    for (t = 0; t < 2u; t++) {
        o->current_transaction = t; o->stage = SPMI_S2_PRESTATUS;
        if (!read_reg(&r, 1u, &o->pre_status[t])) return o->result;
        o->pre_status_valid[t] = true;
        if (o->pre_status[t] > 1u) return fail(&r, bad_status(o->pre_status[t]));
        o->stage = SPMI_S2_DIAGNOSTIC;
        if (!read_reg(&r, 2u, &o->diagnostic_before[t])) return o->result;
        o->diagnostic_valid[t] = true;
        o->stage = SPMI_S2_COMMAND;
        if (!command(&r, t)) return o->result;
        o->stage = SPMI_S2_POLL;
        for (p = 0; p < 100u; p++) {
            if (!read_reg(&r, 1u, &o->completion_status[t])) return o->result;
            o->completion_valid[t] = true;
            if (o->completion_status[t] > 1u)
                return fail(&r, bad_status(o->completion_status[t]));
            if (o->completion_status[t] == 1u) break;
            if (p == 99u) return fail(&r, SPMI_S2_TIMEOUT);
            if (!delay(&r)) return o->result;
        }
        o->stage = SPMI_S2_DATA;
        if (!read_reg(&r, 3u, &o->data_raw[t])) return o->result;
        o->sample_valid[t] = true; o->valid_mask |= 2u << t;
        o->stage_status[t] = SPMI_S2_OK;
    }
    o->stage = SPMI_S2_DECODE; o->failed_address = 0u;
    o->range_raw = (uint8_t)o->data_raw[0];
    o->vset_raw = (uint8_t)(o->data_raw[0] >> 8);
    o->mode_raw = (uint8_t)o->data_raw[1];
    o->enable_raw = (uint8_t)(o->data_raw[1] >> 8);
    o->hpm_requested = (o->mode_raw & 0x80u) != 0u;
    o->auto_requested = (o->mode_raw & 0x40u) != 0u;
    o->enabled_request = (o->enable_raw & 0x80u) != 0u;
    if (o->range_raw > 1u) return fail(&r, SPMI_S2_BAD_RANGE);
    if ((o->range_raw == 0u && o->vset_raw < 70u) ||
        (o->range_raw == 1u && (o->vset_raw < 128u || o->vset_raw > 204u)))
        return fail(&r, SPMI_S2_BAD_ENCODING);
    o->setpoint_uv = (uint32_t)o->vset_raw * (o->range_raw == 0u ? 5000u : 10000u);
    o->decoded = true; o->setpoint_conversion = true;
    o->nominal_reference_met = o->setpoint_uv >= 900000u;
    if (!clock_gate(&r)) return o->result;
    o->stage = SPMI_S2_DONE; o->failed_address = 0u; o->result = SPMI_S2_OK;
    return SPMI_S2_OK;
}
