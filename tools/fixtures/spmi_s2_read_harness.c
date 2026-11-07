#include "spmi_s2_read.h"
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static unsigned checks, cases;
#define CHECK(x) do { checks++; if (!(x)) { fprintf(stderr, "CHECK:%d:%s\n", __LINE__, #x); exit(1); } } while (0)
struct fake {
    unsigned reads, writes, delays, times, txn, poll[2], wait[2];
    unsigned fail_read, fail_write, fail_delay, fail_time, bad_time, time_mode;
    uint32_t version, pre[2], status[2], data[2], delivered;
    bool active;
};
static struct fake f;
static struct spmi_s2_output out, gold;
static uint32_t io_addr[420], io_value[420];
static unsigned io_kind[420], io_count;
static void io(unsigned kind, uint32_t addr, uint32_t value)
{
    CHECK(io_count < 420u); io_kind[io_count] = kind;
    io_addr[io_count] = addr; io_value[io_count++] = value;
}
static int rd(void *ctx, uint32_t a, uint32_t *v)
{
    unsigned t = f.txn;
    CHECK(ctx == NULL); CHECK(t < 2u); f.reads++; io(0u, a, 0u);
    *v = 0xdeadbeefu;
    if (f.fail_read == f.reads) return -7;
    if (a == 0xfc4cf000u) { CHECK(f.reads == 1u); *v = f.version; }
    else if (a == 0xfc4caf20u) { CHECK(!f.active); *v = 0x12340000u + t; }
    else if (a == 0xfc4cf808u) {
        if (!f.active) *v = f.pre[t];
        else { f.poll[t]++; *v = f.poll[t] <= f.wait[t] ? 0u : f.status[t]; }
    } else {
        CHECK(a == 0xfc4cf818u); CHECK(f.active);
        CHECK(f.poll[t] > f.wait[t]); CHECK(f.status[t] == 1u);
        *v = f.data[t]; f.active = false; f.txn++;
    }
    return 0;
}
static int wr(void *ctx, uint32_t a, uint32_t v)
{
    CHECK(ctx == NULL); f.writes++; io(1u, a, v);
    CHECK(a == 0xfc4cf800u); CHECK(f.writes <= 2u);
    CHECK(v == (f.writes == 1u ? 0x08517401u : 0x08517451u));
    /* A failed store may already have reached hardware. */
    f.delivered = v; f.active = true;
    if (f.fail_write == f.writes) { f.data[f.txn] ^= 0xffffffffu; return 8; }
    return 0;
}
static int tm(void *ctx, uint64_t *v)
{
    CHECK(ctx == NULL); f.times++; *v = UINT64_MAX;
    if (f.fail_time == f.times) return 3;
    *v = f.time_mode == 3u ? UINT64_MAX - 10000u + f.times : 1000u + f.times;
    if (f.bad_time == f.times) {
        if (f.time_mode == 1u) *v = 11001u;
        else if (f.time_mode == 2u) *v = 1000u;
        else *v = 0u;
    }
    return 0;
}
static int dl(void *ctx, uint32_t us)
{
    CHECK(ctx == NULL); CHECK(us == 1u); f.delays++; io(2u, 0u, us);
    return f.fail_delay == f.delays ? -9 : 0;
}
static const struct spmi_s2_callbacks cb = {rd, wr, tm, dl};
static void reset(void)
{
    memset(&f, 0, sizeof(f)); io_count = 0;
    f.version = 0x10010000u; f.pre[0] = f.pre[1] = 1u;
    f.status[0] = f.status[1] = 1u;
    f.data[0] = 0xaabbB400u; f.data[1] = 0xccdd80c0u;
    memset(&out, 0x5a, sizeof(out)); cases++;
}
static enum spmi_s2_result run(void)
{
    enum spmi_s2_result rc = spmi_s2_read(&cb, NULL, &out);
    CHECK(out.result == rc); CHECK(!out.clock_write_authorized);
    CHECK(!out.supply_floor_proven && !out.adc_measurement);
    CHECK(out.read_attempts == f.reads && out.write_attempted == f.writes);
    CHECK(out.delay_attempts == f.delays && out.time_attempts == f.times);
    CHECK(out.event_count <= SPMI_S2_MAX_EVENTS);
    CHECK(out.event_count == f.reads + f.writes + f.delays + f.times);
    CHECK(out.indeterminate == (rc != SPMI_S2_OK && f.writes != 0u));
    CHECK(out.sample_valid[0] == ((out.valid_mask & 2u) != 0u));
    CHECK(out.sample_valid[1] == ((out.valid_mask & 4u) != 0u));
    CHECK(out.sample_valid[0] || out.data_raw[0] == 0u);
    CHECK(out.sample_valid[1] || out.data_raw[1] == 0u);
    for (unsigned i = 0; i < out.event_count; i++) {
        const struct spmi_s2_event *e = &out.events[i];
        if ((e->kind == SPMI_S2_READ || e->kind == SPMI_S2_TIME) && e->result != 0)
            CHECK(e->value == 0u);
    }
    return rc;
}
static void success(void)
{
    reset(); CHECK(run() == SPMI_S2_OK); gold = out;
    CHECK(f.reads == 9u && f.writes == 2u && f.delays == 0u);
    CHECK(out.valid_mask == 7u && out.decoded && out.setpoint_conversion);
    CHECK(out.setpoint_uv == 900000u && out.nominal_reference_met);
    CHECK(out.hpm_requested && out.auto_requested && out.enabled_request);
    CHECK(out.mode_raw == 0xc0u && out.enable_raw == 0x80u);
    CHECK(out.stage == SPMI_S2_DONE && out.failed_address == 0u);
    CHECK(out.start_us == 1001u && out.last_us == 1013u);
    const uint32_t addresses[] = {0xfc4cf000u,0xfc4cf808u,0xfc4caf20u,0xfc4cf800u,
        0xfc4cf808u,0xfc4cf818u,0xfc4cf808u,0xfc4caf20u,0xfc4cf800u,0xfc4cf808u,0xfc4cf818u};
    CHECK(io_count == 11u);
    for (unsigned i = 0; i < 11u; i++) CHECK(io_addr[i] == addresses[i]);
    CHECK(sizeof(spmi_s2_read_commands) == 8u && sizeof(spmi_s2_read_registers) == 16u);
    for (unsigned i = 0; i < 4u; i++) CHECK(spmi_s2_read_registers[i] == addresses[i == 3u ? 5u : i]);
}
static void faults(void)
{
    const unsigned writes_before[] = {0,0,0,1,1,1,1,2,2};
    const unsigned masks[] = {0,1,1,1,1,3,3,3,3};
    for (unsigned n = 1; n <= 9u; n++) {
        reset(); f.fail_read = n; CHECK(run() == SPMI_S2_READ_FAILED);
        CHECK(f.reads == n && f.writes == writes_before[n-1]);
        CHECK(out.read_completed == n-1u && out.valid_mask == masks[n-1]);
        CHECK(io_count == n + f.writes); CHECK(out.events[out.event_count-1u].result == -7);
    }
    for (unsigned n = 1; n <= 2u; n++) {
        reset(); f.fail_write = n; CHECK(run() == SPMI_S2_WRITE_FAILED);
        CHECK(f.writes == n && f.reads == (n == 1u ? 3u : 7u));
        CHECK(out.write_completed == n-1u && f.delivered != 0u);
        CHECK(out.events[out.event_count-1u].result == 8);
        CHECK(!out.sample_valid[n-1u]);
    }
    for (unsigned n = 1; n <= gold.time_attempts; n++) {
        for (unsigned mode = 0; mode < 4u; mode++) {
            if (n == 1u && mode != 0u) continue;
            reset();
            if (mode == 0u) f.fail_time = n;
            else { f.bad_time = n; f.time_mode = mode; }
            CHECK(run() == (mode == 0u ? SPMI_S2_TIME_FAILED : SPMI_S2_TIME_LIMIT));
            CHECK(f.times == n); CHECK(out.events[out.event_count-1u].kind == SPMI_S2_TIME);
            unsigned expected = 0;
            for (unsigned i = 0, clocks = 0; i < gold.event_count; i++) {
                if (gold.events[i].kind == SPMI_S2_TIME && ++clocks == n) break;
                if (gold.events[i].kind != SPMI_S2_TIME) expected++;
            }
            CHECK(io_count == expected);
        }
    }
}
static void polling(void)
{
    const uint32_t bad[] = {2u,4u,8u,5u,3u,9u,16u,0xffffffffu};
    for (unsigned t = 0; t < 2u; t++) for (unsigned j = 0; j < 8u; j++) {
        for (unsigned pre = 0; pre < 2u; pre++) {
            reset(); if (pre) f.pre[t] = bad[j]; else f.status[t] = bad[j];
            CHECK(run() == ((bad[j] & 4u) ? SPMI_S2_DENIED : SPMI_S2_BAD_STATUS));
            CHECK(f.writes == t + (pre ? 0u : 1u));
            CHECK(f.poll[t] == (pre ? 0u : 1u)); CHECK(!out.sample_valid[t]);
            CHECK(f.reads == 1u + 4u*t + (pre ? 1u : 3u));
        }
    }
    for (unsigned a = 0; a < 2u; a++) for (unsigned b = 0; b < 2u; b++) {
        reset(); f.pre[0] = a; f.pre[1] = b; CHECK(run() == SPMI_S2_OK);
        CHECK(f.writes == 2u && f.poll[0] == 1u && f.poll[1] == 1u);
    }
    for (unsigned t = 0; t < 2u; t++) {
        reset(); f.wait[t] = 100u; CHECK(run() == SPMI_S2_TIMEOUT);
        CHECK(f.poll[t] == 100u && f.delays == 99u && f.writes == t+1u);
        CHECK(!out.sample_valid[t]); CHECK(f.reads == 103u + 4u*t);
        reset(); f.wait[t] = 99u; CHECK(run() == SPMI_S2_OK);
        CHECK(f.poll[t] == 100u && f.delays == 99u);
    }
    for (unsigned t = 0; t < 2u; t++) for (unsigned n = 0; n < 100u; n++) {
        reset(); f.wait[t] = n; CHECK(run() == SPMI_S2_OK);
        CHECK(f.poll[t] == n+1u && out.polls[t] == n+1u);
        CHECK(f.delays == n && f.reads == 9u+n && f.writes == 2u);
    }
    reset(); f.wait[0] = f.wait[1] = 99u; CHECK(run() == SPMI_S2_OK);
    CHECK(f.reads == 207u && f.delays == 198u && out.event_count == 816u);
    gold = out;
    for (unsigned n = 1; n <= gold.time_attempts; n++) {
        for (unsigned mode = 0; mode < 4u; mode++) {
            if (n == 1u && mode != 0u) continue;
            reset(); f.wait[0] = f.wait[1] = 99u;
            if (mode == 0u) f.fail_time = n;
            else { f.bad_time = n; f.time_mode = mode; }
            CHECK(run() == (mode == 0u ? SPMI_S2_TIME_FAILED : SPMI_S2_TIME_LIMIT));
            CHECK(f.times == n);
            unsigned expected = 0;
            for (unsigned i = 0, clocks = 0; i < gold.event_count; i++) {
                if (gold.events[i].kind == SPMI_S2_TIME && ++clocks == n) break;
                if (gold.events[i].kind != SPMI_S2_TIME) expected++;
            }
            CHECK(io_count == expected);
        }
    }
    for (unsigned n = 1; n <= 198u; n++) {
        reset(); f.wait[0] = f.wait[1] = 99u; f.fail_delay = n;
        CHECK(run() == SPMI_S2_DELAY_FAILED); CHECK(f.delays == n);
        CHECK(out.delay_completed == n-1u); CHECK(out.events[out.event_count-1u].result == -9);
    }
}
static void decoding(void)
{
    unsigned valid = 0;
    for (unsigned range = 0; range < 256u; range++) for (unsigned v = 0; v < 256u; v++) {
        reset(); f.data[0] = 0xfedc0000u | (v << 8) | range;
        bool good = (range == 0u && v >= 70u) || (range == 1u && v >= 128u && v <= 204u);
        enum spmi_s2_result rc = run();
        CHECK(rc == (good ? SPMI_S2_OK : range > 1u ? SPMI_S2_BAD_RANGE : SPMI_S2_BAD_ENCODING));
        CHECK(out.valid_mask == 7u && out.range_raw == range && out.vset_raw == v);
        CHECK(f.reads == 9u && f.writes == 2u && out.data_raw[0] == f.data[0]);
        CHECK(out.decoded == good);
        if (good) { valid++; CHECK(out.setpoint_uv == v * (range == 0u ? 5000u : 10000u));
            CHECK(out.nominal_reference_met == (out.setpoint_uv >= 900000u)); }
    }
    CHECK(valid == 263u);
    for (unsigned v = 0; v < 256u; v++) {
        reset(); f.data[1] = 0xffff0000u | (v << 8) | (255u-v); CHECK(run() == SPMI_S2_OK);
        CHECK(out.mode_raw == 255u-v && out.enable_raw == v);
        CHECK(out.enabled_request == ((v & 128u) != 0u));
        CHECK(out.hpm_requested == (((255u-v) & 128u) != 0u));
        CHECK(out.auto_requested == (((255u-v) & 64u) != 0u));
    }
    reset(); f.version = 0u; CHECK(run() == SPMI_S2_OK && out.version == 0u);
    reset(); f.version = 0xffffffffu; CHECK(run() == SPMI_S2_OK && out.version == 0xffffffffu);
}
int main(void)
{
    success(); faults(); polling(); decoding();
    for (unsigned n = 0; n < 5u; n++) {
        struct spmi_s2_callbacks bad = cb; reset();
        if (n == 0u) bad.read32 = NULL;
        if (n == 1u) bad.write32 = NULL;
        if (n == 2u) bad.time_us = NULL;
        if (n == 3u) bad.delay_us = NULL;
        CHECK(spmi_s2_read(n == 4u ? NULL : &bad, NULL, &out) == SPMI_S2_INVALID);
        CHECK(out.event_count == 0u && out.valid_mask == 0u && !out.indeterminate);
        CHECK(!out.clock_write_authorized && f.times == 0u);
    }
    CHECK(spmi_s2_read(&cb, NULL, NULL) == SPMI_S2_INVALID);
    printf("PASS cases=%u checks=%u\n", cases, checks); return 0;
}
