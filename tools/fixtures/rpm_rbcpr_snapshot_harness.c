/* Host-only original fixture: synthetic words, never hardware. */
#include "rpm_rbcpr_snapshot.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static unsigned assertions, cases;
#define CHECK(x) do { ++assertions; if (!(x)) { \
    fprintf(stderr, "CHECK line %u: %s\n", __LINE__, #x); exit(1); } } while (0)
static const uint32_t offsets[12] = {
    0, 0, 4, 8, 12, 0x14, 0x5c, 0xa4, 0xe8, 0xec, 4, 0
};
struct mock {
    uint32_t words[24];
    int fail;
    unsigned calls, rejected;
    struct mi4_rpm_rbcpr_snapshot *report;
};
static struct mock m;
static struct mi4_rpm_rbcpr_snapshot report;
static uint32_t stored(const struct mi4_rpm_rbcpr_sample *s, unsigned i)
{
    switch (i) {
    case 0: return s->pointer;
    case 1: return s->num_rails;
    case 2: return s->status_before;
    case 3: return s->num_corners;
    case 4: return s->num_recommends;
    case 5: case 6: case 7: return s->programmed_voltage_raw[i - 5];
    case 8: return s->current_corner;
    case 9: return s->railway_voltage_raw;
    case 10: return s->status_after;
    default: return s->pointer_after;
    }
}
static int reader(void *ctx, uint32_t address, uint32_t *out)
{
    struct mock *mock = ctx == NULL ? &m : ctx;
    unsigned n = mock->calls++, i = n % 12;
    uint32_t expected;
    CHECK(n < 24);
    if (n == 0) {
        struct mi4_rpm_rbcpr_snapshot cleared = {0};
        cleared.failed_slot = 24;
        cleared.attempted_reads = 1;
        cleared.last_address = MI4_RPM_RBCPR_POINTER_SLOT;
        CHECK(memcmp(mock->report, &cleared, sizeof(cleared)) == 0);
    }
    expected = i == 0 || i == 11 ? MI4_RPM_RBCPR_POINTER_SLOT :
        (uint32_t)(UINT64_C(0xfc000000) + mock->words[0]) + offsets[i];
    *out = UINT32_C(0xdeadbeef); /* failure poison must never be committed */
    if (address != expected) { ++mock->rejected; return -2; }
    if ((int)n == mock->fail) return 17;
    *out = mock->words[n];
    return 0;
}
static void setup(uint32_t p, uint32_t rails, uint32_t corner, uint32_t status)
{
    unsigned pass;
    memset(&m, 0, sizeof(m));
    memset(&report, 0xa5, sizeof(report));
    m.fail = -1; m.report = &report;
    for (pass = 0; pass < 2; ++pass) {
        uint32_t *w = &m.words[12 * pass];
        w[0] = w[11] = p; w[1] = rails; w[2] = w[10] = status;
        w[3] = w[4] = 3; w[5] = 11; w[6] = 22; w[7] = 33;
        w[8] = corner; w[9] = 44;
    }
}
static void run(enum mi4_rpm_rbcpr_result result, unsigned count, int failed,
                bool null_ctx)
{
    unsigned pass, i, successful = count - (result == MI4_RPM_RBCPR_READ_FAILED);
    ++cases;
    CHECK(mi4_rpm_rbcpr_snapshot(reader, null_ctx ? NULL : &m, &report) == result);
    CHECK(report.result == result);
    CHECK(m.calls == count && report.attempted_reads == count);
    CHECK(report.successful_reads == successful);
    CHECK(report.failed_slot == (failed < 0 ? 24u : (unsigned)failed));
    CHECK(!report.write_authorized && !report.live_freshness_proved &&
          !report.supply_floor_proved);
    CHECK(report.stable_sampled == (result == MI4_RPM_RBCPR_OK));
    CHECK(report.reported_nominal_or_higher ==
          (result == MI4_RPM_RBCPR_OK && m.words[8] >= 2));
    for (pass = 0; pass < 2; ++pass) {
        unsigned done = successful > pass * 12 ? successful - pass * 12 : 0;
        if (done > 12) done = 12;
        CHECK(report.samples[pass].valid_mask == ((1u << done) - 1));
        CHECK(report.samples[pass].valid == (count >= (pass + 1) * 12 &&
            (result == MI4_RPM_RBCPR_OK || failed > (int)(pass * 12 + 11) ||
             (count == 24 && result == MI4_RPM_RBCPR_CHANGED && failed == 23 &&
              m.words[23] == m.words[0] && m.words[22] == m.words[14]))));
        for (i = 0; i < 12; ++i)
            CHECK(stored(&report.samples[pass], i) == (i < done ? m.words[12 * pass + i] : 0));
        if (done == 0 || (pass == 0 && result == MI4_RPM_RBCPR_BAD_POINTER) ||
            (pass == 1 && done == 1 && result == MI4_RPM_RBCPR_CHANGED))
            CHECK(report.samples[pass].block_address == 0);
        else CHECK(report.samples[pass].block_address == UINT32_C(0xfc000000) + m.words[0]);
    }
}
int main(int argc, char **argv)
{
    unsigned i, j, k;
    const uint32_t statuses[] = {0, 1, 2, UINT32_MAX};
    const uint32_t pointers[] = {0x190014, 0x19f7fc};
    const uint32_t badp[] = {0, 0x190010, 0x19000c, 0x190015, 0x19f800,
        0x19f7ff, 0x1a0000, 0x100000, 0xfc190014, 0xffffffff, 0x4000000};
    const uint32_t badlayout[] = {0, 2, 4, UINT32_MAX};
    const unsigned changed[] = {1, 2, 5, 6, 7, 8, 9};
    if (argc == 2 && strcmp(argv[1], "injected-address") == 0) {
        setup(0x190014, 1, 2, 0);
        run(MI4_RPM_RBCPR_READ_FAILED, 6, 5, false);
        CHECK(m.rejected == 1);
        printf("address injection: stop at rejected callback, %u assertions\n", assertions);
        return 0;
    }
    CHECK(argc == 1);
    for (i = 0; i < 2; ++i) for (j = 0; j < 4; ++j) for (k = 0; k < 4; ++k) {
        setup(pointers[i], i + 1, j, statuses[k]);
        run(MI4_RPM_RBCPR_OK, 24, -1, i == 0);
    }
    for (i = 0; i < sizeof(badp) / sizeof(badp[0]); ++i) {
        setup(badp[i], 1, 2, 0); run(MI4_RPM_RBCPR_BAD_POINTER, 1, 0, false);
    }
    for (i = 0; i < 24; ++i) {
        setup(0x190014, 1, 2, 0); m.fail = (int)i;
        run(MI4_RPM_RBCPR_READ_FAILED, i + 1, (int)i, false);
    }
    for (i = 0; i < 2; ++i) {
        unsigned base = i * 12;
        setup(0x190014, 1, 2, 0); m.words[base + 11] += 4;
        run(MI4_RPM_RBCPR_CHANGED, base + 12, (int)base + 11, false);
        setup(0x190014, 1, 2, 0); m.words[base + 10] = 1;
        run(MI4_RPM_RBCPR_CHANGED, base + 11, (int)base + 10, false);
    }
    setup(0x190014, 1, 2, 0); m.words[12] += 4;
    run(MI4_RPM_RBCPR_CHANGED, 13, 12, false);
    for (i = 0; i < sizeof(changed) / sizeof(changed[0]); ++i) {
        setup(0x190014, 1, 2, 0); ++m.words[12 + changed[i]];
        if (changed[i] == 2) ++m.words[22];
        run(MI4_RPM_RBCPR_CHANGED, 24, 23, false);
    }
    for (j = 0; j < 2; ++j) for (i = 0; i < 3; ++i) {
        setup(0x190014, 1, 2, 0); m.words[j * 12 + 1] = i == 0 ? 0 : i + 2;
        run(MI4_RPM_RBCPR_BAD_LAYOUT, j * 12 + 2, (int)j * 12 + 1, false);
    }
    for (j = 0; j < 2; ++j) for (k = 3; k <= 4; ++k)
        for (i = 0; i < 4; ++i) {
            setup(0x190014, 1, 2, 0); m.words[j * 12 + k] = badlayout[i];
            run(MI4_RPM_RBCPR_BAD_LAYOUT, j * 12 + k + 1, (int)(j * 12 + k), false);
        }
    for (j = 0; j < 2; ++j) for (i = 4; i <= 0xffff; ++i) {
        setup(0x190014, 1, 2, 0); m.words[j * 12 + 8] = i;
        run(MI4_RPM_RBCPR_BAD_LAYOUT, j * 12 + 9, (int)j * 12 + 8, false);
    }
    for (j = 0; j < 2; ++j) {
        setup(0x190014, 2, 3, UINT32_MAX);
        for (i = 0; i < 24; ++i)
            if ((i % 12 >= 5 && i % 12 <= 7) || i % 12 == 9)
                m.words[i] = j ? UINT32_MAX : 0;
        run(MI4_RPM_RBCPR_OK, 24, -1, false);
    }
    setup(0x190014, 1, 2, 0);
    CHECK(mi4_rpm_rbcpr_snapshot(NULL, &m, &report) == MI4_RPM_RBCPR_INVALID);
    { struct mi4_rpm_rbcpr_snapshot cleared = {0}; cleared.failed_slot = 24;
      CHECK(memcmp(&report, &cleared, sizeof(report)) == 0); }
    CHECK(mi4_rpm_rbcpr_snapshot(reader, &m, NULL) == MI4_RPM_RBCPR_INVALID);
    CHECK(mi4_rpm_rbcpr_snapshot(NULL, NULL, NULL) == MI4_RPM_RBCPR_INVALID);
    CHECK(m.calls == 0);
    printf("host-only: %u cases, %u CHECK assertions; no hardware/freshness/power claim\n",
           cases, assertions);
    return 0;
}
