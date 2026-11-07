/* Original host acceptance tests; synthetic bytes only, no controller access. */
#include "dwc3_trb.h"
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static uint64_t checks;
#define CHECK(x) do { ++checks; if (!(x)) { \
    fprintf(stderr, "FAIL line %d: %s\n", __LINE__, #x); exit(1); \
} } while (0)

static void put_word(uint8_t *p, uint32_t value)
{
    unsigned i;
    for (i = 0; i < 4; ++i) {
        p[i] = (uint8_t)(value % UINT32_C(256));
        value /= UINT32_C(256);
    }
}

static void image(uint8_t *p, uint32_t address, uint32_t size, uint32_t control)
{
    put_word(p, address);
    put_word(p + 4, 0);
    put_word(p + 8, size);
    put_word(p + 12, control);
}

static void rejected_encode(const struct dwc3_trb_span *span,
                            const struct dwc3_trb_request *r, size_t size)
{
    uint8_t bytes[18], before[18];
    memset(bytes, 0xa7, sizeof bytes);
    memcpy(before, bytes, sizeof before);
    CHECK(!dwc3_trb_encode(bytes + 1, size, span, r));
    CHECK(memcmp(bytes, before, sizeof bytes) == 0);
}

static void rejected_decode(const uint8_t *p, size_t size)
{
    struct dwc3_trb_decoded out;
    unsigned char before[sizeof out];
    memset(&out, 0xa7, sizeof out);
    memcpy(before, &out, sizeof before);
    CHECK(!dwc3_trb_decode(p, size, &out));
    CHECK(memcmp(&out, before, sizeof out) == 0);
}

static void accepted(const struct dwc3_trb_span *span,
                     const struct dwc3_trb_request *r)
{
    uint8_t bytes[18], before[sizeof *r], expected[16];
    struct dwc3_trb_decoded out;
    struct dwc3_trb_span span_before = *span;
    memcpy(before, r, sizeof before);
    memset(bytes, 0xc5, sizeof bytes);
    image(expected, (uint32_t)r->address, (uint32_t)r->length,
          (uint32_t)r->type * UINT32_C(16) + (uint32_t)r->flags);
    CHECK(dwc3_trb_encode(bytes + 1, 16, span, r));
    CHECK(memcmp(bytes + 1, expected, 16) == 0);
    CHECK(bytes[0] == 0xc5 && bytes[17] == 0xc5);
    CHECK(memcmp(before, r, sizeof before) == 0);
    CHECK(span_before.base == span->base && span_before.size == span->size);
    CHECK(dwc3_trb_decode(bytes + 1, 16, &out));
    CHECK(out.address == r->address && out.remaining == (uint32_t)r->length);
    CHECK(out.type == r->type && out.status == 0 && out.status_known);
    CHECK(!out.hwo && out.last == ((r->flags & 2) != 0));
    CHECK(out.ioc == ((r->flags & 2048) != 0));
}

static void test_constants(void)
{
    CHECK(DWC3_TRB_BYTES == 16);
    CHECK(DWC3_TRB_LENGTH_MAX == UINT32_C(0xffffff));
    CHECK(DWC3_TRB_TYPE_NORMAL == 1 && DWC3_TRB_TYPE_SETUP == 2);
    CHECK(DWC3_TRB_TYPE_STATUS2 == 3 && DWC3_TRB_TYPE_STATUS3 == 4);
    CHECK(DWC3_TRB_TYPE_DATA == 5);
    CHECK(DWC3_TRB_FLAG_LAST == 2 && DWC3_TRB_FLAG_IOC == 2048);
    CHECK(DWC3_TRB_STATUS_OK == 0 && DWC3_TRB_STATUS_SETUP_PENDING == 2);
}

static void test_encode(void)
{
    struct dwc3_trb_span full = {0, UINT64_C(0x100000000)};
    struct dwc3_trb_span small = {16, 16};
    struct dwc3_trb_request r = {UINT64_C(0x12345678), 8, 2, 2050};
    struct dwc3_trb_span invalid_spans[] = {
        {0, 0}, {16, 0}, {UINT64_C(0x100000000), 1},
        {UINT64_MAX, 1}, {0, UINT64_C(0x100000001)},
        {UINT64_C(0xffffffff), 2}, {1, UINT64_MAX}, {UINT64_MAX, UINT64_MAX}
    };
    const int64_t invalid_lengths[] = {
        -1, INT64_MIN, -INT64_C(0x100000000), INT64_C(0x1000000),
        INT64_C(0x100000000), INT64_MAX
    };
    const int64_t invalid_types[] = {
        INT64_MIN, -1, 0, 6, 7, 8, 63, 64, 65, 256, INT64_MAX
    };
    const size_t invalid_sizes[] = {0, 1, 15, 17, SIZE_MAX};
    const uint8_t exact_setup[16] = {
        0x78, 0x56, 0x34, 0x12, 0, 0, 0, 0,
        8, 0, 0, 0, 0x22, 8, 0, 0
    };
    uint8_t bytes[16];
    size_t i;
    int64_t type, flags;
    accepted(&full, &r);
    CHECK(dwc3_trb_encode(bytes, sizeof bytes, &full, &r));
    CHECK(memcmp(bytes, exact_setup, sizeof bytes) == 0);
    CHECK(!dwc3_trb_encode(NULL, 16, &full, &r));
    rejected_encode(NULL, &r, 16);
    rejected_encode(&full, NULL, 16);
    for (i = 0; i < sizeof invalid_sizes / sizeof invalid_sizes[0]; ++i)
        rejected_encode(&full, &r, invalid_sizes[i]);
    for (i = 0; i < sizeof invalid_spans / sizeof invalid_spans[0]; ++i)
        rejected_encode(&invalid_spans[i], &r, 16);
    for (type = 1; type <= 5; ++type) {
        for (flags = 0; flags < 4; ++flags) {
            r = (struct dwc3_trb_request){0, type == 2 ? 8 : 0, type,
                                         (flags % 2) * 2 + (flags / 2) * 2048};
            accepted(&full, &r); /* Includes DMA address 0 and zero packets. */
        }
    }
    r = (struct dwc3_trb_request){0, 0, 1, 0};
    for (i = 0; i < sizeof invalid_lengths / sizeof invalid_lengths[0]; ++i) {
        r.length = invalid_lengths[i];
        rejected_encode(&full, &r, 16);
    }
    r.length = 0;
    for (i = 0; i < sizeof invalid_types / sizeof invalid_types[0]; ++i) {
        r.type = invalid_types[i];
        rejected_encode(&full, &r, 16);
    }
    r.type = 1;
    for (i = 0; i < 63; ++i) {
        if (i == 1 || i == 11)
            continue;
        r.flags = (int64_t)(UINT64_C(1) << i);
        rejected_encode(&full, &r, 16);
    }
    r.flags = -1;
    rejected_encode(&full, &r, 16);
    r.flags = INT64_MIN;
    rejected_encode(&full, &r, 16);
    r.flags = 2054; /* LAST + IOC cannot hide an unsupported CHN bit. */
    rejected_encode(&full, &r, 16);
    r.flags = 0;
    r.type = 2;
    for (i = 0; i <= 16; ++i) {
        r.length = (int64_t)i;
        if (i == 8)
            accepted(&full, &r);
        else
            rejected_encode(&full, &r, 16);
    }
    for (type = 3; type <= 4; ++type) {
        r.type = type;
        r.length = 1;
        rejected_encode(&full, &r, 16);
    }
    r = (struct dwc3_trb_request){0, INT64_C(0xffffff), 5, 2050};
    accepted(&full, &r);
    r = (struct dwc3_trb_request){UINT64_C(0xffffffff), 1, 1, 0};
    accepted(&full, &r);
    r.length = 0;
    accepted(&full, &r);
    r.length = 2;
    rejected_encode(&full, &r, 16);
    r.address = UINT64_C(0x100000000);
    r.length = 0;
    rejected_encode(&full, &r, 16);
    r.address = UINT64_MAX;
    rejected_encode(&full, &r, 16);
    r = (struct dwc3_trb_request){16, 16, 1, 2};
    accepted(&small, &r);
    r.address = 15;
    rejected_encode(&small, &r, 16);
    r.address = 17;
    rejected_encode(&small, &r, 16);
    r.address = 32;
    r.length = 0;
    accepted(&small, &r); /* Representable one-past span end for ZLP only. */
    r.length = 1;
    rejected_encode(&small, &r, 16);
    r.address = 33;
    r.length = 0;
    rejected_encode(&small, &r, 16);
    r = (struct dwc3_trb_request){31, 1, 1, 0};
    accepted(&small, &r);
}

static void test_decode(void)
{
    uint8_t bytes[18] = {0}, before[18];
    uint8_t *p = bytes + 1;
    struct dwc3_trb_decoded out;
    unsigned type, status, hwo, flags, bit, remaining;
    const size_t invalid_sizes[] = {0, 1, 15, 17, SIZE_MAX};
    size_t i;
    image(p, UINT32_C(0xdeadbeef), 0, 16);
    rejected_decode(NULL, 16);
    CHECK(!dwc3_trb_decode(p, 16, NULL));
    for (i = 0; i < sizeof invalid_sizes / sizeof invalid_sizes[0]; ++i)
        rejected_decode(p, invalid_sizes[i]);
    for (type = 1; type <= 5; ++type) {
        for (status = 0; status < 16; ++status) {
            for (hwo = 0; hwo < 2; ++hwo) {
                for (flags = 0; flags < 4; ++flags) {
                    uint32_t length = type == 2 ? 8u :
                        (type == 3 || type == 4 ? 0u : UINT32_C(0xabcdef));
                    image(p, UINT32_C(0xdeadbeef), length + status *
                          UINT32_C(0x10000000), type * 16u + hwo +
                          (flags % 2u) * 2u + (flags / 2u) * 2048u);
                    memcpy(before, bytes, sizeof bytes);
                    CHECK(dwc3_trb_decode(p, 16, &out));
                    CHECK(memcmp(before, bytes, sizeof bytes) == 0);
                    CHECK(out.address == UINT32_C(0xdeadbeef));
                    CHECK(out.type == type && out.status == status);
                    CHECK(out.remaining == length && out.hwo == (hwo != 0));
                    CHECK(out.status_known == (status == 0 || status == 2));
                    CHECK(out.last == ((flags % 2u) != 0));
                    CHECK(out.ioc == ((flags / 2u) != 0));
                }
            }
        }
    }
    for (type = 0; type < 64; ++type) {
        if (type >= 1 && type <= 5)
            continue;
        image(p, 0, 0, type * 16u);
        rejected_decode(p, 16);
    }
    for (bit = 0; bit < 32; ++bit) {
        image(p, 0, 0, 16);
        put_word(p + 4, UINT32_C(1) << bit);
        rejected_decode(p, 16);
        if (bit == 0 || bit == 1 || (bit >= 4 && bit <= 9) || bit == 11)
            continue;
        image(p, 0, 0, 16u | (UINT32_C(1) << bit));
        rejected_decode(p, 16);
    }
    for (bit = 24; bit < 28; ++bit) {
        image(p, 0, UINT32_C(1) << bit, 16);
        rejected_decode(p, 16); /* Includes unsupported PCM1, not just reserved. */
    }
    for (remaining = 0; remaining <= 9; ++remaining) {
        image(p, 0, remaining, 32);
        if (remaining <= 8) {
            CHECK(dwc3_trb_decode(p, 16, &out));
            CHECK(out.remaining == remaining);
        } else {
            rejected_decode(p, 16);
        }
    }
    for (type = 3; type <= 4; ++type) {
        image(p, 0, 1, type * 16u);
        rejected_decode(p, 16);
    }
}

static uint32_t random_word(void)
{
    static uint32_t state = UINT32_C(0x6d694437);
    state ^= state << 13;
    state ^= state >> 17;
    state ^= state << 5;
    return state;
}

static void test_random(void)
{
    unsigned i;
    for (i = 0; i < 100000; ++i) {
        struct dwc3_trb_span span;
        struct dwc3_trb_request r;
        struct dwc3_trb_decoded out;
        uint8_t bytes[16];
        uint32_t length = random_word() % UINT32_C(0x1000000);
        uint32_t available;
        unsigned flags = random_word() % 4u;
        unsigned status = random_word() % 16u;
        r.type = (int64_t)(random_word() % 5u + 1u);
        if (r.type == 2)
            length = 8;
        if (r.type == 3 || r.type == 4)
            length = 0;
        span.base = random_word() % UINT32_C(0xfe000000);
        span.size = (uint64_t)length + random_word() % 65536u + 1u;
        available = (uint32_t)(span.size - length);
        r.address = span.base + random_word() % (available + 1u);
        r.length = length;
        r.flags = (int64_t)((flags % 2u) * 2u + (flags / 2u) * 2048u);
        accepted(&span, &r);
        CHECK(dwc3_trb_encode(bytes, 16, &span, &r));
        length = length == 0 ? 0 : random_word() % (length + 1u);
        put_word(bytes + 8, length + status * UINT32_C(0x10000000));
        bytes[12] |= (uint8_t)(i % 2u);
        CHECK(dwc3_trb_decode(bytes, 16, &out));
        CHECK(out.remaining == length && out.status == status);
        CHECK(out.hwo == (i % 2u != 0));
        CHECK(out.status_known == (status == 0 || status == 2));
    }
}

int main(void)
{
    test_constants();
    test_encode();
    test_decode();
    test_random();
    printf("PASS: %" PRIu64 " checks; 100000 randomized TRBs\n", checks);
    return 0;
}
