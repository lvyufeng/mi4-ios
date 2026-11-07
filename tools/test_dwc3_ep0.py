#!/usr/bin/env python3
"""Offline tests. SSH runner compiles actual candidate text into Linux memfds.
No local/remote build files, compiler caches, or production writes are needed.
"""
import argparse
import hashlib
import json
from pathlib import Path
import shlex
import subprocess
import sys

HARNESS = r'''
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static unsigned long checks;
#define CHECK(x) do { ++checks; if (!(x)) { \
    fprintf(stderr, "CHECK failed at line %d: %s\n", __LINE__, #x); \
    exit(1); } } while (0)

static struct dwc3_ep0_plan request(struct dwc3_ep0 *e, unsigned bm,
    unsigned req, unsigned value, unsigned index, unsigned length)
{
    uint8_t unaligned[9] = {0};
    uint8_t *s = unaligned + 1;
    s[0] = (uint8_t)bm; s[1] = (uint8_t)req;
    s[2] = (uint8_t)value; s[3] = (uint8_t)(value >> 8);
    s[4] = (uint8_t)index; s[5] = (uint8_t)(index >> 8);
    s[6] = (uint8_t)length; s[7] = (uint8_t)(length >> 8);
    return dwc3_ep0_setup(e, s, 8);
}
static void fresh(struct dwc3_ep0 *e)
{
    CHECK(dwc3_ep0_init(e, dwc3_ep0_fixture, 4));
    CHECK(e->phase == DWC3_EP0_UNRESET);
    CHECK(request(e, 0x80, 6, 0x100, 0, 18).action == DWC3_EP0_STALL);
    dwc3_ep0_bus_reset(e);
    CHECK(e->address == 0 && e->configuration == 0);
}
static void status(struct dwc3_ep0 *e, struct dwc3_ep0_plan p)
{
    CHECK(p.action == DWC3_EP0_STATUS_IN || p.action == DWC3_EP0_STATUS_OUT);
    CHECK(dwc3_ep0_status_complete(e, p.transaction, p.status_direction, true));
}
static void finish_read(struct dwc3_ep0 *e, struct dwc3_ep0_plan p)
{
    CHECK(p.action == DWC3_EP0_DATA_IN && p.status_direction == DWC3_EP0_OUT);
    p = dwc3_ep0_data_complete(e, p.transaction, DWC3_EP0_IN, true);
    CHECK(p.action == DWC3_EP0_STATUS_OUT && p.length == 0 && !p.data);
    status(e, p);
}
static void address(struct dwc3_ep0 *e, unsigned value)
{
    uint8_t before = e->address;
    struct dwc3_ep0_plan p = request(e, 0, 5, value, 0, 0);
    CHECK(p.action == DWC3_EP0_STATUS_IN);
    CHECK(p.pending == DWC3_EP0_PENDING_ADDRESS && p.pending_value == value);
    CHECK(e->address == before && e->pending == DWC3_EP0_PENDING_ADDRESS);
    status(e, p);
    CHECK(e->address == value);
}
static void configure(struct dwc3_ep0 *e, unsigned value)
{
    uint8_t before = e->configuration;
    struct dwc3_ep0_plan p = request(e, 0, 9, value, 0, 0);
    CHECK(p.action == DWC3_EP0_STATUS_IN);
    CHECK(p.pending == DWC3_EP0_PENDING_CONFIG && p.pending_value == value);
    CHECK(e->configuration == before); /* Negative control: premature commit. */
    status(e, p);
    CHECK(e->configuration == value);
}
static void stalled(struct dwc3_ep0 *e, unsigned bm, unsigned req,
                    unsigned v, unsigned i, unsigned n)
{
    uint8_t a = e->address, c = e->configuration;
    struct dwc3_ep0_plan p = request(e, bm, req, v, i, n);
    if (p.action != DWC3_EP0_STALL)
        fprintf(stderr, "Expected STALL: bm=%u req=%u v=%u i=%u n=%u\n",
                bm, req, v, i, n);
    CHECK(p.action == DWC3_EP0_STALL);
    CHECK(!p.data && !p.length && !p.data_zlp);
    CHECK(p.pending == DWC3_EP0_PENDING_NONE && e->pending == p.pending);
    CHECK(e->address == a && e->configuration == c);
    CHECK(!dwc3_ep0_status_complete(e, p.transaction, DWC3_EP0_IN, true));
    CHECK(e->address == a && e->configuration == c);
}
static void test_fixture_and_lengths(void)
{
    static const uint8_t expected[] = {
        18,1,0,2,0,0,0,64,0x34,0x12,1,0,0,1,0,1,0,1,
        9,2,25,0,1,1,0,0x80,50,9,4,0,0,1,0xff,0,0,0,7,5,0x81,2,0,2,0,
        4,3,9,4,16,3,'O',0,'f',0,'f',0,'l',0,'i',0,'n',0,'e',0
    };
    struct dwc3_ep0 e;
    size_t i, offset = 0;
    unsigned n;
    fresh(&e);
    CHECK(sizeof expected == 63);
    for (i = 0; i < 4; ++i) {
        const struct dwc3_ep0_descriptor *d = &dwc3_ep0_fixture[i];
        CHECK(d->length <= sizeof expected - offset);
        CHECK(memcmp(expected + offset, d->bytes, d->length) == 0);
        offset += d->length;
        for (n = 0; n <= 65535; ++n) {
            struct dwc3_ep0_plan p = request(&e, 0x80, 6,
                ((unsigned)d->type << 8) | d->index, d->language, n);
            CHECK(p.length <= n && p.length <= d->length);
            if (n == 0) {
                CHECK(p.action == DWC3_EP0_STATUS_IN && !p.data && !p.data_zlp);
                CHECK(p.status_direction == DWC3_EP0_IN);
                status(&e, p);
            } else {
                CHECK(p.action == DWC3_EP0_DATA_IN);
                CHECK(p.length == (d->length < n ? d->length : n));
                CHECK(memcmp(p.data, d->bytes, p.length) == 0);
                CHECK(!p.data_zlp);
                if (n == 1 || n == 65535)
                    finish_read(&e, p);
            }
        }
    }
    CHECK(offset == sizeof expected);
}
static void test_shape_and_zlp(void)
{
    static const size_t sizes[] = {0,1,18,63,64,65,128,254,4096,SIZE_MAX};
    struct dwc3_ep0 e;
    struct dwc3_ep0_descriptor table[4];
    uint8_t long_string[64] = {64,3};
    size_t i;
    unsigned n;
    memcpy(table, dwc3_ep0_fixture, sizeof table);
    table[3].bytes = long_string; table[3].length = sizeof long_string;
    CHECK(dwc3_ep0_init(&e, table, 4)); dwc3_ep0_bus_reset(&e);
    for (i = 0; i < sizeof sizes / sizeof sizes[0]; ++i) {
        for (n = 0; n <= 65535; ++n) {
            struct dwc3_ep0_in_shape s = dwc3_ep0_shape_in(sizes[i], (uint16_t)n);
            CHECK(s.length <= sizes[i] && s.length <= n);
            CHECK(s.length == (sizes[i] < n ? sizes[i] : n));
            CHECK(s.data_stage == (n != 0));
            CHECK(s.data_zlp == (sizes[i] < n && sizes[i] % 64 == 0));
            CHECK(s.status_direction == (n ? DWC3_EP0_OUT : DWC3_EP0_IN));
        }
    }
    for (n = 0; n <= 130; ++n) {
        struct dwc3_ep0_plan p = request(&e, 0x80, 6, 0x301, 0x409, n);
        if (!n) { status(&e, p); continue; }
        CHECK(p.action == DWC3_EP0_DATA_IN && p.length == (n < 64 ? n : 64));
        CHECK(p.data_zlp == (n > 64));
        CHECK(memcmp(p.data, long_string, p.length) == 0);
        finish_read(&e, p);
    }
}
static void test_state_and_completion(void)
{
    struct dwc3_ep0 e;
    struct dwc3_ep0_plan p, old;
    uint64_t token;
    fresh(&e);
    stalled(&e, 0, 9, 0, 0, 0); stalled(&e, 0, 9, 1, 0, 0);
    stalled(&e, 0x80, 8, 0, 0, 1); stalled(&e, 0x80, 0, 0, 0, 2);
    address(&e, 0); address(&e, 127); address(&e, 7);
    p = request(&e, 0x80, 8, 0, 0, 1);
    CHECK(p.length == 1 && p.data[0] == 0); finish_read(&e, p);
    configure(&e, 0); configure(&e, 1); configure(&e, 1);
    stalled(&e, 0, 5, 0, 0, 0); stalled(&e, 0, 5, 8, 0, 0);
    p = request(&e, 0x80, 8, 0, 0, 1);
    CHECK(p.data[0] == 1); finish_read(&e, p);
    p = request(&e, 0x81, 10, 0, 0, 1);
    CHECK(p.length == 1 && p.data[0] == 0); finish_read(&e, p);
    p = request(&e, 1, 11, 0, 0, 0); status(&e, p);
    p = request(&e, 0x81, 0, 0, 0, 2);
    CHECK(p.length == 2 && p.data[0] == 0 && p.data[1] == 0); finish_read(&e, p);
    configure(&e, 0);
    stalled(&e, 0x81, 10, 0, 0, 1); stalled(&e, 1, 11, 0, 0, 0);
    old = request(&e, 0, 5, 19, 0, 0);
    CHECK(e.address == 7);
    p = request(&e, 0, 5, 23, 0, 0);
    CHECK(!dwc3_ep0_status_complete(&e, old.transaction, DWC3_EP0_IN, true));
    CHECK(e.address == 7 && e.pending_value == 23);
    status(&e, p); CHECK(e.address == 23);
    CHECK(!dwc3_ep0_status_complete(&e, p.transaction, DWC3_EP0_IN, true));
    p = request(&e, 0, 5, 32, 0, 0);
    CHECK(!dwc3_ep0_status_complete(&e, p.transaction, DWC3_EP0_IN, false));
    CHECK(e.address == 23 && e.pending == DWC3_EP0_PENDING_NONE);
    CHECK(!dwc3_ep0_status_complete(&e, p.transaction, DWC3_EP0_IN, true));
    p = request(&e, 0, 5, 32, 0, 0);
    CHECK(!dwc3_ep0_status_complete(&e, p.transaction, DWC3_EP0_OUT, true));
    CHECK(e.address == 23 && e.pending == DWC3_EP0_PENDING_NONE);
    p = request(&e, 0, 5, 32, 0, 0);
    CHECK(dwc3_ep0_data_complete(&e, p.transaction, DWC3_EP0_IN, true).action
          == DWC3_EP0_STALL);
    CHECK(!dwc3_ep0_status_complete(&e, p.transaction, DWC3_EP0_IN, true));
    CHECK(e.address == 23);
    old = request(&e, 0, 9, 1, 0, 0);
    CHECK(e.configuration == 0);
    p = request(&e, 0x80, 6, 0x100, 0, 18);
    CHECK(!dwc3_ep0_status_complete(&e, old.transaction, DWC3_EP0_IN, true));
    CHECK(e.configuration == 0); finish_read(&e, p);
    old = request(&e, 0, 9, 1, 0, 0);
    stalled(&e, 0x40, 9, 1, 0, 0);
    CHECK(!dwc3_ep0_status_complete(&e, old.transaction, DWC3_EP0_IN, true));
    CHECK(e.configuration == 0);
    p = request(&e, 0, 9, 1, 0, 0);
    CHECK(!dwc3_ep0_status_complete(&e, p.transaction, DWC3_EP0_IN, false));
    CHECK(e.configuration == 0);
    configure(&e, 1);
    p = request(&e, 0, 9, 0, 0, 0);
    CHECK(e.configuration == 1);
    CHECK(!dwc3_ep0_status_complete(&e, p.transaction, DWC3_EP0_IN, false));
    CHECK(e.configuration == 1);
    old = request(&e, 0, 9, 0, 0, 0);
    token = old.transaction;
    dwc3_ep0_bus_reset(&e);
    CHECK(e.address == 0 && e.configuration == 0 && !e.pending);
    CHECK(!dwc3_ep0_status_complete(&e, token, DWC3_EP0_IN, true));
    address(&e, 8);
    CHECK(!dwc3_ep0_status_complete(&e, token, DWC3_EP0_IN, true));
    CHECK(e.address == 8 && e.configuration == 0);
    old = request(&e, 0, 5, 50, 0, 0);
    dwc3_ep0_bus_reset(&e);
    CHECK(!dwc3_ep0_status_complete(&e, old.transaction, DWC3_EP0_IN, true));
    CHECK(e.address == 0 && e.configuration == 0);
    address(&e, 8); address(&e, 0);
    stalled(&e, 0, 9, 1, 0, 0);
    p = request(&e, 0x80, 6, 0x100, 0, 0); status(&e, p);
    CHECK(e.phase == DWC3_EP0_IDLE);
}
static void test_data_guards(void)
{
    struct dwc3_ep0 e;
    struct dwc3_ep0_plan p, old;
    fresh(&e); address(&e, 3);
    p = request(&e, 0x80, 6, 0x100, 0, 18);
    CHECK(!dwc3_ep0_status_complete(&e, p.transaction, DWC3_EP0_OUT, true));
    CHECK(e.phase == DWC3_EP0_IDLE);
    p = request(&e, 0x80, 6, 0x100, 0, 18);
    CHECK(dwc3_ep0_data_complete(&e, p.transaction, DWC3_EP0_OUT, true).action
          == DWC3_EP0_STALL);
    CHECK(!dwc3_ep0_status_complete(&e, p.transaction, DWC3_EP0_OUT, true));
    p = request(&e, 0x80, 6, 0x100, 0, 18);
    CHECK(dwc3_ep0_data_complete(&e, p.transaction, DWC3_EP0_IN, false).action
          == DWC3_EP0_STALL);
    old = request(&e, 0x80, 6, 0x100, 0, 18);
    p = request(&e, 0x80, 6, 0x200, 0, 25);
    CHECK(dwc3_ep0_data_complete(&e, old.transaction, DWC3_EP0_IN, true).action
          == DWC3_EP0_STALL);
    CHECK(e.phase == DWC3_EP0_DATA); finish_read(&e, p);
    p = request(&e, 0x80, 6, 0x100, 0, 18);
    p = dwc3_ep0_data_complete(&e, p.transaction, DWC3_EP0_IN, true);
    CHECK(!dwc3_ep0_status_complete(&e, p.transaction, DWC3_EP0_IN, true));
    CHECK(!dwc3_ep0_status_complete(&e, p.transaction, DWC3_EP0_OUT, true));
    p = request(&e, 0x80, 6, 0x100, 0, 18);
    p = dwc3_ep0_data_complete(&e, p.transaction, DWC3_EP0_IN, true);
    CHECK(!dwc3_ep0_status_complete(&e, p.transaction, DWC3_EP0_OUT, false));
    CHECK(e.address == 3 && e.configuration == 0);
    p = request(&e, 0, 5, 44, 0, 0);
    CHECK(!dwc3_ep0_status_complete(&e, p.transaction,
                                   (enum dwc3_ep0_direction)99, true));
    CHECK(e.address == 3);
}
static void test_negative_requests(void)
{
    static const unsigned values[] = {1,2,127,128,255,256,0x1000,0xffff};
    static const unsigned unsupported[] = {1,3,7,12,0x30,0x31,0xff};
    struct dwc3_ep0 e;
    unsigned bm, i, v;
    size_t k;
    fresh(&e); address(&e, 4);
    for (bm = 0; bm < 256; ++bm) {
        if (bm != 0x80) {
            stalled(&e, bm, 6, 0x100, 0, 18);
            stalled(&e, bm, 8, 0, 0, 1);
        }
        if (bm != 0 && bm != 0x80) {
            stalled(&e, bm, 5, 5, 0, 0);
            stalled(&e, bm, 9, 1, 0, 0);
        }
        if (bm != 0x80 && bm != 0x82)
            stalled(&e, bm, 0, 0, 0, 2);
        for (k = 0; k < sizeof unsupported / sizeof unsupported[0]; ++k)
            stalled(&e, bm, unsupported[k], 0, 0, 0);
    }
    for (v = 128; v <= 65535; ++v)
        stalled(&e, 0, 5, v, 0, 0);
    for (v = 2; v <= 65535; ++v)
        stalled(&e, 0, 9, v, 0, 0);
    for (i = 1; i <= 65535; ++i) {
        stalled(&e, 0, 5, 5, i, 0); stalled(&e, 0, 9, 1, i, 0);
        stalled(&e, 0x80, 6, 0x100, i, 18);
        stalled(&e, 0x80, 8, 0, i, 1);
    }
    for (k = 0; k < sizeof values / sizeof values[0]; ++k) {
        unsigned n = values[k];
        stalled(&e, 0, 5, 5, 0, n); stalled(&e, 0, 9, 1, 0, n);
        stalled(&e, 0x80, 8, n, 0, 1); stalled(&e, 0x80, 0, n, 0, 2);
        if (n <= 255) stalled(&e, 0x80, 6, 0x100 | n, 0, 18);
    }
    for (v = 0; v <= 255; ++v)
        if (v != 1 && v != 2 && v != 3)
            stalled(&e, 0x80, 6, v << 8, 0, 65535);
    stalled(&e, 0x80, 6, 0x300, 0x409, 4);
    stalled(&e, 0x80, 6, 0x301, 0, 16);
    stalled(&e, 0x80, 6, 0x301, 0x411, 16);
    stalled(&e, 0x80, 6, 0x302, 0x409, 16);
    stalled(&e, 0x80, 6, 0x201, 0, 25);
    stalled(&e, 0x82, 0, 0, 0x81, 2); /* Bulk halt/status deferred. */
    stalled(&e, 0x82, 0, 0, 0x100, 2);
    stalled(&e, 0x82, 0, 0, 0x10, 2);
    configure(&e, 1);
    for (bm = 0; bm < 256; ++bm) {
        if (bm != 0x81) stalled(&e, bm, 10, 0, 0, 1);
        if (bm != 1 && bm != 0x81) stalled(&e, bm, 11, 0, 0, 0);
    }
    for (k = 0; k < sizeof values / sizeof values[0]; ++k) {
        unsigned bad = values[k];
        stalled(&e, 0x81, 10, bad, 0, 1);
        stalled(&e, 0x81, 10, 0, bad, 1);
        stalled(&e, 1, 11, bad, 0, 0); stalled(&e, 1, 11, 0, bad, 0);
        stalled(&e, 1, 11, 0, 0, bad);
    }
    for (i = 0; i < 4; ++i) {
        if (i != 1) { stalled(&e, 0x80, 8, 0, 0, i);
                      stalled(&e, 0x81, 10, 0, 0, i); }
        if (i != 2) stalled(&e, 0x80, 0, 0, 0, i);
    }
    for (i = 0; i <= 0x80; i += 0x80) {
        struct dwc3_ep0_plan p = request(&e, 0x82, 0, 0, i, 2);
        CHECK(p.length == 2 && p.data[0] == 0 && p.data[1] == 0);
        finish_read(&e, p);
    }
}
static void test_table_and_setup_bounds(void)
{
    struct dwc3_ep0 e;
    struct dwc3_ep0_descriptor t[17];
    struct dwc3_ep0_plan p;
    uint8_t b[256] = {0};
    uint8_t minimal[1] = {0x80};
    size_t n;
    CHECK(!dwc3_ep0_init(NULL, dwc3_ep0_fixture, 4));
    CHECK(!dwc3_ep0_init(&e, NULL, 4));
    CHECK(!dwc3_ep0_init(&e, dwc3_ep0_fixture, 0));
    CHECK(!dwc3_ep0_init(&e, dwc3_ep0_fixture, 17));
    for (n = 0; n < 4; ++n) {
        memcpy(t, dwc3_ep0_fixture, sizeof dwc3_ep0_fixture);
        t[n].bytes = NULL; CHECK(!dwc3_ep0_init(&e, t, 4));
        t[n] = dwc3_ep0_fixture[n]; t[n].length = 0;
        CHECK(!dwc3_ep0_init(&e, t, 4));
        t[n].bytes = minimal; t[n].length = 1;
        CHECK(!dwc3_ep0_init(&e, t, 4));
        t[n].length = SIZE_MAX; CHECK(!dwc3_ep0_init(&e, t, 4));
        t[n].length = 4097; CHECK(!dwc3_ep0_init(&e, t, 4));
    }
    memcpy(t, dwc3_ep0_fixture, sizeof dwc3_ep0_fixture);
    t[4] = t[3]; CHECK(!dwc3_ep0_init(&e, t, 5));
    CHECK(!dwc3_ep0_init(&e, t + 1, 3));
    t[3].language = 0x411; CHECK(!dwc3_ep0_init(&e, t, 4));
    t[3] = dwc3_ep0_fixture[3]; t[3].index = 2;
    CHECK(!dwc3_ep0_init(&e, t, 4));
    for (n = 0; n < 25; ++n) {
        memcpy(t, dwc3_ep0_fixture, sizeof dwc3_ep0_fixture);
        memcpy(b, t[1].bytes, 25); b[n] ^= 0x40; t[1].bytes = b;
        if (n == 8) continue; /* Power budget is caller-owned descriptor data. */
        if (n == 7) { /* Self-powered variant is allowed and reported. */
            CHECK(dwc3_ep0_init(&e, t, 4)); dwc3_ep0_bus_reset(&e);
            address(&e, 1); p = request(&e, 0x80, 0, 0, 0, 2);
            CHECK(p.data[0] == 1 && p.data[1] == 0); finish_read(&e, p);
        } else CHECK(!dwc3_ep0_init(&e, t, 4));
    }
    memcpy(t, dwc3_ep0_fixture, sizeof dwc3_ep0_fixture);
    t[1].bytes = b; t[1].length = 9; b[0] = 9; b[1] = 2;
    CHECK(!dwc3_ep0_init(&e, t, 4));
    memcpy(t, dwc3_ep0_fixture, sizeof dwc3_ep0_fixture);
    t[3].bytes = b; t[3].length = 256; b[0] = 0; b[1] = 3;
    CHECK(!dwc3_ep0_init(&e, t, 4));
    t[3].length = 15; b[0] = 15; CHECK(!dwc3_ep0_init(&e, t, 4));
    t[3].length = 16; b[0] = 14; CHECK(!dwc3_ep0_init(&e, t, 4));
    t[3].length = 2; b[0] = 2; CHECK(dwc3_ep0_init(&e, t, 4));
    dwc3_ep0_bus_reset(&e);
    p = request(&e, 0x80, 6, 0x301, 0x409, 18);
    CHECK(p.length == 2); finish_read(&e, p);
    fresh(&e);
    for (n = 0; n < 11; ++n) {
        if (n == 8) continue;
        p = request(&e, 0, 5, 17, 0, 0);
        CHECK(dwc3_ep0_setup(&e, minimal, n).action == DWC3_EP0_STALL);
        CHECK(!dwc3_ep0_status_complete(&e, p.transaction, DWC3_EP0_IN, true));
        CHECK(e.address == 0 && e.pending == DWC3_EP0_PENDING_NONE);
    }
    p = request(&e, 0, 5, 17, 0, 0);
    CHECK(dwc3_ep0_setup(&e, NULL, 8).action == DWC3_EP0_STALL);
    CHECK(!dwc3_ep0_status_complete(&e, p.transaction, DWC3_EP0_IN, true));
    CHECK(dwc3_ep0_setup(NULL, NULL, 0).action == DWC3_EP0_STALL);
    CHECK(dwc3_ep0_data_complete(NULL, 0, DWC3_EP0_IN, true).action
          == DWC3_EP0_STALL);
    CHECK(!dwc3_ep0_status_complete(NULL, 0, DWC3_EP0_IN, true));
    dwc3_ep0_bus_reset(NULL);
    CHECK(!dwc3_ep0_init(&e, NULL, 0)); dwc3_ep0_bus_reset(&e);
    CHECK(request(&e, 0x80, 6, 0x100, 0, 18).action == DWC3_EP0_STALL);
    fresh(&e);
    e.transaction = UINT64_MAX - 1; /* White-box exhaustion injection only. */
    p = request(&e, 0, 5, 1, 0, 0);
    CHECK(p.transaction == UINT64_MAX); status(&e, p);
    CHECK(request(&e, 0, 5, 2, 0, 0).action == DWC3_EP0_STALL);
    dwc3_ep0_bus_reset(&e);
    CHECK(e.address == 0 && e.configuration == 0);
    CHECK(request(&e, 0, 5, 2, 0, 0).action == DWC3_EP0_STALL);
    CHECK(!dwc3_ep0_status_complete(&e, p.transaction, DWC3_EP0_IN, true));
}
static void test_no_data_direction(void)
{
    struct dwc3_ep0 e;
    unsigned bm;
    fresh(&e);
    for (bm = 0; bm < 256; ++bm) {
        struct dwc3_ep0_plan p = request(&e, bm, 6, 0x100, 0, 0);
        if ((bm & 0x7f) == 0) {
            CHECK(p.action == DWC3_EP0_STATUS_IN);
            CHECK(p.status_direction == DWC3_EP0_IN && !p.length && !p.data_zlp);
            status(&e, p);
        } else CHECK(p.action == DWC3_EP0_STALL);
    }
    status(&e, request(&e, 0x80, 5, 11, 0, 0));
    CHECK(e.address == 11);
    status(&e, request(&e, 0x80, 9, 1, 0, 0));
    CHECK(e.configuration == 1);
    status(&e, request(&e, 0x81, 11, 0, 0, 0));
    status(&e, request(&e, 0x80, 9, 0, 0, 0));
    CHECK(e.configuration == 0 && e.address == 11);
}
int main(void)
{
    test_fixture_and_lengths(); test_shape_and_zlp();
    test_state_and_completion(); test_data_guards(); test_no_data_direction();
    test_negative_requests(); test_table_and_setup_bounds();
    printf("PASS %lu checks; 7 request kinds; fixture 4 descriptors / 63 bytes\n",
           checks);
    return 0;
}
'''

RUNNER = r'''
import hashlib, json, os, shlex, subprocess, sys
p = json.load(sys.stdin)
env = dict(os.environ, TMPDIR='/proc/self/fd', CCACHE_DISABLE='1',
           PYTHONDONTWRITEBYTECODE='1')
flags = ['-std=c11', '-O0', '-Wall', '-Wextra', '-Werror', '-pedantic', '-pipe']
source = p['source']
mutations = [
    ('early-config-commit',
     'ep->pending = DWC3_EP0_PENDING_CONFIG;\n        ep->pending_value = (uint8_t)value;',
     'ep->pending = DWC3_EP0_PENDING_CONFIG;\n        ep->pending_value = (uint8_t)value;\n        ep->configuration = (uint8_t)value;'),
    ('unbounded-response', 'p.length = s.length;', 'p.length = requested;'),
    ('descriptor-wrong-direction', 'if (requested ? bm != 0x80 : bm != 0)\n            break;',
     'if (requested ? (bm & 0x7fu) != 0 : bm != 0)\n            break;')
]

def execute(cc, text, sanitizer=False):
    obj = os.memfd_create('ep0-object', 0)
    exe = os.memfd_create('ep0-test', 0)
    try:
        objpath = '/proc/self/fd/' + str(obj)
        exepath = '/proc/self/fd/' + str(exe)
        extra = ['-fsanitize=address,undefined', '-fno-omit-frame-pointer'] if sanitizer else []
        combined = (p['header'] + '\n#line 1 "dwc3_ep0.c"\n' +
                    text.replace('#include "dwc3_ep0.h"', '') +
                    '\n#line 1 "offline_harness.c"\n' + p['harness'])
        r = subprocess.run([cc] + flags + extra + ['-x','c','-c','-', '-o',objpath],
                           input=combined, text=True, capture_output=True,
                           pass_fds=(obj,), env=env)
        if r.returncode:
            raise RuntimeError('compile [exit code: %d]\n%s%s' %
                               (r.returncode, r.stdout, r.stderr))
        link = [cc] + extra + ['-fno-use-linker-plugin', objpath, '-o',exepath]
        if cc == 'gcc':
            # collect2 itself insists on a named temporary file. Ask GCC for
            # its exact native link arguments, then run ld directly. No LTO,
            # no collect2 constructor work is needed by this plain C11 TU.
            dry = subprocess.run(link + ['-###'], text=True, capture_output=True,
                                 pass_fds=(obj,exe), env=env)
            if dry.returncode:
                raise RuntimeError('GCC link dry-run failed: ' + dry.stderr)
            commands = [shlex.split(line) for line in dry.stderr.splitlines()
                        if line.lstrip().startswith('/') and '/collect2 ' in line]
            if len(commands) != 1:
                raise RuntimeError('Cannot identify GCC native ld arguments')
            link = ['ld'] + commands[0][1:]
        r = subprocess.run(link, text=True, capture_output=True,
                           pass_fds=(obj,exe), env=env)
        if r.returncode:
            raise RuntimeError('link [exit code: %d]\n%s%s' %
                               (r.returncode, r.stdout, r.stderr))
        os.fchmod(exe, 0o700)
        return subprocess.run([exepath], text=True, capture_output=True,
                              pass_fds=(exe,), env=env)
    finally:
        os.close(obj); os.close(exe)

print('Candidate SHA256 ' + hashlib.sha256(source.encode()).hexdigest(), flush=True)
for cc in ('clang','gcc'):
    v = subprocess.run([cc,'--version'], text=True, capture_output=True, check=True)
    print(v.stdout.splitlines()[0], flush=True)
    for sanitized in (False, True):
        r = execute(cc, source, sanitized)
        print('%s %s [exit code: %d] %s' %
              (cc, 'ASan+UBSan' if sanitized else 'strict-C11',
               r.returncode, r.stdout.strip()), flush=True)
        if r.returncode:
            raise RuntimeError(r.stderr)
    for name, old, new in mutations:
        if source.count(old) != 1:
            raise RuntimeError('mutation anchor not unique: ' + name)
        r = execute(cc, source.replace(old,new))
        if r.returncode != 1 or 'CHECK failed' not in r.stderr:
            raise RuntimeError('negative control not caught: %s [exit code: %d]\n%s%s' %
                               (name, r.returncode, r.stdout, r.stderr))
        print('%s REJECTED %s [expected exit code: 1] %s' %
              (cc, name, r.stderr.strip()), flush=True)
print('PASS: 4 clean strict/sanitized executions; 6 rejected mutation executions',
      flush=True)
'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--ssh', metavar='HOST', help='Linux host, e.g. 2080ti')
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    header = (root / 'src/dwc3_ep0.h').read_text()
    source = (root / 'src/dwc3_ep0.c').read_text()
    payload = json.dumps(dict(header=header, source=source, harness=HARNESS))
    if args.ssh:
        cmd = ['ssh', '-o', 'BatchMode=yes', '-o', 'ConnectTimeout=10', args.ssh,
               'python3 -B -c ' + shlex.quote(RUNNER)]
    elif sys.platform.startswith('linux'):
        cmd = [sys.executable, '-B', '-c', RUNNER]
    else:
        parser.error('Linux memfd runner required; use --ssh 2080ti on macOS')
    result = subprocess.run(cmd, input=payload, text=True, check=False)
    print('[exit code: %d]' % result.returncode, flush=True)
    return result.returncode


if __name__ == '__main__':
    sys.exit(main())
