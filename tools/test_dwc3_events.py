#!/usr/bin/env python3
"""Offline acceptance: compile the actual candidate, never model its decoder.

No device access, network, package install, or repository writes. Test artifacts
are created in a fresh directory beneath --repo-root. Vendor text is read only.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile


ORACLE = {
    "DWC3_GEVNTCOUNT_MASK": ("DWC3_EVENTS_COUNT_MASK", 0xFFFC),
    "DWC3_EVENT_TYPE_DEV": ("DWC3_EVENTS_DEV_CATEGORY", 0),
    "DWC3_EVENT_TYPE_CARKIT": ("DWC3_EVENTS_CARKIT_CATEGORY", 3),
    "DWC3_EVENT_TYPE_I2C": ("DWC3_EVENTS_I2C_CATEGORY", 4),
    "DWC3_DEVICE_EVENT_DISCONNECT": ("DWC3_EVENTS_DEV_DISCONNECT", 0),
    "DWC3_DEVICE_EVENT_RESET": ("DWC3_EVENTS_DEV_RESET", 1),
    "DWC3_DEVICE_EVENT_CONNECT_DONE": ("DWC3_EVENTS_DEV_CONNECT_DONE", 2),
    "DWC3_DEVICE_EVENT_LINK_STATUS_CHANGE": ("DWC3_EVENTS_DEV_LINK_CHANGE", 3),
    "DWC3_DEVICE_EVENT_WAKEUP": ("DWC3_EVENTS_DEV_WAKEUP", 4),
    "DWC3_DEVICE_EVENT_HIBER_REQ": ("DWC3_EVENTS_DEV_HIBER_REQ", 5),
    "DWC3_DEVICE_EVENT_EOPF": ("DWC3_EVENTS_DEV_EOPF", 6),
    "DWC3_DEVICE_EVENT_SOF": ("DWC3_EVENTS_DEV_SOF", 7),
    "DWC3_DEVICE_EVENT_ERRATIC_ERROR": ("DWC3_EVENTS_DEV_ERRATIC_ERROR", 9),
    "DWC3_DEVICE_EVENT_CMD_CMPL": ("DWC3_EVENTS_DEV_CMD_COMPLETE", 10),
    "DWC3_DEVICE_EVENT_OVERFLOW": ("DWC3_EVENTS_DEV_OVERFLOW", 11),
    "DWC3_DEVICE_EVENT_VENDOR_DEV_TEST_LMP": ("DWC3_EVENTS_DEV_TEST_LMP", 12),
    "DWC3_DEPEVT_XFERCOMPLETE": ("DWC3_EVENTS_EP_XFER_COMPLETE", 1),
    "DWC3_DEPEVT_XFERINPROGRESS": ("DWC3_EVENTS_EP_XFER_IN_PROGRESS", 2),
    "DWC3_DEPEVT_XFERNOTREADY": ("DWC3_EVENTS_EP_XFER_NOT_READY", 3),
    "DWC3_DEPEVT_RXTXFIFOEVT": ("DWC3_EVENTS_EP_FIFO", 4),
    "DWC3_DEPEVT_STREAMEVT": ("DWC3_EVENTS_EP_STREAM", 6),
    "DWC3_DEPEVT_EPCMDCMPLT": ("DWC3_EVENTS_EP_CMD_COMPLETE", 7),
}
LAYOUTS = {
    "dwc3_event_type": [("is_devspec", 1), ("type", 6), ("reserved8_31", 25)],
    "dwc3_event_depevt": [("one_bit", 1), ("endpoint_number", 5),
                          ("endpoint_event", 4), ("reserved11_10", 2),
                          ("status", 4), ("parameters", 16)],
    "dwc3_event_devt": [("one_bit", 1), ("device_event", 7), ("type", 4),
                         ("reserved15_12", 4), ("event_info", 8),
                         ("reserved31_24", 8)],
    "dwc3_event_gevt": [("one_bit", 1), ("device_event", 7),
                         ("phy_port_number", 4), ("reserved31_12", 20)],
}

# Independent inverse encoders live in the C acceptance executable, not Python.
HARNESS = r'''
#include "dwc3_events.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static unsigned long checks;
#define CHECK(x) do { ++checks; if (!(x)) { \
    fprintf(stderr, "FAIL line %d: %s\n", __LINE__, #x); exit(1); \
} } while (0)

static uint32_t ep_word(unsigned ep, unsigned type, unsigned status, unsigned p)
{
    return (uint32_t)ep * 2u + (uint32_t)type * 64u +
           (uint32_t)status * 4096u + (uint32_t)p * 65536u;
}
static uint32_t dev_word(unsigned type, unsigned info)
{
    return UINT32_C(1) + (uint32_t)type * 256u + (uint32_t)info * 65536u;
}
static void put_word(uint8_t *p, uint32_t word)
{
    p[0] = (uint8_t)word;
    p[1] = (uint8_t)(word / UINT32_C(256));
    p[2] = (uint8_t)(word / UINT32_C(65536));
    p[3] = (uint8_t)(word / UINT32_C(16777216));
}
static int ep_known(unsigned type)
{
    return type == 1u || type == 2u || type == 3u || type == 4u ||
           type == 6u || type == 7u;
}
static int dev_known(unsigned type)
{
    return type <= 7u || (type >= 9u && type <= 12u);
}
struct capture {
    struct dwc3_event_decoded events[32];
    size_t accepted;
    size_t calls;
    size_t pause_at;
};
static struct capture fresh(void)
{
    struct capture c = {0};
    c.pause_at = SIZE_MAX;
    return c;
}
static enum dwc3_events_action capture_event(
    void *context, const struct dwc3_event_decoded *event)
{
    struct capture *c = context;
    ++c->calls;
    if (c->accepted == c->pause_at) {
        return DWC3_EVENTS_PAUSE;
    }
    if (c->accepted < 32u) {
        c->events[c->accepted] = *event;
    }
    ++c->accepted;
    return DWC3_EVENTS_ACCEPT;
}
struct mock_owner { size_t cursor; size_t ack_bytes; size_t writes; };
static void mock_commit(struct mock_owner *owner, struct dwc3_events_result r)
{
    if (r.consumed_bytes != 0u) {
        owner->cursor = r.next_cursor;
        owner->ack_bytes += r.consumed_bytes;
        ++owner->writes;
    }
}
static void test_decode(void)
{
    unsigned ep, type, status, info;
    const unsigned params[] = {0u, 1u, 0x1234u, 0x8000u, 0xffffu};
    size_t i;
    struct dwc3_event_decoded e;
    for (ep = 0; ep < 32u; ++ep) {
        for (type = 0; type < 16u; ++type) {
            for (status = 0; status < 16u; ++status) {
                for (i = 0; i < sizeof(params) / sizeof(params[0]); ++i) {
                    uint32_t w = ep_word(ep, type, status, params[i]);
                    e = dwc3_events_decode(w);
                    CHECK(e.raw == w);
                    CHECK(e.family == DWC3_EVENTS_ENDPOINT);
                    CHECK(e.endpoint_physical == ep && e.type == type);
                    CHECK(e.status == status && e.parameters == params[i]);
                    CHECK(e.known == (ep_known(type) != 0));
                    CHECK(e.diagnostics == (ep_known(type) ? 0u :
                          DWC3_EVENTS_DIAG_UNKNOWN));
                    CHECK(e.info == 0u && e.category == 0u);
                }
            }
        }
    }
    for (type = 0; type < 16u; ++type) {
        for (info = 0; info < 256u; ++info) {
            uint32_t w = dev_word(type, info);
            uint32_t diag = dev_known(type) ? 0u : DWC3_EVENTS_DIAG_UNKNOWN;
            if (type == 11u) { diag |= DWC3_EVENTS_DIAG_OVERFLOW; }
            if (type == 12u) { diag |= DWC3_EVENTS_DIAG_UNSUPPORTED_LENGTH; }
            e = dwc3_events_decode(w);
            CHECK(e.raw == w && e.family == DWC3_EVENTS_DEVICE);
            CHECK(e.type == type && e.info == info && e.category == 0u);
            CHECK(e.known == (dev_known(type) != 0));
            CHECK(e.diagnostics == diag);
            CHECK(e.endpoint_physical == 0u && e.status == 0u &&
                  e.parameters == 0u);
        }
    }
    for (type = 1; type < 128u; ++type) {
        e = dwc3_events_decode(1u + type * 2u + UINT32_C(0xa50100));
        CHECK(e.family == DWC3_EVENTS_OTHER && !e.known);
        CHECK(e.category == type && e.diagnostics == DWC3_EVENTS_DIAG_UNKNOWN);
        CHECK(e.type == 0u && e.info == 0u && e.parameters == 0u);
    }
    e = dwc3_events_decode(UINT32_C(0xabcdaf7e));
    CHECK(e.family == DWC3_EVENTS_ENDPOINT && e.endpoint_physical == 31u);
    CHECK(e.type == 13u && e.status == 10u && e.parameters == 0xabcdu);
    CHECK(e.diagnostics == (DWC3_EVENTS_DIAG_UNKNOWN | DWC3_EVENTS_DIAG_RESERVED));
    e = dwc3_events_decode(UINT32_C(0xffa5f301));
    CHECK(e.family == DWC3_EVENTS_DEVICE && e.type == 3u && e.info == 0xa5u);
    CHECK(e.diagnostics == DWC3_EVENTS_DIAG_RESERVED);
    e = dwc3_events_decode(UINT32_C(0x80000001));
    CHECK(e.known && e.type == 0u && e.diagnostics == DWC3_EVENTS_DIAG_RESERVED);
}
static void test_count(void)
{
    uint32_t high = 0u;
    CHECK(dwc3_events_count_bytes(UINT32_C(0x80000004), &high) == 4u);
    CHECK(high == UINT32_C(0x80000000));
    CHECK(dwc3_events_count_bytes(UINT32_C(0xffffffff), &high) == 65535u);
    CHECK(high == UINT32_C(0xffff0000));
    CHECK(dwc3_events_count_bytes(3u, NULL) == 3u);
    CHECK(dwc3_events_count_bytes(65532u, &high) == DWC3_EVENTS_COUNT_MASK);
    CHECK(high == 0u);
}
static void test_ring_basics(void)
{
    /* Deliberately unaligned base pointer; only the byte cursor is aligned. */
    uint8_t storage[33] = {0};
    uint8_t *ring = storage + 1;
    uint8_t saved[33];
    struct capture c = fresh();
    struct dwc3_events_result r;
    struct mock_owner owner = {0};
    memcpy(saved, storage, sizeof(storage));
    r = dwc3_events_consume(ring, 16u, 0u, 0u, SIZE_MAX, capture_event, &c);
    CHECK(r.status == DWC3_EVENTS_OK && r.consumed_bytes == 0u);
    CHECK(c.calls == 0u && r.next_cursor == 0u);
    r = dwc3_events_consume(ring, 16u, 0u, 16u, SIZE_MAX, capture_event, &c);
    CHECK(r.status == DWC3_EVENTS_OK && r.consumed_bytes == 16u);
    CHECK(r.next_cursor == 0u && r.delivered_events == 4u);
    CHECK(c.calls == 4u && r.unknown_events == 4u && r.overflow_events == 0u);
    CHECK(c.events[0].family == DWC3_EVENTS_ENDPOINT && !c.events[0].known);
    CHECK(memcmp(saved, storage, sizeof(storage)) == 0);
    mock_commit(&owner, r);
    CHECK(owner.ack_bytes == 16u && owner.writes == 1u);

    put_word(ring, dev_word(1u, 0u));
    put_word(ring + 4, dev_word(2u, 0x80u));
    put_word(ring + 8, dev_word(3u, 0xa5u));
    put_word(ring + 12, dev_word(0u, 0u));
    c = fresh();
    r = dwc3_events_consume(ring, 16u, 12u, 12u, SIZE_MAX, capture_event, &c);
    CHECK(r.status == DWC3_EVENTS_OK && r.consumed_bytes == 12u);
    CHECK(r.next_cursor == 8u && c.accepted == 3u);
    CHECK(c.events[0].type == 0u && c.events[1].type == 1u &&
          c.events[2].type == 2u);
    c = fresh();
    r = dwc3_events_consume(ring, 16u, 8u, 16u, SIZE_MAX, capture_event, &c);
    CHECK(r.next_cursor == 8u && c.accepted == 4u && r.consumed_bytes == 16u);
    CHECK(c.events[0].type == 3u && c.events[3].type == 2u);
    c = fresh();
    r = dwc3_events_consume(ring, 12u, 8u, 12u, SIZE_MAX, capture_event, &c);
    CHECK(r.status == DWC3_EVENTS_OK && r.next_cursor == 8u);
    CHECK(c.accepted == 3u && c.events[1].type == 1u);
    c = fresh();
    r = dwc3_events_consume(ring, 4u, 0u, 4u, SIZE_MAX, capture_event, &c);
    CHECK(r.status == DWC3_EVENTS_OK && r.next_cursor == 0u && c.accepted == 1u);

    put_word(ring, dev_word(11u, 0u));
    put_word(ring + 4, dev_word(8u, 0u));
    put_word(ring + 8, ep_word(31u, 7u, 15u, 0xabcdu));
    put_word(ring + 12, 7u); /* Unsupported Carkit category, not device type 0. */
    c = fresh();
    r = dwc3_events_consume(ring, 16u, 0u, 16u, SIZE_MAX, capture_event, &c);
    CHECK(r.consumed_bytes == 16u && r.unknown_events == 2u);
    CHECK(r.overflow_events == 1u && c.events[0].known);
    CHECK(c.events[0].diagnostics == DWC3_EVENTS_DIAG_OVERFLOW);
    CHECK(c.events[2].endpoint_physical == 31u && c.events[2].parameters == 0xabcdu);
    CHECK(c.events[3].family == DWC3_EVENTS_OTHER);
    c = fresh();
    r = dwc3_events_consume(ring, 16u, 0u, 4u, SIZE_MAX, capture_event, &c);
    CHECK(c.accepted == 1u && r.consumed_bytes == 4u && r.next_cursor == 4u);
}
static void test_pause_budget(void)
{
    uint8_t ring[16] = {0};
    struct capture c = fresh();
    struct dwc3_events_result r;
    struct mock_owner owner = {0};
    size_t i;
    for (i = 0; i < 4u; ++i) { put_word(ring + i * 4u, dev_word((unsigned)i, 0u)); }
    r = dwc3_events_consume(ring, 16u, 0u, 16u, 0u, capture_event, &c);
    CHECK(r.status == DWC3_EVENTS_BUDGET && r.consumed_bytes == 0u && c.calls == 0u);
    r = dwc3_events_consume(ring, 16u, 0u, 16u, 2u, capture_event, &c);
    CHECK(r.status == DWC3_EVENTS_BUDGET && r.consumed_bytes == 8u);
    CHECK(r.next_cursor == 8u && c.calls == 2u && r.delivered_events == 2u);
    mock_commit(&owner, r);
    CHECK(owner.cursor == 8u && owner.ack_bytes == 8u && owner.writes == 1u);
    c = fresh();
    r = dwc3_events_consume(ring, 16u, owner.cursor, 8u, 2u, capture_event, &c);
    CHECK(r.status == DWC3_EVENTS_OK && c.events[0].type == 2u);
    mock_commit(&owner, r);
    CHECK(owner.cursor == 0u && owner.ack_bytes == 16u && owner.writes == 2u);
    c = fresh(); c.pause_at = 0u;
    r = dwc3_events_consume(ring, 16u, 0u, 16u, SIZE_MAX, capture_event, &c);
    CHECK(r.status == DWC3_EVENTS_PAUSED && r.consumed_bytes == 0u);
    CHECK(r.next_cursor == 0u && c.calls == 1u && c.accepted == 0u);
    c = fresh(); c.pause_at = 2u;
    r = dwc3_events_consume(ring, 16u, 0u, 16u, SIZE_MAX, capture_event, &c);
    CHECK(r.status == DWC3_EVENTS_PAUSED && r.consumed_bytes == 8u);
    CHECK(r.next_cursor == 8u && c.calls == 3u && c.accepted == 2u);
    c = fresh();
    r = dwc3_events_consume(ring, 16u, r.next_cursor, 8u, SIZE_MAX, capture_event, &c);
    CHECK(r.status == DWC3_EVENTS_OK && c.events[0].type == 2u);
    CHECK(r.consumed_bytes == 8u && r.next_cursor == 0u);
    c = fresh();
    r = dwc3_events_consume(ring, 16u, 0u, 0u, 0u, capture_event, &c);
    CHECK(r.status == DWC3_EVENTS_OK && c.calls == 0u);
}
static void invalid_case(const uint8_t *ring, size_t size, size_t cursor,
                         uint32_t count, dwc3_events_callback callback,
                         enum dwc3_events_status expected)
{
    struct capture c = fresh();
    struct mock_owner owner = {cursor, 123u, 0u};
    struct dwc3_events_result r = dwc3_events_consume(
        ring, size, cursor, count, SIZE_MAX, callback, &c);
    CHECK(r.status == expected);
    CHECK(r.consumed_bytes == 0u && r.next_cursor == cursor && c.calls == 0u);
    CHECK(r.delivered_events == 0u && r.unknown_events == 0u && r.overflow_events == 0u);
    CHECK(r.stop_raw == 0u);
    mock_commit(&owner, r);
    CHECK(owner.cursor == cursor && owner.ack_bytes == 123u && owner.writes == 0u);
}
static void test_invalid(void)
{
    uint8_t ring[16] = {0};
    uint8_t before[16];
    uint32_t count;
    memcpy(before, ring, sizeof(ring));
    invalid_case(NULL, 16u, 0u, 4u, capture_event, DWC3_EVENTS_INVALID_RING);
    invalid_case(ring, 0u, 0u, 0u, capture_event, DWC3_EVENTS_INVALID_RING);
    invalid_case(ring, 14u, 0u, 4u, capture_event, DWC3_EVENTS_INVALID_RING);
    invalid_case(ring, 16u, 1u, 4u, capture_event, DWC3_EVENTS_INVALID_CURSOR);
    invalid_case(ring, 16u, 16u, 0u, capture_event, DWC3_EVENTS_INVALID_CURSOR);
    invalid_case(ring, 16u, SIZE_MAX, 4u, capture_event, DWC3_EVENTS_INVALID_CURSOR);
    for (count = 1u; count <= 7u; ++count) {
        if (count != 4u) {
            invalid_case(ring, 16u, 0u, count, capture_event, DWC3_EVENTS_INVALID_COUNT);
        }
    }
    invalid_case(ring, 16u, 0u, 20u, capture_event, DWC3_EVENTS_INVALID_COUNT);
    invalid_case(ring, 16u, 0u, 65532u, capture_event, DWC3_EVENTS_INVALID_COUNT);
    invalid_case(ring, 16u, 0u, 65536u, capture_event, DWC3_EVENTS_INVALID_COUNT);
    invalid_case(ring, 16u, 0u, UINT32_MAX, capture_event, DWC3_EVENTS_INVALID_COUNT);
    invalid_case(ring, 16u, 0u, UINT32_C(0x80000004), capture_event,
                 DWC3_EVENTS_INVALID_COUNT);
    invalid_case(ring, 16u, 0u, 4u, NULL, DWC3_EVENTS_INVALID_CALLBACK);
    /* SIZE_MAX-sized fictitious ring must not be touched on invalid count. */
    invalid_case(ring, SIZE_MAX - (SIZE_MAX % 4u), 0u, 65536u, capture_event,
                 DWC3_EVENTS_INVALID_COUNT);
    CHECK(memcmp(before, ring, sizeof(ring)) == 0);
}
static void test_lmp_and_maximum(void)
{
    uint8_t ring[16] = {0};
    static uint8_t large[65532];
    struct capture c = fresh();
    struct dwc3_events_result r;
    put_word(ring, dev_word(12u, 0u));
    put_word(ring + 4, dev_word(1u, 0u)); /* Payload must not be interpreted. */
    r = dwc3_events_consume(ring, 16u, 0u, 12u, SIZE_MAX, capture_event, &c);
    CHECK(r.status == DWC3_EVENTS_UNSUPPORTED_RECORD && r.stop_raw == 0xc01u);
    CHECK(r.consumed_bytes == 0u && r.next_cursor == 0u && c.calls == 0u);
    put_word(ring + 12, dev_word(0u, 0u));
    r = dwc3_events_consume(ring, 16u, 12u, 16u, SIZE_MAX, capture_event, &c);
    CHECK(r.status == DWC3_EVENTS_UNSUPPORTED_RECORD && r.consumed_bytes == 4u);
    CHECK(r.next_cursor == 0u && c.calls == 1u && c.events[0].type == 0u);
    c = fresh();
    r = dwc3_events_consume(large, sizeof(large), 65528u, 65532u,
                           SIZE_MAX, capture_event, &c);
    CHECK(r.status == DWC3_EVENTS_OK && r.consumed_bytes == 65532u);
    CHECK(r.next_cursor == 65528u && c.accepted == 16383u);
    CHECK(r.unknown_events == 16383u && r.delivered_events == 16383u);
}
static void test_wrap_matrix(void)
{
    uint8_t ring[68];
    uint8_t before[68];
    size_t size, cursor, pending, budget, i;
    for (i = 0; i < 17u; ++i) { put_word(ring + i * 4u, ep_word((unsigned)i, 1u, 0u, 0u)); }
    memcpy(before, ring, sizeof(ring));
    for (size = 4u; size <= sizeof(ring); size += 4u) {
        for (cursor = 0u; cursor < size; cursor += 4u) {
            for (pending = 0u; pending <= size; pending += 4u) {
                for (budget = 0u; budget <= size / 4u + 1u; ++budget) {
                    struct capture c = fresh();
                    size_t n = pending / 4u < budget ? pending / 4u : budget;
                    struct dwc3_events_result r = dwc3_events_consume(
                        ring, size, cursor, (uint32_t)pending, budget, capture_event, &c);
                    CHECK(r.consumed_bytes == n * 4u && r.delivered_events == n);
                    CHECK(r.next_cursor == (cursor + n * 4u) % size);
                    CHECK(c.accepted == n && c.calls == n);
                    CHECK(r.status == (n * 4u == pending ? DWC3_EVENTS_OK : DWC3_EVENTS_BUDGET));
                    for (i = 0u; i < n; ++i) {
                        CHECK(c.events[i].endpoint_physical == (cursor / 4u + i) % (size / 4u));
                    }
                }
            }
        }
    }
    CHECK(memcmp(before, ring, sizeof(ring)) == 0);
}
int main(void)
{
    test_decode();
    test_count();
    test_ring_basics();
    test_pause_budget();
    test_invalid();
    test_lmp_and_maximum();
    test_wrap_matrix();
    printf("PASS: 7 C test groups, %lu assertions; offline model acceptance only\n", checks);
    return 0;
}
'''


def run(command):
    result = subprocess.run(command, text=True, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, check=False)
    print("$", " ".join(str(x) for x in command))
    if result.stdout:
        print(result.stdout, end="")
    if result.stderr:
        print(result.stderr, file=sys.stderr, end="")
    print(f"[exit code: {result.returncode}]")
    if result.returncode:
        raise RuntimeError(f"command failed with status {result.returncode}")
    return result.stdout


def oracle(core):
    text = core.read_text(encoding="utf-8")
    clean = re.sub(r"/\*.*?\*/|//[^\n]*", "", text, flags=re.S)
    assertions = []
    for name, (candidate, expected) in ORACLE.items():
        matches = re.findall(r"^\s*#\s*define\s+" + re.escape(name) +
                             r"\s+([^\n]+)$", clean, flags=re.M)
        if len(matches) != 1 or not re.fullmatch(r"(?:0[xX][0-9a-fA-F]+|[0-9]+)", matches[0].strip()):
            raise ValueError(f"missing/ambiguous/nonliteral vendor define: {name}")
        actual = int(matches[0].strip(), 0)
        if actual != expected:
            raise ValueError(f"vendor oracle mismatch: {name}={actual:#x}, expected {expected:#x}")
        assertions.append(f'_Static_assert({candidate} == {actual}u, "{name}");')
    for name, expected in LAYOUTS.items():
        match = re.search(r"struct\s+" + name + r"\s*\{(.*?)\}", clean, flags=re.S)
        if not match:
            raise ValueError(f"missing vendor layout: {name}")
        actual = [(n, int(w)) for n, w in re.findall(r"\bu32\s+(\w+)\s*:\s*(\d+)\s*;", match[1])]
        if actual != expected:
            raise ValueError(f"vendor field layout mismatch: {name}: {actual}")
    return "\n".join(assertions) + "\n"


def resolve_compiler(value, name):
    found = shutil.which(value)
    if found is None:
        raise ValueError(f"{name} compiler not found: {value}; supply --{name}")
    return str(Path(found).resolve())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", type=Path, required=True,
                        help="isolated candidate root, not the production repository")
    parser.add_argument("--vendor-core", type=Path,
                        help="vendor DWC3 core.h; default: candidate/vendor/core.h")
    parser.add_argument("--clang", default="clang")
    parser.add_argument("--gcc", default="gcc")
    parser.add_argument("--gcc-compile-only", action="store_true",
                        help="explicitly report cross-GCC compilation without execution")
    parser.add_argument("--sanitize", action="store_true",
                        help="also run native Clang ASan/UBSan acceptance executable")
    args = parser.parse_args()
    root = args.repo_root.resolve(strict=True)
    source = root / "src/dwc3_events.c"
    header = root / "src/dwc3_events.h"
    for path in (source, header):
        if not path.is_file() or not path.resolve().is_relative_to(root):
            raise ValueError(f"candidate source missing or escaped candidate: {path}")
    vendor = (args.vendor_core or root / "vendor/core.h").resolve(strict=True)
    assertions = oracle(vendor)  # Fail before any compiler/build directory on mismatch.
    clang = resolve_compiler(args.clang, "clang")
    gcc = resolve_compiler(args.gcc, "gcc")
    cv = run([clang, "--version"])
    gv = run([gcc, "--version"])
    if "clang" not in cv.lower():
        raise ValueError("--clang is not Clang")
    if "clang" in gv.lower() or "gcc" not in gv.lower():
        raise ValueError("--gcc must be real GNU GCC, not Apple's gcc-named Clang")
    build = Path(tempfile.mkdtemp(prefix="test-run-", dir=root))
    harness = build / "acceptance.c"
    harness.write_text('#include "dwc3_events.h"\n' + assertions + HARNESS,
                       encoding="utf-8")
    flags = ["-std=c11", "-O0", "-Wall", "-Wextra", "-Werror", "-pedantic",
             "-I", str(header.parent)]
    compile_count = 0
    execution_outputs = []
    for name, compiler, compile_only in (("clang", clang, False),
                                          ("gcc", gcc, args.gcc_compile_only)):
        if compile_only:
            for file in (source, harness):
                run([compiler, *flags, "-c", str(file), "-o", str(build / f"{name}-{file.stem}.o")])
                compile_count += 1
        else:
            executable = build / f"acceptance-{name}"
            run([compiler, *flags, str(source), str(harness), "-o", str(executable)])
            compile_count += 1
            execution_outputs.append(run([str(executable)]).strip())
    if args.sanitize:
        executable = build / "acceptance-clang-sanitized"
        run([clang, *flags, "-fsanitize=address,undefined", "-fno-omit-frame-pointer",
             str(source), str(harness), "-o", str(executable)])
        compile_count += 1
        execution_outputs.append(run([str(executable)]).strip())
    report = {
        "scope": "OFFLINE UNIT ACCEPTANCE ONLY; NOT USB CONNECTION OR DEVICE CAPABILITY",
        "vendor_core": str(vendor),
        "vendor_sha256": hashlib.sha256(vendor.read_bytes()).hexdigest(),
        "oracle_defines": len(ORACLE), "oracle_struct_layouts": len(LAYOUTS),
        "strict_compile_commands": compile_count,
        "native_executions": len(execution_outputs),
        "gcc_execution": "NOT RUN (explicit cross-compile-only)" if args.gcc_compile_only else "PASS",
        "test_outputs": execution_outputs,
        "artifacts": str(build),
        "files_sha256": {str(p.relative_to(root)): hashlib.sha256(p.read_bytes()).hexdigest()
                          for p in (source, header, Path(__file__).resolve())},
    }
    (build / "report.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, RuntimeError) as error:
        print(f"FAIL: {error}", file=sys.stderr)
        sys.exit(1)
