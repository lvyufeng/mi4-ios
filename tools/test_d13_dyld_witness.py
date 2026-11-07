#!/usr/bin/env python3
"""Offline regression of the *actual* IOS7WITNESS block in an arm_trap.c snapshot.

Usage: python3 tools/test_d13_dyld_witness.py --source /path/to/arm_trap.c [--cc gcc]

No production/checker imports, device, network, kernel build, or source edits. The
three actual functions (clean, lines, dyld_message), constants and counter are
extracted verbatim; only their two kernel includes are removed. Fake copyin and
copyinstr resolve bounded numerical user addresses, never host pointers. Both
32-bit ARM and widened 64-bit address/size models run under C11 -O0 -Wall -Wextra
-Werror, with no warning waivers. This is not a concurrency/race proof: the actual
volatile counter is non-atomic. Out-of-range r8 arithmetic is observed, not fixed.

The call-site check preprocesses actual sleh_undef with ONLY this witness enabled
(all other switches default OFF). UNDEF_RAISE=1 deliberately allows non-UDF fall-
through and is outside that assertion. This does not replace the linked checker.
Source reads are bounded to 2 MiB and hashed before/after all tests; generated C
and binaries exist only in a temporary directory. Three in-memory corruptions
must be rejected: lost rate cap, lost chunk restoration, direct user printf.
Exit 0: all checks/controls pass; 1: regression; 2: input/compiler/tool error.
"""

import argparse
import hashlib
import os
from pathlib import Path
import re
import shlex
import subprocess
import sys
import tempfile

MAX_SOURCE = 2 * 1024 * 1024
BEGIN = "/* IOS7WITNESS_BEGIN */"
END = "/* IOS7WITNESS_END */"
GUARD = "#if defined(STAGE90_XNU_DYLD_WITNESS) && STAGE90_XNU_DYLD_WITNESS"
FLAGS = ["-std=c11", "-O0", "-Wall", "-Wextra", "-Werror"]


def bounded_read(path):
    with path.open("rb") as stream:
        data = stream.read(MAX_SOURCE + 1)
    if len(data) > MAX_SOURCE:
        raise ValueError("source exceeds 2 MiB limit")
    if b"\0" in data:
        raise ValueError("source contains NUL")
    return data


def mask_c(text):
    """Keep offsets/braces, but hide comments, strings and character literals."""
    rx = r'/\*.*?\*/|//[^\n]*|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\''
    return re.sub(rx, lambda m: re.sub(r"[^\n]", " ", m.group()), text, flags=re.S)


def closing(text, start):
    depth = 0
    for pos in range(start, len(text)):
        if text[pos] == "{":
            depth += 1
        elif text[pos] == "}":
            depth -= 1
            if depth == 0:
                return pos
    raise ValueError("unbalanced C braces")


def extract(source):
    if source.count(BEGIN) != 2 or source.count(END) != 2:
        raise ValueError("expected exactly one owned definition and one owned call block")
    blocks = list(re.finditer(re.escape(BEGIN) + r"(.*?)" + re.escape(END), source, re.S))
    if len(blocks) != 2:
        raise ValueError("malformed owned marker blocks")
    definition, call = (m.group(1).strip() for m in blocks)
    for block in (definition, call):
        if not block.startswith(GUARD + "\n") or not block.endswith("#endif"):
            raise ValueError("owned block is not guarded by the witness-only switch")
    if re.sub(r"\s+", "", call[len(GUARD):-len("#endif")]) != "ios7wit_dyld_message(thread->task,arm_ctx);":
        raise ValueError("unexpected owned call block contents")
    body = definition[len(GUARD):-len("#endif")].strip()
    includes = re.findall(r"^#include[^\n]*", body, re.M)
    if includes != ["#include <kern/misc_protos.h>", "#include <sys/errno.h>"]:
        raise ValueError("unexpected witness includes")
    body = re.sub(r"^#include[^\n]*\n?", "", body, flags=re.M)
    names = re.findall(r"\bstatic\s+(?:unsigned|void)\s+(ios7wit_\w+)\s*\(", mask_c(body))
    if names != ["ios7wit_clean", "ios7wit_lines", "ios7wit_dyld_message"]:
        raise ValueError("actual owned function set changed: " + repr(names))
    masked = mask_c(source)
    match = re.search(r"\bvoid\s+sleh_undef\s*\([^)]*\)\s*\{", masked)
    if not match:
        raise ValueError("actual sleh_undef definition not found")
    start = masked.index("{", match.start())
    stop = closing(masked, start)
    if not start < blocks[1].start() < blocks[1].end() < stop:
        raise ValueError("witness call is not inside actual sleh_undef")
    return body, source[match.start():stop + 1]


def run(command, **kwargs):
    return subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          text=True, timeout=30, **kwargs)


def callsite_check(cc, sleh):
    proc = run(cc + ["-E", "-P", "-x", "c", "-DSTAGE90_XNU_DYLD_WITNESS=1", "-"], input=sleh)
    if proc.returncode:
        raise ValueError("cannot preprocess actual sleh_undef:\n" + proc.stderr)
    code = mask_c(proc.stdout)
    if len(re.findall(r"\bios7wit_dyld_message\s*\(", code)) != 1:
        raise ValueError("expected exactly one active witness call in sleh_undef")
    user = re.search(r"else\s+if\s*\(\s*cpsr\s*==\s*0x10\s*\)\s*\{", code)
    nonfatal = re.search(r"if\s*\(\s*instruction\s*!=\s*0xfedeffe7\s*\)\s*\{", code)
    call = code.index("ios7wit_dyld_message")
    if not user or not nonfatal:
        raise ValueError("actual user/UDF instruction branch structure changed")
    ub = code.index("{", user.start())
    ue = closing(code, ub)
    nb = code.index("{", nonfatal.start())
    ne = closing(code, nb)
    if not ub < nb < ne < call < ue:
        raise ValueError("witness no longer follows the nonfatal guard inside user branch")
    branch = code[nb + 1:ne]
    if not re.search(r"\breturn\s*;\s*$", branch):
        raise ValueError("non-UDF path no longer returns before witness (UNDEF_RAISE must stay OFF)")
    tail = code[call:ue]
    if not re.search(r"exception_type\s*=\s*EXC_BAD_INSTRUCTION\s*;", tail):
        raise ValueError("fatal UDF exception delivery no longer follows witness")
    if not re.search(r"doexception\s*\(\s*exception_type\s*,\s*exception_subcode\s*,\s*0\s*\)", code[ue:]):
        raise ValueError("actual exception delivery removed")
    if "dyld_all_image_info_addr:" not in proc.stdout[:call]:
        raise ValueError("witness no longer follows actual all-image-info dump")
    if re.search(r"\b(?:arm_ctx|state)\s*->\s*(?:pc|r\s*\[[^]]+\])\s*(?:[+\-]?=|\+\+|--)", code):
        raise ValueError("actual sleh_undef modifies saved PC/registers")


PREAMBLE = r'''
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <errno.h>
/* macOS headers may already reserve user_addr_t; isolate the fake ABI name. */
#define user_addr_t audit_user_addr_t
#if TEST_ADDR_BITS == 32
typedef uint32_t user_addr_t;
typedef uint32_t vm_size_t;
#elif TEST_ADDR_BITS == 64
typedef uint64_t user_addr_t;
typedef uint64_t vm_size_t;
#else
#error Unsupported address width
#endif
typedef uint32_t UInt32;
typedef int boolean_t;
#define FALSE 0
#define TRUE 1
struct fake_task { void *bsd_info; uint32_t all_image_info_addr; uint32_t all_image_info_size; };
typedef struct fake_task *task_t;
typedef struct { uint32_t r[13], sp, lr, pc, cpsr; } arm_saved_state_t;
static int copyin(user_addr_t, char *, size_t);
static int copyinstr(user_addr_t, char *, vm_size_t, vm_size_t *);
static int audit_test_printf(const char *, ...) __attribute__((format(printf, 1, 2)));
static int audit_bcmp(const void *a, const void *b, size_t n) { return memcmp(a, b, n); }
#define bcmp audit_bcmp
#define printf audit_test_printf
'''

HARNESS = r'''
#undef printf
#define OUT_CAP 32768U
#define MAP_CAP 20U
#define MAP_BYTES 1024U
#define READ_CAP 64U
#define A 0x10000U
#define M 0x20000U
#define B 0x21000U
#define R 0x30000U
#define CLIENT 0x40000U
#define TARGET 0x41000U
#define SYMBOL 0x42000U
struct user_map { user_addr_t base; size_t size; unsigned char bytes[MAP_BYTES]; };
struct read_event { user_addr_t addr; size_t size; int string; };
static struct user_map maps[MAP_CAP];
static struct read_event reads[READ_CAP];
static size_t nmap, nread, nout, nprintf, nio, checks, cases;
static char output[OUT_CAP];
static unsigned expected_slot;
static user_addr_t bad_in, bad_str;
static int in_error, str_error;
static struct fake_task task;
static arm_saved_state_t state;
static const char poison[] = "COPY_ERROR_DATA_MUST_NOT_PRINT";
static void die(const char *expr, int line)
{
    fprintf(stderr, "FAIL addr_bits=%d case=%zu line=%d: %s\n%s\n", TEST_ADDR_BITS, cases, line, expr, output);
    exit(1);
}
#define CHECK(x) do { ++checks; if (!(x)) die(#x, __LINE__); } while (0)
static void io_event(void)
{
    ++nio;
    CHECK(ios7wit_prints == expected_slot);
    CHECK(ios7wit_prints > 0U && ios7wit_prints <= 2U);
}
static int audit_test_printf(const char *fmt, ...)
{
    int count;
    va_list args;
    io_event();
    ++nprintf;
    CHECK(nout < sizeof(output));
    va_start(args, fmt);
    count = vsnprintf(output + nout, sizeof(output) - nout, fmt, args);
    va_end(args);
    CHECK(count >= 0 && (size_t)count < sizeof(output) - nout);
    nout += (size_t)count;
    return count;
}
static void record_read(user_addr_t addr, size_t size, int string)
{
    io_event();
    CHECK(nread < READ_CAP);
    reads[nread++] = (struct read_event){addr, size, string};
    CHECK(string ? (size == 256U || size == 128U) : (size == 4U || size == 16U));
}
static struct user_map *lookup(user_addr_t addr, size_t size)
{
    size_t i;
    if (addr < 0x1000U || addr >= 0x40000000U) return NULL;
    for (i = 0; i < nmap; ++i) {
        if (addr >= maps[i].base && size <= maps[i].size &&
            (uint64_t)(addr - maps[i].base) <= maps[i].size - size)
            return &maps[i];
    }
    return NULL;
}
static int copyin(user_addr_t addr, char *dst, size_t size)
{
    struct user_map *map;
    record_read(addr, size, 0);
    if (in_error && addr == bad_in) return in_error;
    map = lookup(addr, size);
    if (!map) return EFAULT;
    memcpy(dst, map->bytes + (size_t)(addr - map->base), size);
    return 0;
}
static int copyinstr(user_addr_t addr, char *dst, vm_size_t cap, vm_size_t *copied)
{
    vm_size_t i;
    record_read(addr, (size_t)cap, 1);
    *copied = 0;
    if (str_error && addr == bad_str) {
        /* Error may leave arbitrary/partial bytes. They must never be printed. */
        memset(dst, 'Z', (size_t)cap);
        memcpy(dst, poison, sizeof(poison));
        dst[cap - 1U] = 0;
        return str_error;
    }
    for (i = 0; i < cap; ++i) {
        struct user_map *map = lookup((user_addr_t)(addr + i), 1U);
        if (!map) return EFAULT;
        dst[i] = (char)map->bytes[(size_t)(addr + i - map->base)];
        *copied = i + 1U;
        if (!dst[i]) return 0;
    }
    return ENAMETOOLONG; /* Entire cap filled, with no implied NUL. */
}
static struct user_map *add_map(user_addr_t addr, const void *data, size_t size)
{
    struct user_map *map;
    CHECK(nmap < MAP_CAP && size <= MAP_BYTES && addr >= 0x1000U);
    map = &maps[nmap++];
    map->base = addr;
    map->size = size;
    memcpy(map->bytes, data, size);
    return map;
}
static void add_text(user_addr_t addr, const char *text)
{
    (void)add_map(addr, text, strlen(text) + 1U);
}
static void word(unsigned off, uint32_t value)
{
    CHECK(off + sizeof(value) <= maps[0].size);
    memcpy(maps[0].bytes + off, &value, sizeof(value));
}
static void reset(void)
{
    unsigned i;
    unsigned char info[0x68] = {0};
    ++cases;
    memset(maps, 0, sizeof(maps));
    memset(reads, 0, sizeof(reads));
    memset(output, 0, sizeof(output));
    memset(&task, 0, sizeof(task));
    memset(&state, 0, sizeof(state));
    nmap = nread = nout = nprintf = nio = 0;
    ios7wit_prints = 0;
    expected_slot = 1;
    bad_in = bad_str = 0;
    in_error = str_error = 0;
    task.bsd_info = &task;
    task.all_image_info_addr = A;
    task.all_image_info_size = 0xa4U;
    for (i = 0; i < 13; ++i) state.r[i] = 0x12345000U + i;
    state.r[5] = B;
    state.r[8] = R;
    state.sp = 0x12340000U;
    state.lr = 0x2be00001U;
    state.pc = 0x2be08d04U;
    state.cpsr = 0x10U;
    (void)add_map(A, info, sizeof(info));
    word(0x20U, M);
    word(0x40U, 2U);
    word(0x50U, 0x12000U);
    word(0x64U, 0x2c000000U);
}
static void invoke(task_t t, arm_saved_state_t *s)
{
    struct fake_task before_task = task;
    arm_saved_state_t before_state = state;
    ios7wit_dyld_message(t, s);
    CHECK(memcmp(&task, &before_task, sizeof(task)) == 0);
    CHECK(memcmp(&state, &before_state, sizeof(state)) == 0);
    CHECK(strstr(output, poison) == NULL);
}
static void has(const char *text) { CHECK(strstr(output, text) != NULL); }
static void lacks(const char *text) { CHECK(strstr(output, text) == NULL); }
static size_t count_reads(user_addr_t addr, int string)
{
    size_t i, count = 0;
    for (i = 0; i < nread; ++i)
        if (reads[i].addr == addr && reads[i].string == string) ++count;
    return count;
}
static void payload(const char *tag, const char *want)
{
    const char *line = output;
    char got[1024];
    size_t used = 0, taglen = strlen(tag), lines = 0;
    while (*line) {
        const char *end = strchr(line, '\n');
        size_t len;
        CHECK(end != NULL);
        len = (size_t)(end - line);
        if (len >= taglen && memcmp(line, tag, taglen) == 0) {
            size_t n = len - taglen;
            CHECK(n > 0 && n <= 48U && used + n < sizeof(got));
            memcpy(got + used, line + taglen, n);
            used += n;
            ++lines;
        }
        line = end + 1;
    }
    got[used] = 0;
    CHECK(strcmp(got, want) == 0);
    CHECK(lines == (strlen(want) + 47U) / 48U);
}
static void pattern(char *out, size_t size)
{
    size_t i;
    for (i = 0; i < size; ++i) out[i] = (char)('!' + i % 94U);
    out[size] = 0;
}
static void test_helpers(void)
{
    char text[258], before[258], want[146];
    const unsigned char dirty[] = {1, 31, 32, 126, 127, 255, 9, 10, '%', 0};
    reset();
    memset(text, 'X', sizeof(text));
    memcpy(text, dirty, sizeof(dirty));
    CHECK(ios7wit_clean(text, 256U) == 9U);
    CHECK(strcmp(text, "?? ~????%") == 0);
    CHECK(text[255] == 0 && text[256] == 'X' && text[257] == 'X');
    CHECK(nio == 0);
    memset(text, 'Y', sizeof(text));
    CHECK(ios7wit_clean(text, 256U) == 255U);
    CHECK(text[254] == 'Y' && text[255] == 0 && text[256] == 'Y');
    text[0] = 'Q';
    CHECK(ios7wit_clean(text, 1U) == 0U && text[0] == 0);
    pattern(want, 145U);
    memcpy(text, want, sizeof(want));
    memcpy(before, text, sizeof(text));
    ios7wit_prints = 1U;
    ios7wit_lines("chunk> ", text, 145U);
    CHECK(memcmp(text, before, sizeof(text)) == 0);
    CHECK(nprintf == 4U && nread == 0U);
    payload("chunk> ", want);
    CHECK(text[48] == want[48] && text[96] == want[96] && text[144] == want[144]);
    ios7wit_lines("empty> ", text, 0U);
    CHECK(nprintf == 4U);
}
static void test_guards(void)
{
    unsigned which;
    for (which = 0; which < 6; ++which) {
        task_t t;
        arm_saved_state_t *s;
        reset();
        t = &task;
        s = &state;
        if (which == 0) t = NULL;
        if (which == 1) s = NULL;
        if (which == 2) task.bsd_info = NULL;
        if (which == 3) task.all_image_info_addr = 0;
        if (which == 4) task.all_image_info_size = 0x67U;
        if (which == 5) ios7wit_prints = 2U;
        expected_slot = (unsigned)ios7wit_prints;
        invoke(t, s);
        CHECK(nio == 0U && nread == 0U && nprintf == 0U && nout == 0U);
        CHECK(ios7wit_prints == expected_slot);
    }
}
static void test_messages(void)
{
    char text[301], different[301], truncated[256];
    size_t i, ni = 0, ns = 0;
    pattern(text, 180U);
    reset();
    add_text(M, text);
    add_text(B, text);
    add_text(R, "interior %n stays data");
    word(0x44U, CLIENT); word(0x48U, TARGET); word(0x4cU, SYMBOL);
    add_text(CLIENT, "/client/%n"); add_text(TARGET, "/target"); add_text(SYMBOL, "_symbol");
    invoke(&task, &state);
    CHECK(ios7wit_prints == 1U);
    has("r5 matches errorMessage\n");
    payload("dyld> ", text); payload("dyld5> ", text); payload("dyld8> ", "interior %n stays data");
    has("cacheBase=0x2c000000 slide=0x00012000 errKind=0x00000002");
    has("client=\"/client/%n\""); has("target=\"/target\""); has("symbol=\"_symbol\"");
    for (i = 0; i < nread; ++i) { if (reads[i].string) ++ns; else ++ni; }
    CHECK(ni == 9U && ns == 6U);
    reset();
    memcpy(different, text, 181U); different[179] = 'z';
    add_text(M, text); add_text(B, different);
    invoke(&task, &state); has("r5 DIFFERS from errorMessage\n");
    payload("dyld> ", text); payload("dyld5> ", different);
    reset(); add_text(M, "same"); add_text(B, "same but longer");
    invoke(&task, &state); has("r5 DIFFERS from errorMessage\n");
    reset(); add_text(M, ""); add_text(B, "");
    invoke(&task, &state); has("r5 matches errorMessage\n"); has("dyld> <empty>"); has("dyld5> <empty>");
    reset(); state.r[5] = M; add_text(M, "same pointer");
    invoke(&task, &state); has("r5 matches errorMessage\n"); CHECK(count_reads(M, 1) == 2U);
    reset(); bad_in = A + 0x20U; in_error = EFAULT; add_text(B, "r5 survives");
    invoke(&task, &state); has("copyin="); has("dyld> <no message pointer>");
    has("r5 unreadable, no comparison"); payload("dyld5> ", "r5 survives"); CHECK(count_reads(M, 1) == 0U);
    reset(); word(0x20U, 0); add_text(B, "r5 survives null");
    invoke(&task, &state); has("dyld msg=0x00000000 copyin=0"); has("dyld> <no message pointer>"); CHECK(count_reads(M, 1) == 0U);
    reset(); bad_str = M; str_error = EFAULT; add_text(B, "good r5");
    invoke(&task, &state); has("dyld> <copyinstr failed>"); has("r5 unreadable, no comparison"); payload("dyld5> ", "good r5");
    reset(); bad_str = B; str_error = EFAULT; add_text(M, "good field");
    invoke(&task, &state); has("dyld5> <copyinstr failed>"); has("r5 unreadable, no comparison"); payload("dyld> ", "good field");
    pattern(text, 300U); memcpy(truncated, text, 255U); truncated[255] = 0;
    reset(); add_text(M, text); add_text(B, text); add_text(R, text);
    invoke(&task, &state);
    has("r5 matches errorMessage\n"); has("len=256\n"); has("message interior len=255\n");
    payload("dyld> ", truncated); payload("dyld5> ", truncated); payload("dyld8> ", truncated);
    reset(); add_text(M, "A\001B\177C\377D\nE"); add_text(B, "A?B?C?D?E");
    invoke(&task, &state); has("r5 matches errorMessage\n"); payload("dyld> ", "A?B?C?D?E");
    reset(); bad_str = R; str_error = EFAULT;
    invoke(&task, &state); has("dyld> <copyinstr failed>"); has("dyld5> <copyinstr failed>"); has("stale probe="); lacks("dyld8> ");
}
static void test_paths(void)
{
    unsigned p;
    const unsigned offs[] = {0x44U, 0x48U, 0x4cU};
    const char *const names[] = {"client", "target", "symbol"};
    char expect[160], longpath[201];
    reset(); invoke(&task, &state);
    has("client=\"<null>\""); has("target=\"<null>\""); has("symbol=\"<null>\"");
    for (p = 0; p < 3; ++p) {
        reset(); bad_in = A + offs[p]; in_error = EFAULT;
        invoke(&task, &state);
        (void)snprintf(expect, sizeof(expect), "info %s copyin=%d", names[p], EFAULT); has(expect);
        reset(); word(offs[p], CLIENT); bad_str = CLIENT; str_error = EFAULT;
        invoke(&task, &state);
        (void)snprintf(expect, sizeof(expect), "info %s copyinstr=%d", names[p], EFAULT); has(expect);
        reset(); word(offs[p], CLIENT); pattern(longpath, 200U); add_text(CLIENT, longpath);
        invoke(&task, &state);
        (void)snprintf(expect, sizeof(expect), "info %s copyinstr=%d", names[p], ENAMETOOLONG); has(expect);
        lacks("info client=\"!"); lacks("info target=\"!"); lacks("info symbol=\"!");
        CHECK(count_reads(CLIENT, 1) == 1U);
    }
    for (p = 0; p < 3; ++p) {
        const unsigned fields[] = {0x40U, 0x50U, 0x64U};
        reset(); bad_in = A + fields[p]; in_error = EFAULT;
        invoke(&task, &state); has("info cacheBase/slide/errKind copyin=");
    }
}
static void signature(user_addr_t addr, int valid)
{
    uint32_t words[4] = {0x432b2b00U, 0x434c4e47U, 0x13572468U, 0xabcdef01U};
    if (!valid) words[1] ^= 1U;
    (void)add_map(addr, words, sizeof(words));
}
static void test_r8(void)
{
    unsigned i;
    const uint32_t boundaries[] = {0U, 0x10U, 0x3ffffff0U, 0xffffffffU};
    reset(); signature(R - 0x20U, 1);
    invoke(&task, &state); has("exception object (signature at r8-0x20)");
    CHECK(count_reads(R - 0x20U, 0) == 1U && count_reads(R + 0x30U, 0) == 0U && count_reads(R, 1) == 0U);
    reset(); signature(R - 0x20U, 0); signature(R + 0x30U, 1);
    invoke(&task, &state); has("exception block base (signature at r8+0x30)");
    CHECK(count_reads(R - 0x20U, 0) == 1U && count_reads(R + 0x30U, 0) == 1U && count_reads(R, 1) == 0U);
    reset(); signature(R + 0x30U, 1);
    invoke(&task, &state); has("exception block base (signature at r8+0x30)");
    reset(); signature(R - 0x20U, 0); signature(R + 0x30U, 0); add_text(R, "heap run9 %s %n");
    invoke(&task, &state); has("message interior len=15"); payload("dyld8> ", "heap run9 %s %n");
    for (i = 0; i < sizeof(boundaries) / sizeof(boundaries[0]); ++i) {
        user_addr_t back, fwd;
        reset(); state.r[8] = boundaries[i];
        back = (user_addr_t)((user_addr_t)state.r[8] - IOS7WIT_OBJ_BACK);
        fwd = (user_addr_t)((user_addr_t)state.r[8] + IOS7WIT_BASE_FWD);
        invoke(&task, &state); has("stale probe="); lacks("dyld8> ");
        CHECK(count_reads(back, 0) == 1U && count_reads(fwd, 0) == 1U && count_reads((user_addr_t)state.r[8], 1) == 1U);
    }
}
static void test_limit(void)
{
    size_t oldio, oldread, oldout, oldprintf;
    reset(); add_text(M, "finite"); add_text(B, "finite");
    invoke(&task, &state); CHECK(ios7wit_prints == 1U);
    expected_slot = 2U;
    invoke(&task, &state); CHECK(ios7wit_prints == 2U);
    oldio = nio; oldread = nread; oldout = nout; oldprintf = nprintf;
    invoke(&task, &state);
    CHECK(ios7wit_prints == 2U && nio == oldio && nread == oldread && nout == oldout && nprintf == oldprintf);
}
int main(void)
{
    CHECK(IOS7WIT_MAX_PRINTS == 2U && IOS7WIT_MAX_TEXT == 256U && IOS7WIT_PATH_TEXT == 128U && IOS7WIT_LINE == 48U);
    test_helpers(); test_guards(); test_messages(); test_paths(); test_r8(); test_limit();
    fprintf(stdout, "PASS addr_bits=%d cases=%zu checks=%zu\n", TEST_ADDR_BITS, cases, checks);
    return 0;
}
'''


def build_run(cc, directory, name, body, bits):
    c_path = directory / (name + ".c")
    binary = directory / name
    c_path.write_text(PREAMBLE + "\n" + body + "\n" + HARNESS, encoding="utf-8")
    compiled = run(cc + FLAGS + [f"-DTEST_ADDR_BITS={bits}", str(c_path), "-o", str(binary)])
    if compiled.returncode:
        return "compile", compiled.stdout + compiled.stderr
    executed = run([str(binary)])
    if executed.returncode:
        return "behavior", executed.stdout + executed.stderr
    if not re.fullmatch(rf"PASS addr_bits={bits} cases=\d+ checks=\d+\n", executed.stdout):
        return "behavior", "missing exact harness success summary: " + executed.stdout
    return "pass", executed.stdout.strip()


def mutate_once(body, old, new):
    if body.count(old) != 1:
        raise ValueError("negative-control anchor changed: " + repr(old))
    return body.replace(old, new, 1)


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--source", required=True, type=Path, help="actual arm_trap.c snapshot (read-only)")
    parser.add_argument("--cc", default=os.environ.get("CC", "cc"), help="host C compiler command, optionally with arguments")
    args = parser.parse_args()
    cc = shlex.split(args.cc)
    if not cc:
        parser.error("--cc must name a compiler")
    before = bounded_read(args.source)
    sha = hashlib.sha256(before).hexdigest()
    body, sleh = extract(before.decode("utf-8"))
    callsite_check(cc, sleh)
    line_ranges = [(before[:m.start()].count(b"\n") + 1,
                    before[:m.end()].count(b"\n") + 1) for m in
                   re.finditer(re.escape(BEGIN.encode()) + b".*?" + re.escape(END.encode()), before, re.S)]
    print(f"source={args.source.resolve()} bytes={len(before)} lines={len(before.splitlines())} sha256={sha}")
    print(f"actual owned blocks={line_ranges}; functions=3 (clean, lines, dyld_message); source call-site=PASS (witness-only; UNDEF_RAISE=OFF)")
    print("compiler=" + shlex.join(cc + FLAGS) + "; address/size models=32,64; no warning waivers")
    failures = []
    try:
        with tempfile.TemporaryDirectory(prefix="d13-dyld-witness-test-") as temp:
            directory = Path(temp)
            for bits in (32, 64):
                kind, detail = build_run(cc, directory, f"actual_{bits}", body, bits)
                print(detail)
                if kind != "pass":
                    failures.append(f"actual {bits}-bit {kind} failed")
            if not failures:
                controls = [
                    ("rate-cap", "    if (ios7wit_prints >= IOS7WIT_MAX_PRINTS) return;", "    /* in-memory negative: no rate cap */", "behavior"),
                    ("chunk-restore", "        text[index + count] = tail;", "        (void)tail; /* in-memory negative: lost restoration */", "behavior"),
                    ("direct-user-printf", '    printf("IOS7WITNESS r5 msg=0x%08x copyinstr=%d len=%u\\n", state->r[5], err5, (unsigned)copied5);', "    printf(state->r[5]);", "compile"),
                ]
                for name, old, new, expected in controls:
                    changed = mutate_once(body, old, new)
                    kind, detail = build_run(cc, directory, "negative_" + name, changed, 64)
                    if kind != expected:
                        failures.append(f"negative {name}: expected {expected} rejection, got {kind}: {detail}")
                    else:
                        reason = next((line for line in detail.splitlines() if "FAIL " in line or "error:" in line), detail.splitlines()[0])
                        print(f"PASS negative={name} rejected-by={kind}: {reason}")
    finally:
        after = bounded_read(args.source)
        if after != before:
            raise ValueError(f"source changed while testing: before={sha} after={hashlib.sha256(after).hexdigest()}")
    if failures:
        for failure in failures:
            print("FAIL " + failure, file=sys.stderr)
        return 1
    print(f"PASS source stable sha256={sha}; actual models=2 negative controls=3; production untouched")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, ValueError, subprocess.TimeoutExpired, UnicodeError) as error:
        print("ERROR " + str(error), file=sys.stderr)
        sys.exit(2)
