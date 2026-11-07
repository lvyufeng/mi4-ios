#!/usr/bin/env python3
"""Host-only tests for inspect_user_image_fault.py; no devices/builds required.

    PYTHONDONTWRITEBYTECODE=1 python3 tools/test_inspect_user_image_fault.py
    # Optional actual-image regression, without making the suite depend on /tmp:
    MI4_AUDIT_DYLD=/path/to/dyld MI4_AUDIT_LAUNCHD=/path/to/launchd \
        PYTHONDONTWRITEBYTECODE=1 python3 tools/test_inspect_user_image_fault.py

Every malformed-input test mutates only an in-memory synthetic Mach-O.
CLI tests use a new TemporaryDirectory, never an existing repository file.
"""

import contextlib
import io
import json
import os
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import patch

import inspect_user_image_fault as audit


BASE = 0x10000000
SLIDE = 0x1B000
TEXT_FILE_SIZE = 0x2000
DATA_FILE_OFFSET = 0x2000
LINKEDIT_FILE_OFFSET = 0x3000
FUNCTION_FILE_OFFSET = 0x3000
SYMBOL_FILE_OFFSET = 0x3100
STRING_FILE_OFFSET = 0x3200


def uleb(value):
    result = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        result.append(byte | (0x80 if value else 0))
        if not value:
            return bytes(result)


def section(name, segment, addr, size, offset, flags, align=2):
    return struct.pack("<16s16s9I", name.encode(), segment.encode(), addr, size,
                       offset, align, 0, 0, flags, 0, 0)


def segment(name, vmaddr, vmsize, fileoff, filesize, protection, sections=(), flags=0):
    return struct.pack("<II16s8I", audit.LC_SEGMENT, 56 + 68 * len(sections),
                       name.encode(), vmaddr, vmsize, fileoff, filesize,
                       protection, protection, len(sections), flags) + b"".join(sections)


def thread(pc=BASE + 0x1000, cpsr=0, flavor=1, words=17):
    state = [0] * words
    if words >= 17:
        state[15], state[16] = pc, cpsr
    return struct.pack("<4I", audit.LC_UNIXTHREAD, 16 + words * 4, flavor, words) + \
        struct.pack("<" + "I" * words, *state)


def dylinker():
    path = b"/usr/lib/dyld\0"
    size = (12 + len(path) + 3) & ~3
    return struct.pack("<III", audit.LC_LOAD_DYLINKER, size, 12) + path + \
        bytes(size - 12 - len(path))


def fixture(*, main=False, dynamic=False, pagezero=False, symbols=True, starts=True,
            function_bytes=None, filetype=None, base=BASE, entry_pc=None, entry_cpsr=0,
            thumb_desc=8, extra_commands=(), data_tail_bss=False):
    """Deliberately nonlinear __LINKEDIT VM/file layout and tagged mode transitions."""
    commands = []
    if pagezero:
        commands.append(segment("__PAGEZERO", 0, 0x1000, 0, 0, 0))
    commands.append(segment("__TEXT", base, TEXT_FILE_SIZE, 0, TEXT_FILE_SIZE, 5, (
        section("__text", "__TEXT", base + 0x1000, 0x800, 0x1000, 0x80000400),
        section("__cstring", "__TEXT", base + 0x1800, 0x800, 0x1800, 2, 0),
    )))
    data_sections = [section("__all_image_info", "__DATA", base + 0x2000,
                             0xA4, 0x2000, 0)]
    if data_tail_bss:
        data_sections.append(section("__bss_tail", "__DATA", base + 0x20A4,
                                     0x100, 0, 1))
    data_sections.append(section("__bss", "__DATA", base + 0x3000, 0x1000, 0, 1))
    commands.append(segment("__DATA", base + 0x2000, 0x2000, 0x2000, 0x1000, 3,
                            data_sections))
    commands.append(segment("__LINKEDIT", base + 0x6000, 0x1000, 0x3000, 0x1000, 1))
    if main:
        commands.append(struct.pack("<IIQQ", audit.LC_MAIN, 24, 0x1101, 0))
    else:
        commands.append(thread(base + 0x1000 if entry_pc is None else entry_pc, entry_cpsr))
    if dynamic:
        commands.append(dylinker())
    # ARM0x1000 -> Thumb0x1101 -> Thumb0x1141 -> ARM0x1180 -> Thumb0x11c1.
    # Masking each DELTA loses mode-change bytes. Treating tagged offsets as
    # physical offsets instead produces odd Thumb starts.
    tagged_starts = [0x1000, 0x1101, 0x1141, 0x1180, 0x11C1]
    if function_bytes is None:
        previous = 0
        parts = []
        for tagged in tagged_starts:
            parts.append(uleb(tagged - previous))
            previous = tagged
        function_bytes = b"".join(parts) + b"\0"
    strings = bytearray(b"\0")
    nlists = []
    for offset, name, mode in [(0x1000, "_dyld_start", 0),
                               (0x1100, "_thumb_caller", thumb_desc),
                               (0x1140, "_thumb_next", 8),
                               (0x1180, "_mach_absolute_time", 0),
                               (0x11C0, "_thumb_after", 8)]:
        strx = len(strings)
        strings += name.encode() + b"\0"
        nlists.append(struct.pack("<IBBHI", strx, 0x0F, 1, mode, base + offset))
    if symbols:
        commands.append(struct.pack("<6I", audit.LC_SYMTAB, 24, SYMBOL_FILE_OFFSET,
                                    len(nlists), STRING_FILE_OFFSET, len(strings)))
    if starts:
        commands.append(struct.pack("<4I", audit.LC_FUNCTION_STARTS, 16,
                                    FUNCTION_FILE_OFFSET, len(function_bytes)))
    commands += list(extra_commands)
    image = bytearray(0x4000)
    chosen_type = filetype if filetype is not None else \
        (audit.MH_EXECUTE if main or dynamic or pagezero else audit.MH_DYLINKER)
    header = struct.pack("<7I", audit.MH_MAGIC, 12, 9, chosen_type,
                         len(commands), sum(len(command) for command in commands), 0x85)
    image[:28] = header
    image[28:28 + sum(map(len, commands))] = b"".join(commands)
    struct.pack_into("<III", image, 0x1180, 0xE304C088, 0xE34FCFFF, 0xE5DC0008)
    image[0x1800:0x1804] = b"str\0"
    image[FUNCTION_FILE_OFFSET:FUNCTION_FILE_OFFSET + len(function_bytes)] = function_bytes
    image[SYMBOL_FILE_OFFSET:SYMBOL_FILE_OFFSET + len(nlists) * 12] = b"".join(nlists)
    image[STRING_FILE_OFFSET:STRING_FILE_OFFSET + len(strings)] = strings
    return image


def command_offsets(blob, command):
    offset = 28
    for _ in range(struct.unpack_from("<I", blob, 16)[0]):
        kind, size = struct.unpack_from("<II", blob, offset)
        if kind == command:
            yield offset
        offset += size


def set_u32(blob, offset, value):
    struct.pack_into("<I", blob, offset, value)
    return blob


class AttributionTests(unittest.TestCase):
    def setUp(self):
        self.image = audit.MachO(fixture())

    def test_two_independent_anchors_agree(self):
        slide, anchors = audit.derive_slide(self.image, entry=BASE + SLIDE + 0x1000,
                                           all_image_info=BASE + SLIDE + 0x2000)
        self.assertEqual(slide, SLIDE)
        self.assertEqual([a["source"] for a in anchors], ["LC_UNIXTHREAD", "__all_image_info"])

    def test_inconsistent_anchors_refused(self):
        with self.assertRaisesRegex(audit.AuditError, "inconsistent mapping anchors"):
            audit.derive_slide(self.image, entry=BASE + SLIDE + 0x1000,
                               all_image_info=BASE + SLIDE + 0x3000)

    def test_third_base_anchor_must_agree(self):
        with self.assertRaisesRegex(audit.AuditError, "inconsistent mapping anchors"):
            audit.derive_slide(self.image, entry=BASE + SLIDE + 0x1000,
                               all_image_info=BASE + SLIDE + 0x2000,
                               base=BASE + SLIDE + 0x1000)

    def test_main_is_metadata_not_initial_kernel_anchor(self):
        image = audit.MachO(fixture(main=True, dynamic=True))
        self.assertEqual(image.main["entryoff"], 0x1101)
        self.assertEqual(image.main["physical_file_offset"], 0x1100)
        self.assertEqual(image.main["preferred_address"], BASE + 0x1100)
        self.assertEqual(image.main["mode"], "Thumb")
        with self.assertRaisesRegex(audit.AuditError, "LC_MAIN cannot anchor"):
            audit.derive_slide(image, entry=BASE + SLIDE + 0x1000)
        self.assertEqual(audit.derive_slide(image, base=BASE + SLIDE)[0], SLIDE)

    def test_dynamic_unixthread_not_initial_kernel_anchor(self):
        image = audit.MachO(fixture(dynamic=True))
        with self.assertRaisesRegex(audit.AuditError, "executable requests dyld"):
            audit.derive_slide(image, entry=BASE + SLIDE + 0x1000)

    def test_static_unixthread_is_allowed(self):
        image = audit.MachO(fixture(filetype=audit.MH_EXECUTE))
        self.assertEqual(audit.derive_slide(image, entry=BASE + SLIDE + 0x1000)[0], SLIDE)

    def test_allinfo_anchor_restricted_to_dyld(self):
        image = audit.MachO(fixture(main=True))
        with self.assertRaisesRegex(audit.AuditError, "all-image-info anchor requires dyld"):
            audit.derive_slide(image, all_image_info=BASE + SLIDE + 0x2000)

    def test_no_anchor_and_unaligned_slide_are_refused(self):
        with self.assertRaisesRegex(audit.AuditError, "no mapping anchor"):
            audit.derive_slide(self.image)
        with self.assertRaisesRegex(audit.AuditError, "not page-aligned"):
            audit.derive_slide(self.image, base=BASE + 4)

    def test_negative_slide_is_valid_if_ranges_fit(self):
        self.assertEqual(audit.derive_slide(self.image, base=BASE - 0x1000)[0], -0x1000)

    def test_slide_overflow_is_refused(self):
        with self.assertRaisesRegex(audit.AuditError, "runtime segment"):
            audit.derive_slide(self.image, base=0xFFFFF000)

    def test_pc_function_mode_and_word(self):
        row = audit.attribute(self.image, SLIDE, BASE + SLIDE + 0x1188, code=True, mode="ARM")
        self.assertEqual(row["file_offset"], 0x1188)
        self.assertEqual(row["function"]["names"], ["_mach_absolute_time"])
        self.assertEqual(row["function"]["offset"], 8)
        self.assertEqual(row["function"]["mode"], "ARM")
        self.assertEqual(row["file_word_le"], 0xE5DC0008)

    def test_thumb_lr_tag_removed_without_odd_byte_offset(self):
        row = audit.attribute(self.image, SLIDE, BASE + SLIDE + 0x111F, code=True, mode="Thumb")
        self.assertEqual(row["normalized_address"], BASE + SLIDE + 0x111E)
        self.assertEqual(row["file_offset"], 0x111E)
        self.assertEqual(row["function"]["start"], BASE + 0x1100)
        self.assertEqual(row["function"]["mode"], "Thumb")

    def test_explicit_arm_pc_low_bit_not_silently_removed(self):
        value = BASE + SLIDE + 0x1189
        row = audit.attribute(self.image, SLIDE, value, code=True, mode="ARM")
        self.assertEqual(row["normalized_address"], value)
        self.assertEqual(row["file_offset"], 0x1189)
        self.assertIn("misaligned", row["mode_warning"])

    def test_odd_data_pointer_is_not_a_thumb_tag(self):
        row = audit.attribute(self.image, SLIDE, BASE + SLIDE + 0x2001)
        self.assertEqual(row["file_offset"], 0x2001)

    def test_zerofill_no_fileoffset(self):
        row = audit.attribute(self.image, SLIDE, BASE + SLIDE + 0x3001)
        self.assertEqual(row["section"], "__DATA,__bss")
        self.assertIsNone(row["file_offset"])
        self.assertEqual(row["backing"], "section_zero_fill")
        self.assertNotIn("file_bytes_hex", row)

    def test_section_zerofill_in_file_backed_page_has_no_fileoffset(self):
        image = audit.MachO(fixture(data_tail_bss=True))
        row = audit.attribute(image, SLIDE, BASE + SLIDE + 0x20A4)
        self.assertIsNone(row["file_offset"])
        self.assertEqual(row["section"], "__DATA,__bss_tail")

    def test_non_linear_linkedit_fileoff(self):
        row = audit.attribute(self.image, SLIDE, BASE + SLIDE + 0x6004)
        self.assertEqual(row["file_offset"], 0x3004)  # Not linear base delta 0x6004.
        self.assertEqual(row["segment"], "__LINKEDIT")

    def test_end_boundaries_and_gap(self):
        self.assertEqual(audit.attribute(self.image, SLIDE, BASE + SLIDE + 0x2000)["segment"],
                         "__DATA")
        self.assertEqual(audit.attribute(self.image, SLIDE, BASE + SLIDE + 0x4000)["backing"],
                         "outside_supplied_image")

    def test_cstring_not_attributed_as_nearest_function(self):
        row = audit.attribute(self.image, SLIDE, BASE + SLIDE + 0x1800, code=True)
        self.assertEqual(row["section"], "__TEXT,__cstring")
        self.assertIsNone(row["function"])

    def test_pagezero_extended_not_slid_and_not_file_backed(self):
        image = audit.MachO(fixture(pagezero=True, base=0x1000))
        slide, anchors = audit.derive_slide(image, base=0x21000)
        self.assertEqual(slide, 0x20000)
        row = audit.attribute(image, slide, 0x1000)
        self.assertEqual(row["segment"], "__PAGEZERO")
        self.assertEqual(row["backing"], "inaccessible")
        self.assertIsNone(row["file_offset"])
        self.assertEqual(audit.report(image, slide, anchors, {})["segments"][0]["runtime_start"], "0x0")

    def test_single_anchor_report_is_not_cross_checked(self):
        slide, anchors = audit.derive_slide(self.image, base=BASE + SLIDE)
        self.assertFalse(audit.report(self.image, slide, anchors, {})["anchors_cross_checked"])

    def test_mode_disagreement_is_explicit(self):
        row = audit.attribute(self.image, SLIDE, BASE + SLIDE + 0x1188, code=True, mode="Thumb")
        self.assertIn("mode_warning", row)

    def test_tagged_thread_entry_mode_handled(self):
        image = audit.MachO(fixture(entry_pc=BASE + 0x1101))
        self.assertEqual(image.unixthread["mode"], "Thumb")
        self.assertEqual(audit.derive_slide(image, entry=BASE + SLIDE + 0x1101)[0], SLIDE)
        with self.assertRaisesRegex(audit.AuditError, "runtime entry Thumb tag"):
            audit.derive_slide(self.image, entry=BASE + SLIDE + 0x1001)


class FunctionStartsTests(unittest.TestCase):
    def test_cumulative_tagged_mode_transitions(self):
        image = audit.MachO(fixture())
        self.assertEqual([(f.address - BASE, f.mode) for f in image.function_starts],
                         [(0x1000, "ARM"), (0x1100, "Thumb"), (0x1140, "Thumb"),
                          (0x1180, "ARM"), (0x11C0, "Thumb")])
        self.assertEqual([f.tagged_offset for f in image.function_starts],
                         [0x1000, 0x1101, 0x1141, 0x1180, 0x11C1])

    def test_nlist_mode_disagreement_is_refused(self):
        with self.assertRaisesRegex(audit.AuditError, "mode contradicts nlist"):
            audit.MachO(fixture(thumb_desc=0))

    def test_starts_without_nlist_still_have_modes(self):
        image = audit.MachO(fixture(symbols=False))
        row = image.function_at(BASE + 0x1188)
        self.assertEqual(row["mode"], "ARM")
        self.assertEqual(row["names"], [])

    def test_nlist_fallback_does_not_claim_function_extent(self):
        image = audit.MachO(fixture(starts=False))
        self.assertIn("extent_not_proven", image.function_at(BASE + 0x1188)["evidence"])

    def test_no_symbols_or_starts_means_no_function_guess(self):
        image = audit.MachO(fixture(starts=False, symbols=False))
        self.assertIsNone(image.function_at(BASE + 0x1188))

    def test_missing_terminator(self):
        with self.assertRaisesRegex(audit.AuditError, "missing zero terminator"):
            audit.MachO(fixture(function_bytes=uleb(0x1000)))

    def test_nonzero_after_terminator(self):
        with self.assertRaisesRegex(audit.AuditError, "nonzero bytes after terminator"):
            audit.MachO(fixture(function_bytes=uleb(0x1000) + b"\0\x01"))

    def test_duplicate_physical_start_despite_positive_delta(self):
        with self.assertRaisesRegex(audit.AuditError, "non-increasing physical"):
            audit.MachO(fixture(function_bytes=uleb(0x1000) + b"\x01\0"))

    def test_start_in_cstring_or_misaligned_arm_is_refused(self):
        cases = [(uleb(0x1800) + b"\0", "executable code"),
                 (uleb(0x1002) + b"\0", "misaligned ARM")]
        for data, message in cases:
            with self.subTest(data=data), self.assertRaisesRegex(audit.AuditError, message):
                audit.MachO(fixture(function_bytes=data))

    def test_truncated_overflow_and_overlong_uleb(self):
        for data in (b"\x80", b"\xff\xff\xff\xff\x10", b"\x80\x00",
                     b"\x80\x80\x80\x80\x80\x01"):
            with self.subTest(data=data), self.assertRaises(audit.AuditError):
                audit.read_uleb128(data, 0, len(data))

    def test_uleb_maximum_and_bad_range(self):
        data = uleb(0xFFFFFFFF)
        self.assertEqual(audit.read_uleb128(data, 0, len(data)), (0xFFFFFFFF, 5))
        with self.assertRaisesRegex(audit.AuditError, "invalid ULEB128 range"):
            audit.read_uleb128(b"\0", 0, 2)


class MalformedMachOTests(unittest.TestCase):
    def rejects(self, blob, message=None):
        with self.assertRaises(audit.AuditError) as raised:
            audit.MachO(blob)
        if message:
            self.assertIn(message, str(raised.exception))

    def test_truncated_header_and_commands(self):
        data = fixture()
        for size in (0, 4, 27, 28, 48, 100, len(data) - 1):
            with self.subTest(size=size):
                self.rejects(data[:size])

    def test_wrong_magic_cpu_and_segment64(self):
        for offset, value in [(0, 0xCAFEBABE), (0, 0xFEEDFACF), (0, 0xCEFAEDFE),
                              (4, 0x0100000C), (28, 0x19)]:
            with self.subTest(offset=offset, value=value):
                self.rejects(set_u32(fixture(), offset, value))

    def test_command_sizes(self):
        for size in (0, 4, 9, 0xFFFFFFFC, 52):
            with self.subTest(size=size):
                self.rejects(set_u32(fixture(), 32, size))

    def test_header_command_count_and_size_extent(self):
        for offset, value in [(16, 0xFFFFFFFF), (20, 0xFFFFFFFF), (20, 8)]:
            self.rejects(set_u32(fixture(), offset, value))
        data = fixture()
        set_u32(data, 20, struct.unpack_from("<I", data, 20)[0] + 4)
        self.rejects(data, "sizeofcmds")

    def test_segment_vm_overflow_file_oob_and_highvm(self):
        for field_offset, value in [(24, 0xFFFFF000), (32, 0xFFFFFFFF),
                                    (36, 0xFFFFFFF0), (52, 1)]:
            with self.subTest(field_offset=field_offset):
                self.rejects(set_u32(fixture(), 28 + field_offset, value))

    def test_segment_overlap_and_duplicate(self):
        data = fixture()
        text, data_offset, _ = list(command_offsets(data, audit.LC_SEGMENT))
        self.rejects(set_u32(data, data_offset + 24, BASE + 0x1000), "overlapping")
        data = fixture()
        offsets = list(command_offsets(data, audit.LC_SEGMENT))
        data[offsets[1] + 8:offsets[1] + 24] = b"__TEXT" + bytes(10)
        self.rejects(data, "duplicate")

    def test_invalid_protection_and_filesize_gt_vmsize(self):
        self.rejects(set_u32(fixture(), 28 + 44, 7), "protections")
        self.rejects(set_u32(fixture(), 28 + 28, 0x1000), "filesize exceeds")

    def test_section_outside_vm_file_or_mismatched_segment(self):
        first_section = 28 + 56
        for offset, value in [(32, BASE + 0x8000), (36, 0xFFFFF000), (40, 0x1004),
                              (44, 32), (48, 0xFFFFFFFF), (52, 0xFFFFFFFF)]:
            with self.subTest(offset=offset):
                self.rejects(set_u32(fixture(), first_section + offset, value))
        data = fixture()
        data[first_section + 16:first_section + 32] = b"__DATA" + bytes(10)
        self.rejects(data, "containing command")

    def test_section_overlap_and_excessive_section_count(self):
        second_section = 28 + 56 + 68
        data = fixture()
        set_u32(data, second_section + 32, BASE + 0x1700)
        set_u32(data, second_section + 40, 0x1700)
        set_u32(data, second_section + 36, 0x900)
        self.rejects(data, "section VM: overlapping")
        self.rejects(set_u32(fixture(), 28 + 48, 1000000), "excessive section")

    def test_thread_state_count_and_flavor_bounded(self):
        for count in (0, 16, 18, 0xFFFFFFFF):
            data = fixture()
            offset = next(command_offsets(data, audit.LC_UNIXTHREAD))
            self.rejects(set_u32(data, offset + 12, count))
        data = fixture()
        offset = next(command_offsets(data, audit.LC_UNIXTHREAD))
        self.rejects(set_u32(data, offset + 8, 99), "no ARM_THREAD_STATE")

    def test_entry_into_data_or_cstring_is_refused(self):
        for pc in (BASE + 0x1800, BASE + 0x2000, BASE + 0x1002):
            with self.subTest(pc=pc):
                self.rejects(fixture(entry_pc=pc))

    def test_duplicate_and_both_entry_commands(self):
        self.rejects(fixture(extra_commands=[thread()]), "duplicate LC_UNIXTHREAD")
        self.rejects(fixture(main=True, extra_commands=[thread()]), "both supply")
        self.rejects(fixture(main=True, extra_commands=[struct.pack("<IIQQ", audit.LC_MAIN,
                                                                   24, 0x1101, 0)]), "duplicate LC_MAIN")

    def test_main_entryoff_outside_file_or_in_cstring(self):
        for value in (0xFFFFFFFFFFFFFFFF, 0x1801):
            data = fixture(main=True)
            offset = next(command_offsets(data, audit.LC_MAIN))
            struct.pack_into("<Q", data, offset + 8, value)
            self.rejects(data, "LC_MAIN")

    def test_nlist_table_oob_strings_and_section(self):
        data = fixture()
        offset = next(command_offsets(data, audit.LC_SYMTAB))
        self.rejects(set_u32(data, offset + 8, 0xFFFFFFFC), "nlist table")
        self.rejects(set_u32(fixture(), SYMBOL_FILE_OFFSET, 0xFFFFFFFF), "string index")
        data = fixture()
        data[SYMBOL_FILE_OFFSET + 5] = 255
        self.rejects(data, "section index")
        data = fixture()
        set_u32(data, SYMBOL_FILE_OFFSET + 8, BASE + 0x3000)
        self.rejects(data, "symbol outside")

    def test_header_symbol_is_data_not_a_function_start(self):
        data = fixture()
        name = b"__mh_execute_header\0"
        data[STRING_FILE_OFFSET + 1:STRING_FILE_OFFSET + 1 + len(name)] = name
        struct.pack_into("<H", data, SYMBOL_FILE_OFFSET + 6, 0x10)
        set_u32(data, SYMBOL_FILE_OFFSET + 8, BASE)
        image = audit.MachO(data)
        header = next(symbol for symbol in image.symbols if symbol.name == "__mh_execute_header")
        self.assertIsNone(header.mode)
        self.assertIsNone(image.function_at(BASE))
        self.rejects(set_u32(data, SYMBOL_FILE_OFFSET + 8, BASE - 4), "symbol outside")

    def test_unterminated_and_excessively_long_symbol_string(self):
        data = fixture()
        data[STRING_FILE_OFFSET:0x4000] = b"x" * (0x4000 - STRING_FILE_OFFSET)
        self.rejects(data, "unterminated string")
        with self.assertRaisesRegex(audit.AuditError, "length limit"):
            audit._cstring(b"a" * 4097 + b"\0", 0, 4098, "test")

    def test_function_table_oob_or_outside_linkedit(self):
        for value in (0xFFFFFFFC, 0x1000):
            data = fixture()
            offset = next(command_offsets(data, audit.LC_FUNCTION_STARTS))
            self.rejects(set_u32(data, offset + 8, value))

    def test_dylinker_string_offset_and_termination(self):
        data = fixture(dynamic=True)
        offset = next(command_offsets(data, audit.LC_LOAD_DYLINKER))
        self.rejects(set_u32(data, offset + 8, 4), "path offset")
        data = fixture(dynamic=True)
        offset = next(command_offsets(data, audit.LC_LOAD_DYLINKER))
        size = struct.unpack_from("<I", data, offset + 4)[0]
        data[offset + 12:offset + size] = b"x" * (size - 12)
        self.rejects(data, "unterminated")

    def test_unknown_command_skipped_only_inside_bounds(self):
        image = audit.MachO(fixture(extra_commands=[struct.pack("<II", 0x12345678, 8)]))
        self.assertEqual(image.commands[-1][0], 0x12345678)

    def test_entry_command_modes_must_match_function_metadata(self):
        data = fixture(main=True)
        offset = next(command_offsets(data, audit.LC_MAIN))
        struct.pack_into("<Q", data, offset + 8, 0x1100)  # ARM tag on known Thumb function.
        self.rejects(data, "mode contradicts")
        self.rejects(fixture(entry_pc=BASE + 0x1000, entry_cpsr=0x20), "mode contradicts")

    def test_header_commands_must_be_file_backed(self):
        data = fixture()
        set_u32(data, 28 + 36, 32)
        self.rejects(data, "does not back")

    def test_page_and_section_alignment_enforced(self):
        data = fixture()
        data_segment = list(command_offsets(data, audit.LC_SEGMENT))[1]
        self.rejects(set_u32(data, data_segment + 24, BASE + 0x2001), "page-aligned")
        first_section = 28 + 56
        data = fixture()
        set_u32(data, first_section + 32, BASE + 0x1002)
        set_u32(data, first_section + 40, 0x1002)
        self.rejects(data, "declared alignment")

    def test_table_segment_and_symbol_name_resource_caps(self):
        with patch.object(audit, "MAX_SEGMENTS", 2):
            self.rejects(fixture(), "excessive segment")
        with patch.object(audit, "MAX_TABLE_ENTRIES", 1):
            self.rejects(fixture(), "invalid state count")
        with patch.object(audit, "MAX_SYMBOL_NAME_BYTES", 1):
            self.rejects(fixture(), "memory budget")

    def test_resource_limit(self):
        with patch.object(audit, "MAX_IMAGE_SIZE", 100):
            self.rejects(fixture(), "byte limit")

    def test_every_cut_within_load_commands_refused_without_structerror(self):
        blob = fixture()
        end = 28 + struct.unpack_from("<I", blob, 20)[0]
        for length in range(end):
            with self.subTest(length=length):
                self.rejects(blob[:length])


class CliTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="mi4-image-unit-")
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "image.bin"
        self.path.write_bytes(fixture())

    def run_cli(self, *args):
        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            code = audit.main(["--image", str(self.path), *args])
        return code, stdout.getvalue(), stderr.getvalue()

    def test_success_json_and_zerofill(self):
        code, out, err = self.run_cli("--entry", hex(BASE + SLIDE + 0x1000),
                                      "--all-image-info", hex(BASE + SLIDE + 0x2000),
                                      "--pc", hex(BASE + SLIDE + 0x1188), "--cpsr", "0x10",
                                      "--lr", hex(BASE + SLIDE + 0x111F),
                                      "--reg", f"r10={BASE + SLIDE + 0x3000:#x}")
        self.assertEqual(code, 0, err)
        data = json.loads(out)
        self.assertEqual(data["slide"], "0x1b000")
        self.assertTrue(data["anchors_cross_checked"])
        self.assertEqual(data["attribution"]["pc"]["file_word_le"], "0xe5dc0008")
        self.assertIsNone(data["attribution"]["r10"]["file_offset"])
        self.assertEqual(err, "")

    def test_inconsistent_anchor_exit_two_and_no_partial_json(self):
        code, out, err = self.run_cli("--entry", hex(BASE + SLIDE + 0x1000),
                                      "--all-image-info", hex(BASE + SLIDE + 0x3000))
        self.assertEqual(code, 2)
        self.assertEqual(out, "")
        self.assertIn("REFUSED: inconsistent", err)

    def test_main_and_duplicate_register_refused(self):
        self.path.write_bytes(fixture(main=True))
        code, _, err = self.run_cli("--entry", hex(BASE + SLIDE + 0x1000))
        self.assertEqual(code, 2)
        self.assertIn("LC_MAIN cannot anchor", err)
        code, _, err = self.run_cli("--base", hex(BASE + SLIDE),
                                    "--reg", "r0=0x1", "--reg", "r0=0x2")
        self.assertEqual(code, 2)
        self.assertIn("duplicate register", err)

    def test_missing_file_clean_refusal(self):
        missing = Path(self.temp.name) / "missing.bin"
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            result = audit.main(["--image", str(missing), "--base", "0x1000"])
        self.assertEqual(result, 2)
        self.assertIn("REFUSED", stderr.getvalue())

    def test_parser_type_errors(self):
        for args in [("--base", "-1"), ("--base", "0x100000000"),
                     ("--base", "nope"), ("--base", "0x1000", "--reg", "r0"),
                     ("--base", "0x1000", "--reg", "bad-name=0")]:
            with self.subTest(args=args), contextlib.redirect_stderr(io.StringIO()), \
                    self.assertRaises(SystemExit) as result:
                audit.main(["--image", str(self.path), *args])
            self.assertEqual(result.exception.code, 2)


@unittest.skipUnless(os.environ.get("MI4_AUDIT_DYLD"), "set MI4_AUDIT_DYLD for actual-image regression")
class ActualDyldTests(unittest.TestCase):
    def test_capture_tuple_exact_offsets_modes_and_word(self):
        image = audit.MachO.from_path(os.environ["MI4_AUDIT_DYLD"])
        self.assertEqual(audit.hashlib.sha256(image.blob).hexdigest(),
                         "408061f0ec0a2d037f9c791f7c2c744bd1c3fd0ce2f6e0b550670e1d46755310")
        slide, _ = audit.derive_slide(image, entry=0x2BE1C028, all_image_info=0x2BE3CC8C)
        self.assertEqual(slide, 0x1B000)
        self.assertEqual(len(image.function_starts), 763)
        pc = audit.attribute(image, slide, 0x2BE362C8, code=True, mode="ARM")
        lr = audit.attribute(image, slide, 0x2BE24A9F, code=True, mode="Thumb")
        self.assertEqual(pc["file_offset"], 0x1B2C8)
        self.assertEqual(pc["file_word_le"], 0xE5DC0008)
        self.assertEqual(pc["function"]["names"], ["_mach_absolute_time"])
        self.assertEqual(pc["function"]["offset"], 8)
        self.assertEqual(lr["file_offset"], 0x9A9E)
        self.assertEqual(lr["function"]["mode"], "Thumb")
        self.assertEqual(lr["function"]["offset"], 0x36)
        self.assertEqual(audit.attribute(image, slide, 0x2BE3CC8C)["file_offset"], 0x21C8C)
        self.assertIsNone(audit.attribute(image, slide, 0x2BE3E6AC)["file_offset"])
        self.assertEqual(audit.attribute(image, slide, 0x2BE24A98)["file_word_le"], 0xF01168FE)
        with self.assertRaisesRegex(audit.AuditError, "inconsistent mapping anchors"):
            audit.derive_slide(image, entry=0x2BE1C028, all_image_info=0x2BE38C8C)


@unittest.skipUnless(os.environ.get("MI4_AUDIT_LAUNCHD"), "set MI4_AUDIT_LAUNCHD for actual-image regression")
class ActualLaunchdTests(unittest.TestCase):
    def test_main_tagged_offset_and_wrong_image_anchor_refusal(self):
        image = audit.MachO.from_path(os.environ["MI4_AUDIT_LAUNCHD"])
        self.assertEqual(image.main["entryoff"], 0x30DD)
        self.assertEqual(image.main["physical_file_offset"], 0x30DC)
        self.assertEqual(image.main["mode"], "Thumb")
        self.assertIsNone(image.unixthread)
        with self.assertRaisesRegex(audit.AuditError, "LC_MAIN cannot anchor"):
            audit.derive_slide(image, entry=0x2BE1C028)
        self.assertEqual(len(image.function_starts), 315)


if __name__ == "__main__":
    unittest.main(verbosity=2)
