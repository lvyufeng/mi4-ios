#!/usr/bin/env python3
"""Read-only, bounded ARM32 Mach-O fault attribution; standard library only.

Example (the image must be the dyld actually used by this capture):
    python3 tools/inspect_user_image_fault.py --image /path/to/dyld \
        --entry 0x2be1c028 --all-image-info 0x2be3cc8c \
        --pc 0x2be362c8 --lr 0x2be24a9f --cpsr 0x40000010 \
        --reg r0=0x2be3cc8c --reg r10=0x2be3e6ac

LC_MAIN is dyld's main-function entry, NOT the kernel's initial thread entry.
An executable requesting LC_LOAD_DYLINKER initially runs the separate dyld
image, even if that executable also has LC_UNIXTHREAD. --entry is therefore
accepted only for dyld or a non-dynamic LC_UNIXTHREAD executable. For another
image use --base with an independently verified runtime __TEXT address.

Both supplied dyld anchors MUST give the same slide. A single anchor is
allowed, but the report explicitly records that it is not cross-checked.
Image bytes/metadata are not evidence of missing libraries or lazy binding.
The tool never contacts a device, writes files, or executes a build.
"""

import argparse
from bisect import bisect_right
from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import struct
import sys


MH_MAGIC = 0xFEEDFACE
CPU_TYPE_ARM = 12
MH_EXECUTE = 2
MH_DYLINKER = 7
LC_SEGMENT = 1
LC_SYMTAB = 2
LC_UNIXTHREAD = 5
LC_LOAD_DYLINKER = 0xE
LC_ID_DYLINKER = 0xF
LC_UUID = 0x1B
LC_MAIN = 0x80000028
LC_FUNCTION_STARTS = 0x26
ARM_THREAD_STATE = 1
ARM_THREAD_STATE_COUNT = 17
N_STAB = 0xE0
N_TYPE = 0x0E
N_SECT = 0x0E
N_ARM_THUMB_DEF = 0x0008
INSTRUCTION_ATTRIBUTES = 0x80000400
ZEROFILL_TYPES = {1, 0xC, 0x12}
U32_LIMIT = 1 << 32
PAGE_SIZE = 4096
MAX_IMAGE_SIZE = 64 * 1024 * 1024
MAX_COMMANDS = 4096
MAX_SEGMENTS = 64
MAX_SECTIONS = 255  # nlist's n_sect is one byte.
MAX_TABLE_ENTRIES = 100_000
MAX_STRING_LENGTH = 4096
MAX_SYMBOL_NAME_BYTES = 16 * 1024 * 1024
LINKEDIT_DATA_COMMANDS = {0x1D, 0x1E, 0x26, 0x29, 0x2B, 0x2E,
                          0x80000033, 0x80000034}


class AuditError(ValueError):
    """Invalid or insufficient forensic evidence, not an inferred runtime cause."""


def _range(start, size, limit, label):
    if start < 0 or size < 0 or start > limit or size > limit - start:
        raise AuditError(f"{label}: range {start:#x}+{size:#x} exceeds {limit:#x}")
    return start + size


def _name(raw):
    return raw.split(b"\0", 1)[0].decode("utf-8", errors="replace")


def _cstring(blob, start, end, label):
    if not 0 <= start < end <= len(blob):
        raise AuditError(f"{label}: invalid string range")
    stop = blob.find(b"\0", start, min(end, start + MAX_STRING_LENGTH + 1))
    if stop < 0:
        raise AuditError(f"{label}: unterminated string or exceeds length limit")
    return blob[start:stop].decode("utf-8", errors="replace")


def _disjoint(ranges, label):
    occupied = sorted((lo, hi) for lo, hi in ranges if hi > lo)
    for (_, previous_end), (start, _) in zip(occupied, occupied[1:]):
        if start < previous_end:
            raise AuditError(f"{label}: overlapping ranges")


def read_uleb128(blob, offset, end):
    """A bounded uint32 ULEB; no unterminated, overflowing or overlong values."""
    if not 0 <= offset <= end <= len(blob):
        raise AuditError("LC_FUNCTION_STARTS: invalid ULEB128 range")
    value = 0
    for index in range(5):
        if offset >= end:
            raise AuditError("LC_FUNCTION_STARTS: truncated ULEB128")
        byte = blob[offset]
        offset += 1
        if index == 4 and byte & 0xF0:
            raise AuditError("LC_FUNCTION_STARTS: ULEB128 overflows uint32")
        value |= (byte & 0x7F) << (7 * index)
        if not byte & 0x80:
            if index and byte == 0:
                raise AuditError("LC_FUNCTION_STARTS: overlong ULEB128")
            return value, offset
    raise AuditError("LC_FUNCTION_STARTS: unterminated ULEB128")


@dataclass(frozen=True)
class Segment:
    name: str
    vmaddr: int
    vmsize: int
    fileoff: int
    filesize: int
    maxprot: int
    initprot: int
    flags: int
    command_offset: int

    @property
    def pagezero(self):
        return (self.vmaddr == 0 and self.filesize == 0 and
                self.initprot == 0 and self.maxprot == 0)

    def runtime_range(self, slide):
        # XNU extends page-zero rather than sliding its start.
        return ((0, self.vmsize + slide) if self.pagezero else
                (self.vmaddr + slide, self.vmaddr + self.vmsize + slide))


@dataclass(frozen=True)
class Section:
    name: str
    segment: str
    addr: int
    size: int
    offset: int
    align: int
    flags: int
    index: int
    command_offset: int

    @property
    def zerofill(self):
        return (self.flags & 0xFF) in ZEROFILL_TYPES

    @property
    def instructions(self):
        return bool(self.flags & INSTRUCTION_ATTRIBUTES) or self.name == "__text"


@dataclass(frozen=True)
class Symbol:
    name: str
    address: int
    section_index: int
    mode: str | None
    table_offset: int


@dataclass(frozen=True)
class FunctionStart:
    address: int
    tagged_offset: int
    mode: str
    stream_offset: int


class MachO:
    def __init__(self, blob, path="<bytes>"):
        if len(blob) > MAX_IMAGE_SIZE:
            raise AuditError(f"image exceeds {MAX_IMAGE_SIZE} byte limit")
        _range(0, 28, len(blob), "Mach-O header")
        self.blob = bytes(blob)
        self.path = str(path)
        (magic, cpu, self.subtype, self.filetype, ncmds,
         sizeofcmds, self.flags) = struct.unpack_from("<7I", self.blob)
        if magic != MH_MAGIC or cpu != CPU_TYPE_ARM:
            raise AuditError("requires a thin, little-endian ARM32 Mach-O (not FAT/ARM64)")
        if ncmds > MAX_COMMANDS or ncmds > sizeofcmds // 8:
            raise AuditError("Mach-O header: excessive or impossible load-command count")
        end = _range(28, sizeofcmds, len(blob), "load commands")
        self.command_end = end
        self.segments = []
        self.sections = []
        self.symbols = []
        self.function_starts = []
        self.unixthread = None
        self.main = None
        self.dylinker = None
        self.uuid = None
        self.symtab = None
        self.function_table = None
        self.linkedit_ranges = []
        self.commands = []
        offset = 28
        for _ in range(ncmds):
            _range(offset, 8, end, "load-command header")
            command, size = struct.unpack_from("<II", self.blob, offset)
            if size < 8 or size % 4:
                raise AuditError("load command: cmdsize must be >= 8 and four-byte aligned")
            stop = _range(offset, size, end, "load command")
            self.commands.append((command, offset, size))
            self._command(command, offset, size, stop)
            offset = stop
        if offset != end:
            raise AuditError("sizeofcmds does not equal the load-command extent")
        self._validate_segments()
        if self.main and self.unixthread:
            raise AuditError("LC_MAIN and LC_UNIXTHREAD both supply a thread entry")
        self.all_image_info = next((s for s in self.sections
                                    if s.segment == "__DATA" and
                                    s.name == "__all_image_info"), None)
        if sum(s.segment == "__DATA" and s.name == "__all_image_info"
               for s in self.sections) > 1:
            raise AuditError("duplicate __all_image_info sections")
        self._validate_entries()
        self._parse_symbols()
        self._parse_function_starts()
        self._function_addresses = [f.address for f in self.function_starts]
        self._validate_entry_modes()

    @classmethod
    def from_path(cls, path):
        # Read at most the documented limit, including when a file grows while read.
        with Path(path).open("rb") as handle:
            blob = handle.read(MAX_IMAGE_SIZE + 1)
        return cls(blob, path)

    def _exact_size(self, actual, expected, label):
        if actual != expected:
            raise AuditError(f"{label}: expected cmdsize {expected}, got {actual}")

    def _command(self, command, offset, size, stop):
        if command == LC_SEGMENT:
            if len(self.segments) >= MAX_SEGMENTS:
                raise AuditError("excessive segment count")
            _range(offset, 56, stop, "LC_SEGMENT")
            (raw, vm, vs, fo, fs, maxprot, initprot, nsects,
             flags) = struct.unpack_from("<16s8I", self.blob, offset + 8)
            if nsects > MAX_SECTIONS - len(self.sections):
                raise AuditError("excessive section count")
            self._exact_size(size, 56 + nsects * 68, "LC_SEGMENT")
            segment = Segment(_name(raw), vm, vs, fo, fs, maxprot,
                              initprot, flags, offset)
            self.segments.append(segment)
            for index in range(nsects):
                position = offset + 56 + index * 68
                (sn, sg, addr, length, fileoff, align, reloff, nreloc,
                 section_flags, _, _) = struct.unpack_from("<16s16s9I", self.blob, position)
                if nreloc > MAX_TABLE_ENTRIES:
                    raise AuditError("section: excessive relocation count")
                _range(reloff, nreloc * 8, len(self.blob), "section relocations")
                self.sections.append(Section(_name(sn), _name(sg), addr,
                                             length, fileoff, align, section_flags,
                                             len(self.sections) + 1, position))
        elif command == LC_UNIXTHREAD:
            if self.unixthread is not None:
                raise AuditError("duplicate LC_UNIXTHREAD")
            position = offset + 8
            state = None
            while position < stop:
                _range(position, 8, stop, "LC_UNIXTHREAD flavor/count")
                flavor, count = struct.unpack_from("<II", self.blob, position)
                if count == 0 or count > MAX_TABLE_ENTRIES:
                    raise AuditError("LC_UNIXTHREAD: invalid state count")
                state_end = _range(position + 8, count * 4, stop, "LC_UNIXTHREAD state")
                if flavor == ARM_THREAD_STATE:
                    if state is not None or count != ARM_THREAD_STATE_COUNT:
                        raise AuditError("LC_UNIXTHREAD: requires one 17-word ARM_THREAD_STATE")
                    pc, cpsr = struct.unpack_from("<II", self.blob, position + 8 + 15 * 4)
                    state = {"pc": pc, "cpsr": cpsr, "command_offset": offset,
                             "mode": "Thumb" if (pc & 1 or cpsr & 0x20) else "ARM"}
                position = state_end
            if state is None:
                raise AuditError("LC_UNIXTHREAD: no ARM_THREAD_STATE entry")
            self.unixthread = state
        elif command == LC_MAIN:
            self._exact_size(size, 24, "LC_MAIN")
            if self.main is not None:
                raise AuditError("duplicate LC_MAIN")
            entryoff, stacksize = struct.unpack_from("<QQ", self.blob, offset + 8)
            self.main = {"entryoff": entryoff, "stacksize": stacksize,
                         "command_offset": offset,
                         "mode": "Thumb" if entryoff & 1 else "ARM"}
        elif command == LC_SYMTAB:
            self._exact_size(size, 24, "LC_SYMTAB")
            if self.symtab is not None:
                raise AuditError("duplicate LC_SYMTAB")
            self.symtab = struct.unpack_from("<4I", self.blob, offset + 8)
            so, count, st, ss = self.symtab
            if count > MAX_TABLE_ENTRIES:
                raise AuditError("LC_SYMTAB: excessive symbol count")
            _range(so, count * 12, len(self.blob), "nlist table")
            _range(st, ss, len(self.blob), "string table")
            if count and ss == 0:
                raise AuditError("LC_SYMTAB: symbols without a string table")
            self.linkedit_ranges.extend([(so, count * 12, "nlist table"),
                                         (st, ss, "string table")])
        elif command in (LC_LOAD_DYLINKER, LC_ID_DYLINKER):
            _range(offset, 12, stop, "dylinker command")
            string_offset = struct.unpack_from("<I", self.blob, offset + 8)[0]
            if not 12 <= string_offset < size:
                raise AuditError("dylinker command: invalid path offset")
            path = _cstring(self.blob, offset + string_offset, stop, "dylinker path")
            if command == LC_LOAD_DYLINKER:
                if self.dylinker is not None:
                    raise AuditError("duplicate LC_LOAD_DYLINKER")
                self.dylinker = path
        elif command == LC_UUID:
            self._exact_size(size, 24, "LC_UUID")
            if self.uuid is not None:
                raise AuditError("duplicate LC_UUID")
            self.uuid = self.blob[offset + 8:offset + 24].hex()
        elif command in LINKEDIT_DATA_COMMANDS:
            self._exact_size(size, 16, "linkedit_data_command")
            dataoff, datasize = struct.unpack_from("<II", self.blob, offset + 8)
            _range(dataoff, datasize, len(self.blob), "linkedit data")
            self.linkedit_ranges.append((dataoff, datasize, f"command {command:#x}"))
            if command == LC_FUNCTION_STARTS:
                if self.function_table is not None:
                    raise AuditError("duplicate LC_FUNCTION_STARTS")
                self.function_table = (dataoff, datasize)
        elif command in (0x22, 0x80000022):  # LC_DYLD_INFO[_ONLY]
            self._exact_size(size, 48, "LC_DYLD_INFO")
            fields = struct.unpack_from("<10I", self.blob, offset + 8)
            for dataoff, datasize in zip(fields[::2], fields[1::2]):
                _range(dataoff, datasize, len(self.blob), "dyld info data")
                self.linkedit_ranges.append((dataoff, datasize, "dyld info data"))
        elif command == 0x19:
            raise AuditError("LC_SEGMENT_64 in an ARM32 image")
        # Unknown commands are skipped only after their complete range was bounded.

    def _validate_segments(self):
        if not self.segments or len({s.name for s in self.segments}) != len(self.segments):
            raise AuditError("missing segments or duplicate segment names")
        by_name = {s.name: s for s in self.segments}
        self.text = by_name.get("__TEXT")
        if self.text is None or self.text.fileoff != 0 or not self.text.filesize:
            raise AuditError("requires one file-backed __TEXT containing the Mach-O header")
        if self.text.filesize < self.command_end:
            raise AuditError("__TEXT does not back the complete Mach-O header/load commands")
        sizes = {offset: size for _, offset, size in self.commands}
        for segment in self.segments:
            if segment.vmaddr % PAGE_SIZE or segment.vmsize % PAGE_SIZE or segment.fileoff % PAGE_SIZE:
                raise AuditError("segment VM/file ranges are not XNU page-aligned")
            _range(segment.vmaddr, segment.vmsize, U32_LIMIT, "segment VM")
            _range(segment.fileoff, segment.filesize, len(self.blob), "segment file")
            if segment.filesize > segment.vmsize:
                raise AuditError("segment filesize exceeds vmsize")
            if segment.flags & 1:
                raise AuditError("SG_HIGHVM images are unsupported; cannot assume low file backing")
            if (segment.maxprot & ~7 or segment.initprot & ~segment.maxprot):
                raise AuditError("segment: inconsistent VM protections")
        _disjoint([(s.vmaddr, s.vmaddr + s.vmsize) for s in self.segments], "segment VM")
        _disjoint([(s.fileoff, s.fileoff + s.filesize) for s in self.segments], "segment file")
        for section in self.sections:
            segment = by_name.get(section.segment)
            if segment is None or not (segment.command_offset < section.command_offset <
                                       segment.command_offset + sizes[segment.command_offset]):
                raise AuditError("section segment name does not match its containing command")
            if section.align > 31:
                raise AuditError("section: alignment exponent exceeds ARM32")
            alignment = 1 << section.align
            if section.addr % alignment or (not section.zerofill and section.offset % alignment):
                raise AuditError("section: declared alignment does not match address/file offset")
            end = _range(section.addr, section.size, U32_LIMIT, "section VM")
            if section.addr < segment.vmaddr or end > segment.vmaddr + segment.vmsize:
                raise AuditError("section VM range outside its segment")
            if not section.zerofill:
                stop = _range(section.offset, section.size, len(self.blob), "section file")
                if (section.offset < segment.fileoff or
                        stop > segment.fileoff + segment.filesize or
                        section.addr - segment.vmaddr != section.offset - segment.fileoff):
                    raise AuditError("section backing does not match its mapped segment")
        for segment in self.segments:
            sections = [s for s in self.sections if s.segment == segment.name]
            _disjoint([(s.addr, s.addr + s.size) for s in sections], "section VM")
        linkedit = by_name.get("__LINKEDIT")
        for offset, size, label in self.linkedit_ranges:
            if size and (linkedit is None or offset < linkedit.fileoff or
                         offset + size > linkedit.fileoff + linkedit.filesize):
                raise AuditError(f"{label}: data outside __LINKEDIT")

    def location(self, address):
        """Map an untagged preferred VA; zerofill sections take precedence."""
        for segment in self.segments:
            if segment.vmaddr <= address < segment.vmaddr + segment.vmsize:
                section = next((s for s in self.sections if s.segment == segment.name and
                                s.addr <= address < s.addr + s.size), None)
                delta = address - segment.vmaddr
                if segment.pagezero or not segment.initprot:
                    backing, fileoff = "inaccessible", None
                elif section and section.zerofill:
                    backing, fileoff = "section_zero_fill", None
                elif delta >= segment.filesize:
                    backing, fileoff = "segment_zero_fill", None
                else:
                    backing, fileoff = "file", segment.fileoff + delta
                return segment, section, fileoff, backing
        return None

    def file_to_vm(self, offset):
        for segment in self.segments:
            if segment.fileoff <= offset < segment.fileoff + segment.filesize:
                return segment.vmaddr + offset - segment.fileoff
        raise AuditError("file offset is not backed by a mapped segment")

    def _code(self, address, mode, label):
        location = self.location(address)
        if (location is None or not location[0].initprot & 4 or
                location[2] is None or
                (location[1] is not None and not location[1].instructions)):
            raise AuditError(f"{label}: address is not file-backed executable code")
        if address % (2 if mode == "Thumb" else 4):
            raise AuditError(f"{label}: misaligned {mode} instruction address")
        return location

    def _validate_entries(self):
        if self.unixthread:
            self._code(self.unixthread["pc"] & ~1, self.unixthread["mode"], "LC_UNIXTHREAD")
        if self.main:
            offset = self.main["entryoff"] & ~1
            if offset >= len(self.blob):
                raise AuditError("LC_MAIN: entryoff outside image")
            address = self.file_to_vm(offset)
            self._code(address, self.main["mode"], "LC_MAIN")
            self.main["preferred_address"] = address
            self.main["physical_file_offset"] = offset

    def _parse_symbols(self):
        if self.symtab is None:
            return
        so, count, st, ss = self.symtab
        names = {}
        name_bytes = 0
        for index in range(count):
            position = so + index * 12
            strx, kind, sect, desc, address = struct.unpack_from("<IBBHI", self.blob, position)
            if strx >= ss:
                raise AuditError("nlist: string index outside string table")
            if strx not in names:
                names[strx] = _cstring(self.blob, st + strx, st + ss, "nlist name")
                name_bytes += len(names[strx])
                if name_bytes > MAX_SYMBOL_NAME_BYTES:
                    raise AuditError("nlist: cumulative symbol names exceed memory budget")
            name = names[strx]
            if kind & N_STAB or kind & N_TYPE != N_SECT:
                continue
            if not 1 <= sect <= len(self.sections):
                raise AuditError("nlist: section index outside section table")
            section = self.sections[sect - 1]
            # Linkers attach __mh_*_header to section 1 while its value names
            # the Mach-O header BEFORE __text. It is not a function symbol.
            header_symbol = (name in ("__mh_execute_header", "__mh_dylinker_header",
                                      "__mh_dylib_header", "__mh_bundle_header") and
                             address == self.text.vmaddr and sect == 1)
            mode = (("Thumb" if desc & N_ARM_THUMB_DEF else "ARM")
                    if section.instructions and not header_symbol else None)
            physical = address & ~1 if mode else address
            if not header_symbol and not section.addr <= physical <= section.addr + section.size:
                raise AuditError("nlist: symbol outside its declared section")
            if mode and address & 1 and mode != "Thumb":
                raise AuditError("nlist: Thumb-tagged address contradicts ARM mode")
            self.symbols.append(Symbol(name, physical, sect, mode, position))

    def _parse_function_starts(self):
        if self.function_table is None:
            return
        offset, size = self.function_table
        if size == 0:
            return
        end = offset + size
        tagged = 0
        previous = -1
        modes = {}
        for symbol in self.symbols:
            if symbol.mode:
                modes.setdefault(symbol.address, set()).add(symbol.mode)
        while offset < end:
            stream_offset = offset
            delta, offset = read_uleb128(self.blob, offset, end)
            if delta == 0:
                if any(self.blob[offset:end]):
                    raise AuditError("LC_FUNCTION_STARTS: nonzero bytes after terminator")
                return
            if len(self.function_starts) >= MAX_TABLE_ENTRIES:
                raise AuditError("LC_FUNCTION_STARTS: excessive function count")
            # Deltas are BETWEEN TAGGED addresses. Masking each delta is wrong.
            tagged = _range(tagged, delta, U32_LIMIT - 1, "function-start accumulator")
            address = self.text.vmaddr + (tagged & ~1)
            mode = "Thumb" if tagged & 1 else "ARM"
            if address <= previous:
                raise AuditError("LC_FUNCTION_STARTS: non-increasing physical starts")
            self._code(address, mode, "LC_FUNCTION_STARTS")
            if address in modes and modes[address] != {mode}:
                raise AuditError("LC_FUNCTION_STARTS mode contradicts nlist")
            self.function_starts.append(FunctionStart(address, tagged, mode, stream_offset))
            previous = address
        raise AuditError("LC_FUNCTION_STARTS: missing zero terminator")

    def function_at(self, address):
        location = self.location(address)
        if location is None or not location[0].initprot & 4 or location[2] is None:
            return None
        section = location[1]
        if section is not None and not section.instructions:
            return None
        if self.function_starts:
            index = bisect_right(self._function_addresses, address) - 1
            if index < 0:
                return None
            function = self.function_starts[index]
            start_location = self.location(function.address)
            if start_location[1] != section:
                return None
            next_start = (self.function_starts[index + 1].address
                          if index + 1 < len(self.function_starts) else
                          location[0].vmaddr + location[0].filesize)
            boundary = section.addr + section.size if section else next_start
            if address >= min(next_start, boundary):
                return None
            return {"start": function.address, "mode": function.mode,
                    "offset": address - function.address,
                    "names": [s.name for s in self.symbols if s.mode and
                              s.address == function.address],
                    "evidence": "LC_FUNCTION_STARTS",
                    "stream_file_offset": function.stream_offset}
        candidates = [s for s in self.symbols if s.mode and s.address <= address and
                      section is not None and section.addr <= s.address < section.addr + section.size and
                      s.section_index == section.index]
        if not candidates:
            return None
        start = max(s.address for s in candidates)
        same = [s for s in candidates if s.address == start]
        modes = {s.mode for s in same}
        return {"start": start, "mode": next(iter(modes)) if len(modes) == 1 else None,
                "offset": address - start, "names": [s.name for s in same],
                "evidence": "nearest_nlist_symbol_only; extent_not_proven"}

    def _validate_entry_modes(self):
        entries = []
        if self.unixthread:
            entries.append(("LC_UNIXTHREAD", self.unixthread["pc"] & ~1,
                            self.unixthread["mode"]))
        if self.main:
            entries.append(("LC_MAIN", self.main["preferred_address"], self.main["mode"]))
        for label, address, mode in entries:
            known = {s.mode for s in self.symbols if s.address == address and s.mode}
            known.update(f.mode for f in self.function_starts if f.address == address)
            if known and known != {mode}:
                raise AuditError(f"{label}: mode contradicts nlist/function-start metadata")


def derive_slide(image, *, entry=None, all_image_info=None, base=None):
    """Use only image-specific entry/section/base anchors, refusing contradictions."""
    anchors = []
    if entry is not None:
        if not 0 <= entry < U32_LIMIT:
            raise AuditError("runtime entry outside ARM32")
        if image.main is not None:
            raise AuditError("LC_MAIN cannot anchor the initial kernel entry; it is called by dyld. "
                             "Use the actual dyld image or an independently verified --base.")
        if image.dylinker is not None and image.filetype != MH_DYLINKER:
            raise AuditError("this executable requests dyld: its LC_UNIXTHREAD is not the "
                             "initial kernel entry; supply the dyld image or verified --base")
        if image.unixthread is None or image.filetype not in (MH_EXECUTE, MH_DYLINKER):
            raise AuditError("entry anchor requires a dyld/static executable LC_UNIXTHREAD")
        if entry & 1 and image.unixthread["mode"] != "Thumb":
            raise AuditError("runtime entry Thumb tag contradicts ARM LC_UNIXTHREAD")
        preferred = image.unixthread["pc"] & ~1
        anchors.append(("LC_UNIXTHREAD", entry & ~1, preferred))
    if all_image_info is not None:
        section = image.all_image_info
        if image.filetype != MH_DYLINKER or section is None or not section.size:
            raise AuditError("all-image-info anchor requires dyld's __DATA,__all_image_info")
        if image.location(section.addr)[2] is None:
            raise AuditError("all-image-info anchor requires a file-backed section")
        if not 0 <= all_image_info < U32_LIMIT:
            raise AuditError("runtime all-image-info address outside ARM32")
        anchors.append(("__all_image_info", all_image_info, section.addr))
    if base is not None:
        if not 0 <= base < U32_LIMIT:
            raise AuditError("runtime __TEXT base outside ARM32")
        anchors.append(("explicit_verified___TEXT_base", base, image.text.vmaddr))
    if not anchors:
        raise AuditError("no mapping anchor; supply --entry/--all-image-info for dyld "
                         "or an independently verified --base")
    slides = {actual - preferred for _, actual, preferred in anchors}
    if len(slides) != 1:
        detail = ", ".join(f"{name}={actual - preferred:#x}"
                           for name, actual, preferred in anchors)
        raise AuditError(f"inconsistent mapping anchors: {detail}")
    slide = next(iter(slides))
    if slide % PAGE_SIZE:
        raise AuditError("slide is not page-aligned for ARM32 XNU mappings")
    for segment in image.segments:
        start, stop = segment.runtime_range(slide)
        _range(start, stop - start, U32_LIMIT, "runtime segment")
    return slide, [{"source": name, "actual": actual, "preferred": preferred,
                    "slide": actual - preferred} for name, actual, preferred in anchors]


def attribute(image, slide, value, *, code=False, mode=None):
    if not 0 <= value < U32_LIMIT:
        raise AuditError("runtime value outside ARM32")
    # LR/code pointers may carry Thumb bit 0; an explicitly ARM-mode PC
    # must retain a bad low bit so the report does not silently repair it.
    normalized = value & ~1 if code and mode != "ARM" else value
    preferred = normalized - slide
    result = {"value": value, "normalized_address": normalized,
              "preferred_address": preferred, "code_mode": mode,
              "segment": None, "section": None, "file_offset": None}
    if code and mode and normalized % (2 if mode == "Thumb" else 4):
        result["mode_warning"] = f"runtime code address is misaligned for {mode}"
    for segment in image.segments:
        if segment.pagezero and 0 <= normalized < segment.vmsize + slide:
            result.update(segment=segment.name, backing="inaccessible")
            return result
    location = image.location(preferred)
    if location is None:
        result["backing"] = "outside_supplied_image"
        return result
    segment, section, fileoff, backing = location
    result.update(segment=segment.name,
                  section=f"{section.segment},{section.name}" if section else None,
                  file_offset=fileoff, backing=backing)
    if section:
        result["section_offset"] = preferred - section.addr
    result["exact_symbols"] = [s.name for s in image.symbols if s.address == preferred]
    if code:
        function = image.function_at(preferred)
        result["function"] = function
        if mode and function and function["mode"] and function["mode"] != mode:
            result["mode_warning"] = "runtime mode disagrees with image code metadata"
    if fileoff is not None:
        end = segment.fileoff + segment.filesize
        if section:
            end = min(end, section.offset + section.size)
        raw = image.blob[fileoff:min(fileoff + 16, end)]
        result["file_bytes_hex"] = raw.hex(" ")
        if len(raw) >= 4:
            result["file_word_le"] = struct.unpack_from("<I", raw)[0]
    return result


def _hex_values(value):
    if isinstance(value, bool) or value is None:
        return value
    if isinstance(value, int):
        return hex(value)
    if isinstance(value, dict):
        return {key: _hex_values(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_hex_values(item) for item in value]
    return value


def report(image, slide, anchors, registers):
    segments = []
    for segment in image.segments:
        start, end = segment.runtime_range(slide)
        segments.append({"name": segment.name, "preferred_start": segment.vmaddr,
                         "vmsize": segment.vmsize, "runtime_start": start, "runtime_end": end,
                         "file_offset": segment.fileoff, "filesize": segment.filesize,
                         "initprot": segment.initprot, "reserved_only": segment.pagezero,
                         "sections": [{"name": s.name, "preferred_start": s.addr,
                                       "runtime_start": s.addr + slide, "size": s.size,
                                       "file_offset": None if s.zerofill else s.offset,
                                       "zerofill": s.zerofill, "flags": s.flags}
                                      for s in image.sections if s.segment == segment.name]})
    return _hex_values({"image": image.path, "sha256": hashlib.sha256(image.blob).hexdigest(),
                        "size": len(image.blob), "filetype": image.filetype, "uuid": image.uuid,
                        "slide": slide, "anchors": anchors,
                        "anchors_cross_checked": len(anchors) >= 2,
                        "LC_UNIXTHREAD": image.unixthread, "LC_MAIN": image.main,
                        "LC_LOAD_DYLINKER": image.dylinker,
                        "function_starts_count": len(image.function_starts),
                        "function_starts_table": image.function_table,
                        "segments": segments, "attribution": registers,
                        "limitations": ["Ranges are reconstructed from supplied image and anchors, "
                                        "not a complete live VM-map enumeration.",
                                        "file_bytes are snapshot bytes, not runtime instruction probes.",
                                        "LC_MAIN is not an initial kernel-entry anchor.",
                                        "No missing-library or runtime-binding inference."]})


def _address(text):
    try:
        value = int(text, 0)
    except ValueError as error:
        raise argparse.ArgumentTypeError("expected an integer address, e.g. 0x2be362c8") from error
    if not 0 <= value < U32_LIMIT:
        raise argparse.ArgumentTypeError("address must fit unsigned ARM32")
    return value


def _register(text):
    name, separator, address = text.partition("=")
    if not separator or not name or not name.replace("_", "").isalnum():
        raise argparse.ArgumentTypeError("expected --reg name=address")
    return name, _address(address)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--image", required=True, type=Path)
    parser.add_argument("--entry", type=_address, help="actual initial kernel-entry PC of this image")
    parser.add_argument("--all-image-info", type=_address, help="runtime task dyld-info address")
    parser.add_argument("--base", type=_address, help="independently verified runtime __TEXT base")
    parser.add_argument("--pc", type=_address)
    parser.add_argument("--lr", type=_address)
    parser.add_argument("--cpsr", type=_address, help="PC execution mode from saved ARM CPSR")
    parser.add_argument("--reg", type=_register, action="append", default=[])
    args = parser.parse_args(argv)
    try:
        image = MachO.from_path(args.image)
        slide, anchors = derive_slide(image, entry=args.entry,
                                      all_image_info=args.all_image_info, base=args.base)
        registers = {}
        if args.pc is not None:
            mode = ("Thumb" if args.cpsr & 0x20 else "ARM") if args.cpsr is not None else None
            registers["pc"] = attribute(image, slide, args.pc, code=True, mode=mode)
        if args.lr is not None:
            registers["lr"] = attribute(image, slide, args.lr, code=True,
                                         mode="Thumb" if args.lr & 1 else "ARM")
        for name, value in args.reg:
            if name in registers:
                raise AuditError(f"duplicate register name: {name}")
            registers[name] = attribute(image, slide, value)
        print(json.dumps(report(image, slide, anchors, registers), indent=2))
        return 0
    except (AuditError, OSError) as error:
        print(f"REFUSED: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
