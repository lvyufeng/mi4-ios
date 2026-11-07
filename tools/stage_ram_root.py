#!/usr/bin/env python3
"""Strict host-only RAM-root manifest validator/stager; never builds an image."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import posixpath
import re
import stat
import struct
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

MIB = 1024 * 1024
DEFAULT_VOLUME_BYTES = 16 * MIB
MAX_VOLUME_BYTES = 32 * MIB
MIN_METADATA_BYTES = 512 * 1024
MAX_MANIFEST_BYTES = 2 * MIB
MAX_ENTRIES = 4096
MAX_PATH_BYTES = 4096
MAX_SYMLINK_DEPTH = 64
MAX_LOAD_COMMAND_BYTES = MIB
MAX_LOAD_COMMANDS = 4096
MAX_DYLINKER_PATH_BYTES = 32
CHUNK_BYTES = 128 * 1024
FILE_MODES = {"0600", "0644", "0700", "0755"}
DIR_MODES = {"0700", "0755", "01777"}
REQUIRED_EXECUTABLES = {"/sbin/launchd": 2, "/usr/lib/dyld": 7}
TOP_KEYS = {
    "version", "entries", "max_volume_bytes", "max_payload_bytes",
    "root_name", "source_provenance",
}
ENTRY_KEYS = {
    "dir": {"type", "path", "mode"},
    "file": {"type", "path", "mode", "source", "size", "sha256", "source_provenance"},
    "symlink": {"type", "path", "target"},
}
_NOFOLLOW = os.O_NOFOLLOW
_DIRECTORY = os.O_DIRECTORY
_CLOEXEC = getattr(os, "O_CLOEXEC", 0)


class StageError(Exception):
    """A diagnosed invalid manifest, unsafe path, or staging failure."""


@dataclass(frozen=True)
class Identity:
    device: int
    inode: int
    size: int
    mtime_ns: int
    ctime_ns: int
    mode: int
    nlink: int


@dataclass
class Plan:
    entries: dict[str, dict[str, Any]]
    identities: dict[str, Identity]
    resolved_links: dict[str, str]
    volume_bytes: int
    max_payload_bytes: int
    payload_bytes: int
    metadata_reserve_bytes: int
    root_name: str | None
    source_provenance: str | None


def _fail(message: str) -> None:
    raise StageError(message)


def _integer(value: Any, name: str, minimum: int = 0) -> int:
    if type(value) is not int or value < minimum:
        _fail(f"{name} must be an integer >= {minimum}")
    return value


def _label(value: Any, name: str, limit: int = 512) -> str:
    if not isinstance(value, str) or not 1 <= len(value) <= limit:
        _fail(f"{name} must be a nonempty string of at most {limit} characters")
    if any(ord(ch) < 32 or ord(ch) == 127 for ch in value):
        _fail(f"{name} must not contain control characters")
    return value


def _canonical_path(value: Any, name: str, *, allow_root: bool = False) -> str:
    if not isinstance(value, str) or not value.startswith("/"):
        _fail(f"{name} must be an absolute canonical POSIX path")
    if "\x00" in value or "\\" in value:
        _fail(f"{name} contains NUL or backslash")
    try:
        encoded = value.encode("utf-8")
    except UnicodeEncodeError:
        _fail(f"{name} is not valid UTF-8")
    if len(encoded) > MAX_PATH_BYTES:
        _fail(f"{name} exceeds {MAX_PATH_BYTES} UTF-8 bytes")
    if value == "/":
        if allow_root:
            return value
        _fail(f"{name} must not name the root itself")
    parts = value[1:].split("/")
    if any(part in ("", ".", "..") for part in parts) or len(parts) > 128:
        _fail(f"{name} must be canonical: no empty, dot, or dot-dot components")
    return value


def _host_path(value: str | Path, name: str) -> str:
    return _canonical_path(os.fspath(value), name, allow_root=True)


def _open_directory(path: str) -> int:
    """Walk from / with no-follow directory FDs, including every ancestor."""
    fd = os.open("/", os.O_RDONLY | _DIRECTORY | _NOFOLLOW | _CLOEXEC)
    try:
        for part in path.strip("/").split("/") if path != "/" else ():
            child = os.open(part, os.O_RDONLY | _DIRECTORY | _NOFOLLOW | _CLOEXEC,
                            dir_fd=fd)
            os.close(fd)
            fd = child
        return fd
    except BaseException:
        os.close(fd)
        raise


def _open_regular(path: str) -> int:
    parent = _open_directory(posixpath.dirname(path))
    try:
        name = posixpath.basename(path)
        initial = os.stat(name, dir_fd=parent, follow_symlinks=False)
        if not stat.S_ISREG(initial.st_mode):
            _fail(f"source/manifest is not a regular file: {path}")
        # O_NONBLOCK prevents an unexpected FIFO swap from blocking before fstat.
        fd = os.open(name, os.O_RDONLY | _NOFOLLOW | _CLOEXEC | os.O_NONBLOCK,
                     dir_fd=parent)
    finally:
        os.close(parent)
    opened = os.fstat(fd)
    if (not stat.S_ISREG(opened.st_mode) or
            (opened.st_dev, opened.st_ino) != (initial.st_dev, initial.st_ino)):
        os.close(fd)
        _fail(f"source/manifest is not the inspected regular file: {path}")
    return fd


def _identity(fd: int) -> Identity:
    info = os.fstat(fd)
    if not stat.S_ISREG(info.st_mode):
        _fail("an opened input stopped being a regular file")
    return Identity(info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns,
                    info.st_ctime_ns, info.st_mode, info.st_nlink)


def _read_source_chunk(fd: int, count: int) -> bytes:
    """One narrow seam for deterministic source-change tests; never executes data."""
    return os.read(fd, count)


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            _fail(f"duplicate JSON object key: {key}")
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    _fail(f"non-JSON numeric constant: {value}")


def _load_json(path: str) -> dict[str, Any]:
    fd = _open_regular(path)
    try:
        before = _identity(fd)
        if before.size > MAX_MANIFEST_BYTES:
            _fail(f"manifest exceeds {MAX_MANIFEST_BYTES} bytes")
        chunks = []
        length = 0
        while True:
            data = os.read(fd, min(CHUNK_BYTES, MAX_MANIFEST_BYTES + 1 - length))
            if not data:
                break
            chunks.append(data)
            length += len(data)
            if length > MAX_MANIFEST_BYTES:
                _fail("manifest grew beyond its size limit")
        if before != _identity(fd) or length != before.size:
            _fail("manifest changed while being read")
    finally:
        os.close(fd)
    try:
        result = json.loads(b"".join(chunks).decode("utf-8"),
                            object_pairs_hook=_unique_object,
                            parse_constant=_reject_constant)
    except (UnicodeError, ValueError, RecursionError) as exc:
        raise StageError(f"invalid UTF-8 JSON manifest: {exc}") from exc
    if not isinstance(result, dict):
        _fail("manifest top level must be an object")
    return result


def _no_overlap(path: str, output: str) -> None:
    common = posixpath.commonpath((path, output))
    if common in (path, output):
        _fail(f"input and output paths overlap: {path}")


def _inspect_macho(data: bytes, size: int, guest: str) -> None:
    if len(data) < 28:
        _fail(f"{guest}: truncated 32-bit Mach-O header")
    magic, cpu, _subtype, kind, ncmds, sizeofcmds, _flags = struct.unpack_from("<7I", data)
    if magic != 0xFEEDFACE or cpu != 12 or kind != REQUIRED_EXECUTABLES[guest]:
        _fail(f"{guest}: requires little-endian 32-bit ARM (CPU 12) Mach-O type "
              f"{REQUIRED_EXECUTABLES[guest]}")
    if ncmds > MAX_LOAD_COMMANDS or sizeofcmds > MAX_LOAD_COMMAND_BYTES:
        _fail(f"{guest}: load-command bounds exceeded")
    if 28 + sizeofcmds > size or 28 + sizeofcmds > len(data):
        _fail(f"{guest}: truncated load-command region")
    cursor = 28
    end = 28 + sizeofcmds
    dylinkers = []
    for _ in range(ncmds):
        if cursor + 8 > end:
            _fail(f"{guest}: truncated load command")
        command, command_size = struct.unpack_from("<2I", data, cursor)
        if command_size < 8 or command_size % 4 or cursor + command_size > end:
            _fail(f"{guest}: invalid load-command size")
        if command == 0xE:  # LC_LOAD_DYLINKER; do not infer library dependency closure.
            if command_size < 12:
                _fail(f"{guest}: truncated LC_LOAD_DYLINKER")
            offset = struct.unpack_from("<I", data, cursor + 8)[0]
            if not 12 <= offset < command_size:
                _fail(f"{guest}: invalid LC_LOAD_DYLINKER string offset")
            start = cursor + offset
            stop = data.find(b"\0", start,
                             min(cursor + command_size, start + MAX_DYLINKER_PATH_BYTES + 1))
            if stop < 0:
                _fail(f"{guest}: unterminated/overlong LC_LOAD_DYLINKER pathname")
            dylinkers.append(data[start:stop])
        cursor += command_size
    if cursor != end:
        _fail(f"{guest}: ncmds and sizeofcmds disagree")
    if guest == "/sbin/launchd" and dylinkers != [b"/usr/lib/dyld"]:
        _fail("/sbin/launchd: exactly one LC_LOAD_DYLINKER /usr/lib/dyld is required")
    if guest == "/usr/lib/dyld" and dylinkers:
        _fail("/usr/lib/dyld: MH_DYLINKER must not request another dylinker")


def _read_verify_source(entry: dict[str, Any], expected: Identity | None = None,
                        output_fd: int | None = None) -> Identity:
    fd = _open_regular(entry["source"])
    try:
        before = _identity(fd)
        if before.size != entry["size"]:
            _fail(f"{entry['path']}: source size differs from manifest")
        if expected is not None and before != expected:
            _fail(f"{entry['path']}: source changed since validation")
        digest = hashlib.sha256()
        total = 0
        prefix = bytearray()
        inspect = entry["path"] in REQUIRED_EXECUTABLES
        while True:
            data = _read_source_chunk(fd, min(CHUNK_BYTES, entry["size"] - total + 1))
            if not data:
                break
            total += len(data)
            if total > entry["size"]:
                _fail(f"{entry['path']}: source grew during read")
            digest.update(data)
            if inspect and len(prefix) < 28 + MAX_LOAD_COMMAND_BYTES:
                prefix.extend(data[:28 + MAX_LOAD_COMMAND_BYTES - len(prefix)])
            if output_fd is not None:
                view = memoryview(data)
                while view:
                    written = os.write(output_fd, view)
                    if written <= 0:
                        _fail(f"{entry['path']}: short output write")
                    view = view[written:]
        if before != _identity(fd) or total != entry["size"]:
            _fail(f"{entry['path']}: source changed while being read")
        if digest.hexdigest() != entry["sha256"]:
            _fail(f"{entry['path']}: SHA-256 mismatch")
        if inspect:
            _inspect_macho(bytes(prefix), total, entry["path"])
        return before
    finally:
        os.close(fd)


def _verify_output(fd: int, entry: dict[str, Any], sources: set[tuple[int, int]]) -> None:
    before = _identity(fd)
    if before.nlink != 1 or (before.device, before.inode) in sources:
        _fail(f"{entry['path']}: staged file is hardlinked or aliases an input")
    if before.size != entry["size"]:
        _fail(f"{entry['path']}: staged file size mismatch")
    os.lseek(fd, 0, os.SEEK_SET)
    digest = hashlib.sha256()
    total = 0
    while True:
        data = os.read(fd, min(CHUNK_BYTES, entry["size"] - total + 1))
        if not data:
            break
        total += len(data)
        if total > entry["size"]:
            _fail(f"{entry['path']}: staged file grew during verification")
        digest.update(data)
    if before != _identity(fd) or total != entry["size"] or digest.hexdigest() != entry["sha256"]:
        _fail(f"{entry['path']}: staged file changed or SHA-256 mismatch")


def _resolve_links(entries: dict[str, dict[str, Any]]) -> dict[str, str]:
    resolved: dict[str, str] = {}
    active: set[str] = set()

    def resolve(link: str, depth: int) -> str:
        if link in active:
            _fail(f"symlink cycle involving {link}")
        if depth > MAX_SYMLINK_DEPTH:
            _fail(f"symlink chain exceeds {MAX_SYMLINK_DEPTH}")
        if link in resolved:
            return resolved[link]
        active.add(link)
        target = entries[link]["target"]
        # Check lexical confinement as well as real component-wise resolution.
        lexical = posixpath.dirname(link).strip("/").split("/")
        lexical = [] if lexical == [""] else lexical
        for part in target.split("/"):
            if part == "..":
                if not lexical:
                    _fail(f"{link}: symlink target escapes guest root")
                lexical.pop()
            elif part not in ("", "."):
                lexical.append(part)
        normalized = posixpath.normpath(posixpath.join(posixpath.dirname(link), target))
        if not normalized.startswith("/"):
            _fail(f"{link}: invalid normalized symlink target")
        current = posixpath.dirname(link).strip("/").split("/")
        current = [] if current == [""] else current
        components = target.split("/")
        for index, part in enumerate(components):
            if part in ("", "."):
                continue
            if part == "..":
                if not current:
                    _fail(f"{link}: symlink resolution escapes guest root")
                current.pop()
                continue
            candidate = "/" + "/".join(current + [part])
            entry = entries.get(candidate)
            if entry is None:
                _fail(f"{link}: undeclared symlink target component {candidate}")
            if entry["type"] == "symlink":
                candidate = resolve(candidate, depth + 1)
                entry = entries.get(candidate, {"type": "dir"})
            remaining = components[index + 1:]
            if remaining and entry["type"] != "dir":
                _fail(f"{link}: non-directory in symlink target {candidate}")
            current = candidate.strip("/").split("/") if candidate != "/" else []
        answer = "/" + "/".join(current)
        resolved[link] = answer
        active.remove(link)
        return answer

    for path, entry in entries.items():
        if entry["type"] == "symlink":
            resolve(path, 0)
    return resolved


def validate_manifest(manifest: str | Path, output: str | Path,
                      require_files: tuple[str, ...] | list[str] = ()) -> Plan:
    """Read-only validation, including complete hashes of all bounded regular inputs."""
    manifest_path = _host_path(manifest, "manifest")
    output_path = _host_path(output, "output staging")
    _no_overlap(manifest_path, output_path)
    raw = _load_json(manifest_path)
    unknown = set(raw) - TOP_KEYS
    if unknown:
        _fail(f"unknown manifest fields: {', '.join(sorted(unknown))}")
    if type(raw.get("version")) is not int or raw["version"] != 1:
        _fail("manifest version must be integer 1")
    volume = _integer(raw.get("max_volume_bytes", DEFAULT_VOLUME_BYTES), "max_volume_bytes", 1)
    if volume > MAX_VOLUME_BYTES:
        _fail(f"max_volume_bytes exceeds hard ceiling {MAX_VOLUME_BYTES}")
    reserve = max(MIN_METADATA_BYTES, (volume + 19) // 20)
    payload_limit = _integer(raw.get("max_payload_bytes"), "max_payload_bytes")
    if payload_limit > volume - reserve:
        _fail("max_payload_bytes must leave max(512 KiB, ceil(5% of volume)) metadata reserve")
    root_name = None
    if "root_name" in raw:
        root_name = _label(raw["root_name"], "root_name", 80)
        if not re.fullmatch(r"[A-Za-z0-9_.-]+", root_name) or root_name in (".", ".."):
            _fail("root_name is a report label: use letters, digits, underscore, dot, or hyphen")
    provenance = _label(raw["source_provenance"], "source_provenance") if "source_provenance" in raw else None
    supplied = raw.get("entries")
    if not isinstance(supplied, list) or not 1 <= len(supplied) <= MAX_ENTRIES:
        _fail(f"entries must be a nonempty array of at most {MAX_ENTRIES} objects")
    entries: dict[str, dict[str, Any]] = {}
    total = 0
    for item in supplied:
        if not isinstance(item, dict) or not isinstance(item.get("type"), str):
            _fail("each entry must be an object with a type")
        kind = item["type"]
        if kind not in ENTRY_KEYS:
            _fail(f"unsupported entry type: {kind}")
        unknown = set(item) - ENTRY_KEYS[kind]
        if unknown:
            _fail(f"unknown {kind} fields: {', '.join(sorted(unknown))}")
        path = _canonical_path(item.get("path"), "guest path")
        if path in entries:
            _fail(f"duplicate guest path: {path}")
        if path.startswith("/dev/"):
            _fail("/dev must be an empty mountpoint; no entries beneath /dev")
        entry = dict(item)
        if kind in ("dir", "file"):
            modes = DIR_MODES if kind == "dir" else FILE_MODES
            if not isinstance(item.get("mode"), str) or item["mode"] not in modes:
                _fail(f"{path}: mode must be one of {', '.join(sorted(modes))}")
            if item["mode"] == "01777" and path != "/private/var/tmp":
                _fail("01777 is permitted only for /private/var/tmp")
        if path == "/private/var/tmp" and (kind != "dir" or item.get("mode") != "01777"):
            _fail("/private/var/tmp, when declared, must be a 01777 directory")
        if kind == "file":
            source = _host_path(item.get("source") if isinstance(item.get("source"), str) else "", "source")
            if source == "/dev" or source.startswith("/dev/"):
                _fail("host /dev paths are forbidden sources")
            _no_overlap(source, output_path)
            entry["source"] = source
            size = _integer(item.get("size"), f"{path}: size")
            if size > payload_limit:
                _fail(f"{path}: file size exceeds max_payload_bytes")
            total += size
            sha = item.get("sha256")
            if not isinstance(sha, str) or not re.fullmatch(r"[0-9a-f]{64}", sha):
                _fail(f"{path}: sha256 must be 64 lowercase hexadecimal characters")
            if "source_provenance" in item:
                _label(item["source_provenance"], f"{path}: source_provenance")
        elif kind == "symlink":
            target = item.get("target")
            if not isinstance(target, str) or not target or target.startswith("/") or "\x00" in target or "\\" in target:
                _fail(f"{path}: symlink target must be a nonempty relative POSIX path")
            try:
                target_bytes = target.encode("utf-8")
            except UnicodeEncodeError:
                _fail(f"{path}: symlink target is not valid UTF-8")
            if len(target_bytes) > MAX_PATH_BYTES or len(target.split("/")) > 128:
                _fail(f"{path}: symlink target is too long")
        entries[path] = entry
    if total > payload_limit:
        _fail("sum of file sizes exceeds max_payload_bytes")
    for path in entries:
        parent = posixpath.dirname(path)
        while parent != "/":
            if parent not in entries or entries[parent]["type"] != "dir":
                _fail(f"{path}: every parent must be an explicitly declared directory: {parent}")
            parent = posixpath.dirname(parent)
    for path in REQUIRED_EXECUTABLES:
        if path not in entries or entries[path]["type"] != "file" or entries[path].get("mode") != "0755":
            _fail(f"{path}: a regular file with mode 0755 is required")
    if "/dev" not in entries or entries["/dev"]["type"] != "dir" or entries["/dev"].get("mode") != "0755":
        _fail("/dev: an empty directory with mode 0755 is required")
    resolved = _resolve_links(entries)
    for required in require_files:
        required = _canonical_path(required, "--require-files guest path")
        destination = resolved.get(required, required)
        if required not in entries or destination not in entries or entries[destination]["type"] != "file":
            _fail(f"required file is not declared/resolved to a regular file: {required}")
    identities = {}
    for path in sorted(entries):
        if entries[path]["type"] == "file":
            identities[path] = _read_verify_source(entries[path])
    return Plan(entries, identities, resolved, volume, payload_limit, total, reserve,
                root_name, provenance)


def _guest_directory_fd(root_fd: int, guest: str) -> int:
    fd = os.dup(root_fd)
    try:
        for part in guest.strip("/").split("/") if guest != "/" else ():
            child = os.open(part, os.O_RDONLY | _DIRECTORY | _NOFOLLOW | _CLOEXEC,
                            dir_fd=fd)
            os.close(fd)
            fd = child
        return fd
    except BaseException:
        os.close(fd)
        raise


def _report(plan: Plan) -> dict[str, Any]:
    content = []
    counts = {"file": 0, "dir": 0, "symlink": 0}
    for path, entry in sorted(plan.entries.items()):
        item = {key: entry[key] for key in ("path", "type", "mode", "size", "sha256", "target", "source_provenance") if key in entry}
        if entry["type"] == "symlink":
            item["resolved_target"] = plan.resolved_links[path]
        counts[entry["type"]] += 1
        content.append(item)
    report: dict[str, Any] = {
        "report_version": 1,
        "operation": "host-directory-staging-only",
        "root_mode": "0755",
        "normalized_mtime_seconds": 0,
        "max_volume_bytes": plan.volume_bytes,
        "max_payload_bytes": plan.max_payload_bytes,
        "payload_bytes": plan.payload_bytes,
        "root_file_bytes": plan.payload_bytes,
        "metadata_reserve_bytes": plan.metadata_reserve_bytes,
        "entry_counts": counts,
        "directory_count_including_root": counts["dir"] + 1,
        "content_manifest": content,
        "warnings": [
            "Not an HFS formatter, image builder, boot test, or device tool.",
            "Metadata reserve is only a budgeting estimate; actual HFS fit is not guaranteed.",
            "A <=32 MiB requested volume does not prove RAM fit within the owned 64 MiB or a valid linker layout.",
            "Only launchd/dyld bounded headers and load commands are checked; dependency closure and runtime correctness are not validated.",
            "SHA-256 equality and provenance labels do not prove Apple authenticity, licensing, or trusted origin.",
            "Host uid/gid are retained for new files; guest ownership, ACLs, xattrs, and HFS case-folding are not modeled.",
            "Inputs are never written, chmodded, or executed; ordinary host reads may update filesystem atime.",
        ],
    }
    if plan.root_name is not None:
        report["root_name"] = plan.root_name
    if plan.source_provenance is not None:
        report["source_provenance"] = plan.source_provenance
    return report


def stage_manifest(manifest: str | Path, output: str | Path,
                   require_files: tuple[str, ...] | list[str] = ()) -> dict[str, Any]:
    """Validate then create exactly one new tree; never delete, replace, or execute."""
    parent_fd = root_fd = None
    created = False
    output_path = _host_path(output, "output staging")
    home_paths = {os.path.abspath(os.path.expanduser("~")), os.path.realpath(os.path.expanduser("~"))}
    if output_path == "/" or output_path in home_paths:
        _fail("output staging must not be / or the user's HOME")
    try:
        parent_fd = _open_directory(posixpath.dirname(output_path))
        name = posixpath.basename(output_path)
        try:
            os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            _fail("output staging path already exists (nothing was changed)")
        plan = validate_manifest(manifest, output_path, require_files)
        report = _report(plan)
        # All initial input and schema checks precede creation. mkdir is exclusive.
        os.mkdir(name, 0o700, dir_fd=parent_fd)
        created = True
        made = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        root_fd = os.open(name, os.O_RDONLY | _DIRECTORY | _NOFOLLOW | _CLOEXEC,
                          dir_fd=parent_fd)
        opened = os.fstat(root_fd)
        if (made.st_dev, made.st_ino) != (opened.st_dev, opened.st_ino) or opened.st_uid != os.geteuid():
            _fail("new staging root identity/owner changed")
        os.fchmod(root_fd, 0o700)
        source_inodes = {(i.device, i.inode) for i in plan.identities.values()}
        directories = sorted((p for p, e in plan.entries.items() if e["type"] == "dir"),
                             key=lambda p: (p.count("/"), p))
        for path in directories:
            fd = _guest_directory_fd(root_fd, posixpath.dirname(path))
            try:
                os.mkdir(posixpath.basename(path), 0o700, dir_fd=fd)
            finally:
                os.close(fd)
        for path, entry in sorted(plan.entries.items()):
            if entry["type"] != "file":
                continue
            parent = _guest_directory_fd(root_fd, posixpath.dirname(path))
            try:
                fd = os.open(posixpath.basename(path),
                             os.O_RDWR | os.O_CREAT | os.O_EXCL | _NOFOLLOW | _CLOEXEC,
                             0o600, dir_fd=parent)
            finally:
                os.close(parent)
            try:
                _read_verify_source(entry, plan.identities[path], fd)
                _verify_output(fd, entry, source_inodes)
                os.utime(fd, ns=(0, 0))
                os.fsync(fd)
            finally:
                os.close(fd)
        # No symlinks exist while source files/directories are being populated.
        for path, entry in sorted(plan.entries.items()):
            if entry["type"] != "symlink":
                continue
            parent = _guest_directory_fd(root_fd, posixpath.dirname(path))
            try:
                os.symlink(entry["target"], posixpath.basename(path), dir_fd=parent)
                os.utime(posixpath.basename(path), ns=(0, 0), dir_fd=parent, follow_symlinks=False)
            finally:
                os.close(parent)
        # Apply executable and directory permissions only inside the private root.
        for path, entry in sorted(plan.entries.items()):
            if entry["type"] != "file":
                continue
            parent = _guest_directory_fd(root_fd, posixpath.dirname(path))
            try:
                fd = os.open(posixpath.basename(path), os.O_RDONLY | _NOFOLLOW | _CLOEXEC,
                             dir_fd=parent)
            finally:
                os.close(parent)
            try:
                os.fchmod(fd, int(entry["mode"], 8))
            finally:
                os.close(fd)
        for path in reversed(directories):
            fd = _guest_directory_fd(root_fd, path)
            try:
                os.utime(fd, ns=(0, 0))
                os.fchmod(fd, int(plan.entries[path]["mode"], 8))
            finally:
                os.close(fd)
        os.utime(root_fd, ns=(0, 0))
        os.fchmod(root_fd, 0o755)  # Last operation: make the completed tree accessible.
        return report
    except (OSError, StageError, KeyboardInterrupt) as exc:
        detail = str(exc) or "staging interrupted"
        if created:
            detail += f"; partial staging directory left at {output_path} (not cleaned; inspect it, do not treat as complete)"
        raise StageError(detail) from exc
    finally:
        if root_fd is not None:
            os.close(root_fd)
        if parent_fd is not None:
            os.close(parent_fd)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Validate a private version-1 JSON manifest and stage a NEW host directory only; no HFS/image/device operation.")
    parser.add_argument("manifest", help="absolute private JSON manifest path (never copied into the guest)")
    parser.add_argument("--output-staging", required=True,
                        help="absolute NEW directory; existing non-symlink parent required")
    parser.add_argument("--require-files", action="append", default=[], metavar="/GUEST/PATH",
                        help="repeat to require declared/resolved regular files; not dependency-closure validation")
    args = parser.parse_args(argv)
    try:
        report = stage_manifest(args.manifest, args.output_staging, args.require_files)
    except (StageError, OSError) as exc:
        print(f"stage_ram_root: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(report, indent=2, sort_keys=True, ensure_ascii=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
