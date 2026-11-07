#!/usr/bin/env python3
"""Synthetic host-only tests: no Apple bytes, toolchain, device, or network."""

from __future__ import annotations

import contextlib
import copy
import hashlib
import io
import json
import os
from pathlib import Path
import stat
import struct
import tempfile
import unittest
from unittest import mock

import stage_ram_root as stage


def macho(kind: int, *, cpu: int = 12, magic: int = 0xFEEDFACE,
          dylinker: bytes | None = None, commands: bytes | None = None,
          ncmds: int | None = None) -> bytes:
    if commands is None:
        if dylinker is None:
            commands = b""
            count = 0
        else:
            text = dylinker + b"\0"
            length = (12 + len(text) + 3) & ~3
            commands = struct.pack("<3I", 0xE, length, 12) + text
            commands += b"\0" * (length - len(commands))
            count = 1
    else:
        count = 1
    return struct.pack("<7I", magic, cpu, 0, kind,
                       count if ncmds is None else ncmds, len(commands), 0) + commands


class StageTests(unittest.TestCase):
    def setUp(self) -> None:
        # resolve() here selects a physical private test directory, not tool input.
        self.temporary = tempfile.TemporaryDirectory(prefix="ram-root-test-")
        self.base = Path(self.temporary.name).resolve()
        self.addCleanup(self.temporary.cleanup)
        self.sources = self.base / "sources"
        self.sources.mkdir(mode=0o700)
        self.manifest = self.base / "private.json"
        self.output = self.base / "new-root"
        self.raw = {
            "version": 1,
            "max_payload_bytes": 1024 * 1024,
            "entries": [
                {"type": "dir", "path": "/sbin", "mode": "0755"},
                {"type": "dir", "path": "/usr", "mode": "0755"},
                {"type": "dir", "path": "/usr/lib", "mode": "0755"},
                {"type": "dir", "path": "/dev", "mode": "0755"},
            ],
        }
        self.add_file("/sbin/launchd", macho(2, dylinker=b"/usr/lib/dyld"), "0755")
        self.add_file("/usr/lib/dyld", macho(7), "0755")

    def add_file(self, guest: str, data: bytes, mode: str = "0644") -> dict:
        source = self.sources / f"input-{len(self.raw['entries'])}"
        source.write_bytes(data)
        entry = {"type": "file", "path": guest, "mode": mode,
                 "source": str(source), "size": len(data),
                 "sha256": hashlib.sha256(data).hexdigest()}
        self.raw["entries"].append(entry)
        return entry

    def entry(self, path: str) -> dict:
        return next(entry for entry in self.raw["entries"] if entry["path"] == path)

    def replace_launchd(self, data: bytes) -> None:
        entry = self.entry("/sbin/launchd")
        Path(entry["source"]).write_bytes(data)
        entry["size"] = len(data)
        entry["sha256"] = hashlib.sha256(data).hexdigest()

    def write_manifest(self) -> None:
        self.manifest.write_text(json.dumps(self.raw), encoding="utf-8")

    def run_stage(self, *, output: Path | str | None = None,
                  required: tuple[str, ...] = ()) -> dict:
        self.write_manifest()
        return stage.stage_manifest(self.manifest, output or self.output, required)

    def reject(self, match: str = ".*") -> None:
        with self.assertRaisesRegex(stage.StageError, match):
            self.run_stage()
        self.assertFalse(self.output.exists(), "validation failure created an output")

    def test_minimum_root_and_stdout_report_do_not_contaminate_guest(self) -> None:
        self.write_manifest()
        source_before = {p: (p.read_bytes(), p.stat().st_mode, p.stat().st_mtime_ns)
                         for p in self.sources.iterdir()}
        manifest_before = (self.manifest.read_bytes(), self.manifest.stat().st_mtime_ns)
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            code = stage.main([str(self.manifest), "--output-staging", str(self.output)])
        self.assertEqual(code, 0)
        report = json.loads(output.getvalue())
        self.assertEqual(report["operation"], "host-directory-staging-only")
        self.assertEqual(report["max_volume_bytes"], 16 * stage.MIB)
        self.assertEqual(report["metadata_reserve_bytes"], (16 * stage.MIB + 19) // 20)
        self.assertEqual(report["payload_bytes"], sum(e.get("size", 0) for e in self.raw["entries"]))
        self.assertEqual(report["entry_counts"], {"file": 2, "dir": 4, "symlink": 0})
        self.assertEqual(sorted(p.name for p in self.output.iterdir()), ["dev", "sbin", "usr"])
        self.assertEqual(list((self.output / "dev").iterdir()), [])
        self.assertEqual(stat.S_IMODE(self.output.stat().st_mode), 0o755)
        for entry in self.raw["entries"]:
            target = self.output / entry["path"][1:]
            self.assertEqual(target.stat().st_mtime_ns, 0)
            self.assertEqual(stat.S_IMODE(target.stat().st_mode), int(entry["mode"], 8))
            if entry["type"] == "file":
                self.assertEqual(target.read_bytes(), Path(entry["source"]).read_bytes())
        for source, snapshot in source_before.items():
            self.assertEqual((source.read_bytes(), source.stat().st_mode, source.stat().st_mtime_ns), snapshot)
        self.assertEqual((self.manifest.read_bytes(), self.manifest.stat().st_mtime_ns), manifest_before)
        self.assertNotIn(str(self.sources), output.getvalue())
        self.assertNotIn("source\"", output.getvalue())

    def test_reproducible_report_and_reversed_manifest_order(self) -> None:
        first = self.run_stage()
        self.raw["entries"].reverse()
        second = self.run_stage(output=self.base / "second-root")
        self.assertEqual(first, second)
        for entry in self.raw["entries"]:
            if entry["type"] == "file":
                self.assertEqual((self.output / entry["path"][1:]).read_bytes(),
                                 (self.base / "second-root" / entry["path"][1:]).read_bytes())

    def test_guest_paths_must_be_canonical_absolute_posix(self) -> None:
        for bad in ("relative", "/", "/a/../b", "/a/./b", "/a//b", "//a", "/a/", "/a\0b", "/a\\b"):
            with self.subTest(path=repr(bad)):
                self.raw["entries"].append({"type": "dir", "path": bad, "mode": "0755"})
                self.reject("guest path")
                self.raw["entries"].pop()

    def test_duplicate_paths_rejected_across_types(self) -> None:
        for kind in ("dir", "file", "symlink"):
            with self.subTest(kind=kind):
                item = {"type": kind, "path": "/usr", "mode": "0755"}
                if kind == "symlink":
                    item = {"type": kind, "path": "/usr", "target": "sbin"}
                self.raw["entries"].append(item)
                self.reject("duplicate guest path")
                self.raw["entries"].pop()

    def test_missing_or_non_directory_parent_rejected(self) -> None:
        self.raw["entries"].append({"type": "dir", "path": "/missing/child", "mode": "0755"})
        self.reject("explicitly declared directory")
        self.raw["entries"].pop()
        self.raw["entries"].append({"type": "dir", "path": "/sbin/launchd/child", "mode": "0755"})
        self.reject("explicitly declared directory")

    def test_symlink_ancestor_never_used_as_entry_parent(self) -> None:
        self.raw["entries"].extend([
            {"type": "symlink", "path": "/alias", "target": "usr"},
            {"type": "dir", "path": "/alias/child", "mode": "0755"},
        ])
        self.reject("explicitly declared directory")

    def test_dev_must_be_empty_directory_0755(self) -> None:
        self.raw["entries"].append({"type": "dir", "path": "/dev/sub", "mode": "0755"})
        self.reject("empty mountpoint")
        self.raw["entries"].pop()
        self.entry("/dev")["mode"] = "0700"
        self.reject("empty directory with mode 0755")
        self.raw["entries"] = [e for e in self.raw["entries"] if e["path"] != "/dev"]
        self.reject("/dev")

    def test_confined_relative_symlink_and_required_file(self) -> None:
        library = self.add_file("/usr/lib/owned-library.dylib", b"synthetic opaque test input")
        self.raw["entries"].extend([
            {"type": "symlink", "path": "/usr/lib/library.dylib", "target": "owned-library.dylib"},
            {"type": "symlink", "path": "/lib", "target": "usr/lib"},
            {"type": "symlink", "path": "/other-library", "target": "lib/library.dylib"},
        ])
        report = self.run_stage(required=("/usr/lib/library.dylib", "/other-library"))
        self.assertEqual((self.output / "other-library").read_bytes(), Path(library["source"]).read_bytes())
        self.assertEqual(os.readlink(self.output / "lib"), "usr/lib")
        self.assertEqual((self.output / "lib").lstat().st_mtime_ns, 0)
        links = {e["path"]: e["resolved_target"] for e in report["content_manifest"] if e["type"] == "symlink"}
        self.assertEqual(links["/other-library"], "/usr/lib/owned-library.dylib")

    def test_symlink_target_rejects_absolute_escape_backslash_and_nul(self) -> None:
        for bad in ("/usr/lib/dyld", "../../outside", "usr\\lib", "usr\0lib", ""):
            with self.subTest(target=repr(bad)):
                self.raw["entries"].append({"type": "symlink", "path": "/alias", "target": bad})
                self.reject("symlink")
                self.raw["entries"].pop()

    def test_symlink_dangling_cycle_and_file_as_directory(self) -> None:
        for links, message in (
            ([{"type": "symlink", "path": "/alias", "target": "missing"}], "undeclared"),
            ([{"type": "symlink", "path": "/a", "target": "b"}, {"type": "symlink", "path": "/b", "target": "a"}], "cycle"),
            ([{"type": "symlink", "path": "/alias", "target": "sbin/launchd/.."}], "non-directory"),
        ):
            with self.subTest(message=message):
                self.raw["entries"].extend(links)
                self.reject(message)
                del self.raw["entries"][-len(links):]

    def test_symlink_actual_resolution_cannot_escape_after_directory_link(self) -> None:
        self.raw["entries"].extend([
            {"type": "symlink", "path": "/usr/up", "target": ".."},
            {"type": "symlink", "path": "/alias", "target": "usr/up/../usr"},
        ])
        self.reject("escapes guest root")

    def test_symlink_normalization_requires_declared_walk_components(self) -> None:
        self.raw["entries"].append({"type": "symlink", "path": "/alias", "target": "missing/../usr"})
        self.reject("undeclared")

    def test_source_paths_are_absolute_and_not_guest_or_dev_paths(self) -> None:
        entry = self.entry("/sbin/launchd")
        original = entry["source"]
        for bad in ("relative", "/dev/null", str(self.sources) + "/../source", "C:\\guest\\launchd"):
            with self.subTest(source=bad):
                entry["source"] = bad
                self.reject("source|host /dev")
        entry["source"] = original

    def test_source_final_symlink_rejected(self) -> None:
        entry = self.entry("/sbin/launchd")
        link = self.sources / "linked-source"
        link.symlink_to(Path(entry["source"]).name)
        entry["source"] = str(link)
        self.reject()

    def test_source_symlink_ancestor_rejected(self) -> None:
        alias = self.base / "aliased-sources"
        alias.symlink_to(self.sources, target_is_directory=True)
        entry = self.entry("/sbin/launchd")
        entry["source"] = str(alias / Path(entry["source"]).name)
        self.reject()

    def test_nonregular_directory_fifo_and_host_dev_source_rejected(self) -> None:
        entry = self.entry("/sbin/launchd")
        entry["source"] = str(self.sources)
        self.reject("not a regular file")
        fifo = self.sources / "fifo"
        os.mkfifo(fifo)
        entry["source"] = str(fifo)
        self.reject("not a regular file")
        entry["source"] = "/dev/zero"
        self.reject("host /dev")

    def test_hardlinked_read_only_source_is_copied_not_linked_or_executed(self) -> None:
        entry = self.entry("/sbin/launchd")
        source = Path(entry["source"])
        alias = self.sources / "hardlink"
        os.link(source, alias)
        source.chmod(0o400)
        self.assertEqual(source.stat().st_nlink, 2)
        self.run_stage()
        target = self.output / "sbin/launchd"
        self.assertNotEqual((target.stat().st_dev, target.stat().st_ino),
                            (source.stat().st_dev, source.stat().st_ino))
        self.assertEqual(target.stat().st_nlink, 1)
        self.assertEqual(stat.S_IMODE(source.stat().st_mode), 0o400)
        self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o755)

    def test_input_hash_and_exact_size_enforced(self) -> None:
        entry = self.entry("/sbin/launchd")
        original_hash = entry["sha256"]
        entry["sha256"] = "0" * 64
        self.reject("SHA-256 mismatch")
        entry["sha256"] = original_hash
        entry["size"] += 1
        self.reject("source size")
        entry["size"] -= 2
        self.reject("source size")

    def test_sizes_and_hash_types_fail_closed(self) -> None:
        entry = self.entry("/sbin/launchd")
        original = copy.deepcopy(entry)
        for key, value in (("size", True), ("size", -1), ("size", 1.0),
                           ("sha256", "F" * 64), ("sha256", "abc")):
            with self.subTest(key=key, value=value):
                entry.update(original)
                entry[key] = value
                self.reject("size|sha256")

    def test_safe_mode_whitelists_and_executable_requirement(self) -> None:
        entry = self.entry("/sbin/launchd")
        for bad in ("04755", "02755", "0777", "0666", "0750", 493):
            with self.subTest(mode=bad):
                entry["mode"] = bad
                self.reject("mode")
        entry["mode"] = "0644"
        self.reject("mode 0755")

    def test_directory_sticky_tmp_and_no_other_world_writable_directory(self) -> None:
        self.raw["entries"].extend([
            {"type": "dir", "path": "/private", "mode": "0755"},
            {"type": "dir", "path": "/private/var", "mode": "0700"},
            {"type": "dir", "path": "/private/var/tmp", "mode": "01777"},
        ])
        self.run_stage()
        self.assertEqual(stat.S_IMODE((self.output / "private/var/tmp").stat().st_mode), 0o1777)
        self.output = self.base / "other-root"
        self.entry("/private/var/tmp")["mode"] = "0755"
        self.reject("01777 directory")
        self.entry("/private/var/tmp")["mode"] = "01777"
        self.entry("/usr")["mode"] = "01777"
        self.reject("only for /private/var/tmp")

    def test_unknown_fields_types_versions_and_duplicate_json_keys(self) -> None:
        self.raw["unexpected"] = True
        self.reject("unknown manifest fields")
        del self.raw["unexpected"]
        self.entry("/dev")["unexpected"] = True
        self.reject("unknown dir fields")
        del self.entry("/dev")["unexpected"]
        self.entry("/dev")["type"] = "device"
        self.reject("unsupported entry type")
        self.entry("/dev")["type"] = "dir"
        for version in (True, 2, "1"):
            with self.subTest(version=version):
                self.raw["version"] = version
                self.reject("version")
        self.manifest.write_text('{"version":1,"version":1}', encoding="utf-8")
        with self.assertRaisesRegex(stage.StageError, "duplicate JSON"):
            stage.stage_manifest(self.manifest, self.output)

    def test_manifest_private_regular_utf8_json_and_bounded_size(self) -> None:
        for data, message in ((b"\xff", "UTF-8"), (b"[]", "top level"), (b'{"version":NaN}', "non-JSON")):
            with self.subTest(data=data):
                self.manifest.write_bytes(data)
                with self.assertRaisesRegex(stage.StageError, message):
                    stage.stage_manifest(self.manifest, self.output)
        self.manifest.write_bytes(b" " * (stage.MAX_MANIFEST_BYTES + 1))
        with self.assertRaisesRegex(stage.StageError, "manifest exceeds"):
            stage.stage_manifest(self.manifest, self.output)
        self.write_manifest()
        link = self.base / "manifest-link"
        link.symlink_to(self.manifest.name)
        with self.assertRaises(stage.StageError):
            stage.stage_manifest(link, self.output)

    def test_budget_explicit_payload_volume_hard_ceiling_and_metadata(self) -> None:
        original = copy.deepcopy(self.raw)
        for change, message in (
            ({"max_payload_bytes": None}, "max_payload_bytes"),
            ({"max_payload_bytes": True}, "max_payload_bytes"),
            ({"max_volume_bytes": 33 * stage.MIB}, "hard ceiling"),
            ({"max_volume_bytes": True}, "max_volume_bytes"),
            ({"max_volume_bytes": stage.MIN_METADATA_BYTES - 1, "max_payload_bytes": 0}, "metadata reserve"),
            ({"max_payload_bytes": stage.DEFAULT_VOLUME_BYTES}, "metadata reserve"),
            ({"max_payload_bytes": 50}, "file size|sum of file sizes"),
        ):
            with self.subTest(change=change):
                self.raw = copy.deepcopy(original)
                self.raw.update(change)
                self.reject(message)
        self.raw = original
        self.raw.pop("max_payload_bytes")
        self.reject("max_payload_bytes")

    def test_sum_payload_budget_and_32mib_boundary(self) -> None:
        total = sum(e.get("size", 0) for e in self.raw["entries"])
        self.raw["max_payload_bytes"] = total - 1
        self.reject("sum of file sizes")
        self.raw["max_payload_bytes"] = total
        self.raw["max_volume_bytes"] = stage.MAX_VOLUME_BYTES
        self.assertEqual(self.run_stage()["max_volume_bytes"], 32 * stage.MIB)

    def test_macho_requires_arm32_little_endian_and_correct_filetype(self) -> None:
        for data in (b"short", macho(2, cpu=7, dylinker=b"/usr/lib/dyld"),
                     macho(2, magic=0xCEFAEDFE, dylinker=b"/usr/lib/dyld"),
                     macho(2, magic=0xFEEDFACF, dylinker=b"/usr/lib/dyld"),
                     macho(7, dylinker=b"/usr/lib/dyld")):
            with self.subTest(data=data[:16].hex()):
                self.replace_launchd(data)
                self.reject("Mach-O")

    def test_launchd_load_dylinker_exact_path_count_and_bounded_string(self) -> None:
        for data in (macho(2), macho(2, dylinker=b"/other/dyld"),
                     macho(2, dylinker=b"x" * 33),
                     macho(2, commands=struct.pack("<3I", 0xE, 16, 12) + b"xxxx"),
                     macho(2, commands=struct.pack("<3I", 0xE, 16, 4) + b"xxx\0")):
            with self.subTest(data=data.hex()):
                self.replace_launchd(data)
                self.reject("DYLINKER|dylinker")
        command = macho(2, dylinker=b"/usr/lib/dyld")[28:]
        self.replace_launchd(macho(2, commands=command + command, ncmds=2))
        self.reject("exactly one")

    def test_macho_load_command_region_and_counts_bounded(self) -> None:
        for command in (struct.pack("<2I", 1, 0), struct.pack("<2I", 1, 9),
                        struct.pack("<2I", 1, 100)):
            with self.subTest(command=command.hex()):
                self.replace_launchd(macho(2, commands=command))
                self.reject("load-command")
        for count, length, message in ((4097, 0, "bounds"), (1, stage.MIB + 1, "bounds"),
                                       (1, 8, "truncated"), (1, 0, "truncated")):
            with self.subTest(count=count, length=length):
                self.replace_launchd(struct.pack("<7I", 0xFEEDFACE, 12, 0, 2, count, length, 0))
                self.reject(message)

    def test_dyld_filetype_and_no_recursive_dylinker(self) -> None:
        entry = self.entry("/usr/lib/dyld")
        data = macho(7, dylinker=b"/usr/lib/dyld")
        Path(entry["source"]).write_bytes(data)
        entry.update(size=len(data), sha256=hashlib.sha256(data).hexdigest())
        self.reject("must not request another")

    def test_required_files_missing_directory_and_symlink_to_directory_rejected(self) -> None:
        self.raw["entries"].append({"type": "symlink", "path": "/lib", "target": "usr/lib"})
        for required in ("/missing.dylib", "/usr/lib", "/lib", "relative"):
            with self.subTest(required=required):
                with self.assertRaises(stage.StageError):
                    self.run_stage(required=(required,))
                self.assertFalse(self.output.exists())

    def test_existing_output_file_directory_or_symlink_never_changed(self) -> None:
        self.output.write_bytes(b"untouched")
        with self.assertRaisesRegex(stage.StageError, "already exists"):
            self.run_stage()
        self.assertEqual(self.output.read_bytes(), b"untouched")
        other = self.base / "existing-dir"
        other.mkdir()
        (other / "sentinel").write_bytes(b"sentinel")
        with self.assertRaisesRegex(stage.StageError, "already exists"):
            self.run_stage(output=other)
        self.assertEqual((other / "sentinel").read_bytes(), b"sentinel")
        link = self.base / "existing-link"
        link.symlink_to("absent")
        with self.assertRaisesRegex(stage.StageError, "already exists"):
            self.run_stage(output=link)
        self.assertTrue(link.is_symlink())

    def test_output_ancestors_no_symlinks_parent_must_exist(self) -> None:
        link = self.base / "parent-link"
        link.symlink_to(self.base, target_is_directory=True)
        with self.assertRaises(stage.StageError):
            self.run_stage(output=link / "new-root")
        with self.assertRaises(stage.StageError):
            self.run_stage(output=self.base / "missing" / "root")
        self.assertFalse(self.output.exists())
        self.assertFalse((self.base / "missing").exists())

    def test_output_root_home_and_noncanonical_paths_rejected(self) -> None:
        for bad in ("/", str(Path.home()), "relative", str(self.base) + "/a/../root"):
            with self.subTest(output=bad):
                with self.assertRaises(stage.StageError):
                    self.run_stage(output=bad)
        self.assertFalse(self.output.exists())

    def test_input_output_overlap_rejected_before_creation(self) -> None:
        self.entry("/sbin/launchd")["source"] = str(self.output / "input")
        self.reject("overlap")
        self.write_manifest()
        with self.assertRaisesRegex(stage.StageError, "overlap"):
            stage.stage_manifest(self.output / "private.json", self.output)

    def test_changed_source_during_validation_is_rejected_without_output(self) -> None:
        self.write_manifest()
        original = stage._read_source_chunk
        changed = False

        def mutate(fd: int, count: int) -> bytes:
            nonlocal changed
            data = original(fd, count)
            if data and not changed:
                changed = True
                source = Path(self.entry("/sbin/launchd")["source"])
                source.write_bytes(source.read_bytes() + b"mutation")
            return data

        with mock.patch.object(stage, "_read_source_chunk", side_effect=mutate):
            with self.assertRaisesRegex(stage.StageError, "grew|changed"):
                stage.stage_manifest(self.manifest, self.output)
        self.assertFalse(self.output.exists())

    def test_source_changed_between_validation_and_copy_leaves_diagnosed_private_partial(self) -> None:
        self.write_manifest()
        original = stage._read_verify_source
        changed = False

        def mutate(entry: dict, expected=None, output_fd=None):
            nonlocal changed
            if output_fd is not None and not changed:
                changed = True
                source = Path(entry["source"])
                data = source.read_bytes()
                source.write_bytes(bytes([data[0] ^ 1]) + data[1:])
            return original(entry, expected, output_fd)

        with mock.patch.object(stage, "_read_verify_source", side_effect=mutate):
            with self.assertRaisesRegex(stage.StageError, "source changed.*partial staging directory left"):
                stage.stage_manifest(self.manifest, self.output)
        self.assertTrue(self.output.is_dir())
        self.assertEqual(stat.S_IMODE(self.output.stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE((self.output / "sbin/launchd").stat().st_mode), 0o600)

    def test_bytes_copied_are_hashed_even_if_source_identity_is_unchanged(self) -> None:
        self.write_manifest()
        original = stage._read_source_chunk
        reads = 0

        def corrupt_copy(fd: int, count: int) -> bytes:
            nonlocal reads
            data = original(fd, count)
            if data:
                reads += 1
                if reads == 3:  # Two prevalidation files, then first staged copy.
                    return bytes([data[0] ^ 1]) + data[1:]
            return data

        with mock.patch.object(stage, "_read_source_chunk", side_effect=corrupt_copy):
            with self.assertRaisesRegex(stage.StageError, "SHA-256 mismatch.*partial staging directory left"):
                stage.stage_manifest(self.manifest, self.output)
        self.assertTrue(self.output.exists())
        self.assertEqual(stat.S_IMODE(self.output.stat().st_mode), 0o700)

    def test_destination_readback_catches_corrupted_output_write(self) -> None:
        self.write_manifest()
        original = os.write
        corrupted = False

        def corrupt_write(fd: int, data) -> int:
            nonlocal corrupted
            if data and not corrupted:
                corrupted = True
                return original(fd, bytes([data[0] ^ 1]) + bytes(data[1:]))
            return original(fd, data)

        with mock.patch.object(stage.os, "write", side_effect=corrupt_write):
            with self.assertRaisesRegex(stage.StageError, "staged file changed or SHA-256 mismatch.*partial staging directory left"):
                stage.stage_manifest(self.manifest, self.output)
        self.assertEqual(stat.S_IMODE(self.output.stat().st_mode), 0o700)

    def test_cli_failure_code_diagnostic_and_no_success_report(self) -> None:
        self.raw["version"] = 9
        self.write_manifest()
        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            code = stage.main([str(self.manifest), "--output-staging", str(self.output)])
        self.assertEqual(code, 2)
        self.assertEqual(stdout.getvalue(), "")
        self.assertIn("stage_ram_root: manifest version", stderr.getvalue())
        self.assertFalse(self.output.exists())

    def test_labels_reported_not_authenticity_proofs_and_no_filename_policy(self) -> None:
        self.raw.update(root_name="owned-root-1", source_provenance="user-reviewed private inputs")
        entry = self.add_file("/usr/lib/ios7lab-ordinary-name", b"DYLD_INSERT_LIBRARIES text is unexecuted data")
        entry["source_provenance"] = "opaque audit label"
        report = self.run_stage()
        self.assertEqual(report["root_name"], "owned-root-1")
        self.assertEqual(report["source_provenance"], "user-reviewed private inputs")
        self.assertIn("do not prove Apple authenticity", " ".join(report["warnings"]))
        self.assertTrue((self.output / "usr/lib/ios7lab-ordinary-name").is_file())


if __name__ == "__main__":
    unittest.main()
