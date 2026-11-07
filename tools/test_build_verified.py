#!/usr/bin/env python3
"""Fault-injection tests for the verified build driver; no cross compiler/device needed."""
import contextlib
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

SPEC = importlib.util.spec_from_file_location("build_verified", Path(__file__).with_name("build_verified.py"))
BUILDER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(BUILDER)


class VerifiedBuildTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name).resolve()
        self.addCleanup(self.tmp.cleanup)
        (self.root / "out").mkdir()
        self.worker = self.root / "worker.py"
        self.worker.write_text("""import os, pathlib, sys, time
mode, output = sys.argv[1:3]
p = pathlib.Path(output)
if mode == 'fail':
    p.write_bytes(b'partial')
    print('compiler exited 23')
    sys.exit(23)
if mode == 'refusal':
    p.write_bytes(b'partial')
    print('REFUSING: bad configuration')
    sys.exit(0)
if mode == 'fake-success':
    print('qcdt: abcdef but output not regenerated')
    sys.exit(0)
if mode == 'wait':
    time.sleep(10)
if mode == 'mutate':
    pathlib.Path('input.c').write_text('changed')
if mode == 'assembly-fail':
    p.write_bytes(b'fresh declared assembly output')
    print('  FAIL machine_routines_asm compiler error')
    print('assemble: 2 ok, 1 failed; 0 files translated')
    sys.exit(0)
if mode == 'corrupt-check':
    p.write_bytes(b'ANDROID!changed-after-validation')
    sys.exit(0)
if mode == 'change-source-check':
    pathlib.Path('worker.py').write_text('changed by validator')
    sys.exit(0)
if mode == 'env':
    p.write_text(str(os.getenv('STAGE90_STALE', '<absent>'))+' '+os.environ['XNU_TREE'])
else:
    p.write_bytes(b'ANDROID!entry-image-bytes')
print('FAIL: 0')
""", encoding="utf-8")
        self.profile = {"version": 1, "env": {"STAGE90_XNU_HDD_WRITE": "0"},
                        "inputs": ["worker.py"], "stages": [], "image": "out/boot.img",
                        "android_boot_header": True}

    def stage(self, name, mode="ok", output="out/boot.img", timeout=2):
        return {"name": name, "argv": [sys.executable, "worker.py", mode, output],
                "outputs": [output], "timeout_s": timeout}

    def execute(self):
        path = self.root / "profile.json"
        path.write_text(json.dumps(self.profile), encoding="utf-8")
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            rc, run = BUILDER.execute(path, self.root, self.root / "out/verified-builds")
        record = json.loads((run / "result.json").read_text())
        return rc, run, record

    def assert_refused(self, needle):
        rc, run, record = self.execute()
        self.assertEqual(rc, 1)
        self.assertEqual(record["status"], "failed")
        self.assertIn(needle, record["error"])
        self.assertFalse((run / "verified-image.img").exists())
        return record

    def test_happy_path_publishes_exact_image_and_profile(self):
        self.profile["stages"] = [self.stage("entry", output="out/entry.bin"), self.stage("payload")]
        self.profile["embedded"] = [{"container": "out/boot.img", "payload": "out/entry.bin"}]
        rc, run, record = self.execute()
        self.assertEqual(rc, 0)
        self.assertEqual([s["returncode"] for s in record["stages"]], [0, 0])
        self.assertEqual((run / "verified-image.img").read_bytes(), (self.root / "out/boot.img").read_bytes())
        self.assertEqual(record["profile_sha256"], hashlib.sha256((run / "profile.json").read_bytes()).hexdigest())

    def test_nonzero_exit_stops_before_next_stage(self):
        self.profile["stages"] = [self.stage("entry", "fail", "out/entry.bin"), self.stage("payload")]
        record = self.assert_refused("exited 23")
        self.assertEqual(len(record["stages"]), 1)
        self.assertFalse((self.root / "out/boot.img").exists())

    def test_refusal_even_if_bad_wrapper_returns_zero(self):
        self.profile["stages"] = [self.stage("entry", "refusal", "out/entry.bin"), self.stage("payload")]
        record = self.assert_refused("REFUSING")
        self.assertEqual(len(record["stages"]), 1)

    def test_stale_file_and_printed_hash_are_not_success(self):
        (self.root / "out/boot.img").write_bytes(b"old working image")
        self.profile["stages"] = [self.stage("payload", "fake-success")]
        self.assert_refused("stale output")
        self.assertEqual((self.root / "out/boot.img").read_bytes(), b"old working image")

    def test_timeout_is_failure(self):
        self.profile["stages"] = [self.stage("payload", "wait", timeout=0.05)]
        self.assert_refused("timed out")

    def test_declared_input_cannot_change_mid_build(self):
        (self.root / "input.c").write_text("initial")
        self.profile["inputs"].append("input.c")
        self.profile["stages"] = [self.stage("payload", "mutate")]
        self.assert_refused("input changed during build")

    def test_input_hashes_and_expanded_environment(self):
        self.profile["env"]["XNU_TREE"] = "{repo_root}/xnu"
        self.profile["android_boot_header"] = False
        self.profile["stages"] = [self.stage("payload", "env")]
        with mock.patch.dict(os.environ, {"STAGE90_STALE": "1"}):
            rc, _, record = self.execute()
        self.assertEqual(rc, 0)
        self.assertEqual(record["env"]["XNU_TREE"], str(self.root / "xnu"))
        self.assertEqual((self.root / "out/boot.img").read_text(), "<absent> " + str(self.root / "xnu"))
        self.assertEqual(len(record["inputs"]), 1)

    def test_embedding_exact_payload_required(self):
        self.profile["stages"] = [self.stage("entry", output="out/entry.bin"), self.stage("payload")]
        self.profile["embedded"] = [{"container": "out/entry.bin", "payload": "worker.py"}]
        self.assert_refused("fresh stage artifacts")

    def test_image_must_be_declared_stage_output(self):
        (self.root / "out/boot.img").write_bytes(b"old")
        self.profile["stages"] = [self.stage("entry", output="out/entry.bin")]
        self.assert_refused("final image was not")

    def test_escape_repository_refused(self):
        self.profile["stages"] = [self.stage("payload", output="../escape")]
        self.assert_refused("escapes repository")

    def test_physical_write_gate_refused(self):
        self.profile["env"]["STAGE90_XNU_HDD_WRITE"] = "1"
        self.profile["stages"] = [self.stage("payload")]
        with self.assertRaisesRegex(BUILDER.BuildError, "write path"):
            self.execute()

    def test_unsafe_write_define_refused(self):
        self.profile["env"]["XNU_KERNEL_EXTRA_DEFINES"] = "-DSTAGE90_XNU_HDD_WRITE=1"
        self.profile["stages"] = [self.stage("payload")]
        with self.assertRaisesRegex(BUILDER.BuildError, "write define"):
            self.execute()

    def test_device_command_refused(self):
        self.profile["stages"] = [{"name": "oops", "argv": ["fastboot", "boot", "out/boot.img"],
                                   "outputs": ["out/boot.img"]}]
        with self.assertRaisesRegex(BUILDER.BuildError, "device tools"):
            self.execute()

    def test_shell_pipeline_refused(self):
        self.profile["stages"] = [{"name": "oops", "argv": ["bash", "-c", "false | tail -2"],
                                   "outputs": ["out/boot.img"]}]
        with self.assertRaisesRegex(BUILDER.BuildError, "shell pipeline"):
            self.execute()

    def test_assembly_failure_without_colon_stops_next_stage(self):
        self.profile["stages"] = [self.stage("assembly", "assembly-fail", "out/entry.bin"), self.stage("payload")]
        record = self.assert_refused("FAIL machine_routines_asm")
        self.assertEqual(len(record["stages"]), 1)

    def test_repository_lock_independent_of_runs_directory(self):
        self.profile["stages"] = [self.stage("payload")]
        path = self.root / "profile.json"
        path.write_text(json.dumps(self.profile))
        with (self.root / "out/.verified-build.lock").open("a+") as lock:
            BUILDER.fcntl.flock(lock, BUILDER.fcntl.LOCK_EX | BUILDER.fcntl.LOCK_NB)
            with self.assertRaisesRegex(BUILDER.BuildError, "another verified build"):
                BUILDER.execute(path, self.root, self.root / "out/other-runs")

    def test_successful_checker_cannot_modify_verified_image(self):
        self.profile["stages"] = [self.stage("payload")]
        self.profile["checks"] = [{"argv": [sys.executable, "worker.py", "corrupt-check", "out/boot.img"]}]
        self.assert_refused("validated artifact changed after checks")

    def test_successful_checker_cannot_modify_verified_entry(self):
        self.profile["stages"] = [self.stage("entry", output="out/entry.bin"), self.stage("payload")]
        self.profile["embedded"] = [{"container": "out/boot.img", "payload": "out/entry.bin"}]
        self.profile["checks"] = [{"argv": [sys.executable, "worker.py", "corrupt-check", "out/entry.bin"]}]
        self.assert_refused("validated artifact changed after checks")

    def test_successful_checker_cannot_modify_source_input(self):
        self.profile["stages"] = [self.stage("payload")]
        self.profile["checks"] = [{"argv": [sys.executable, "worker.py", "change-source-check", "out/irrelevant"]}]
        self.assert_refused("input changed after artifact checks")

    def test_later_stage_cannot_change_earlier_output(self):
        stage = self.stage("payload", "corrupt-check", "out/entry.bin")
        stage["outputs"] = ["out/boot.img"]
        self.profile["stages"] = [self.stage("entry", output="out/entry.bin"), stage]
        self.assert_refused("changed earlier stage output")

    def test_declared_intermediate_can_be_consumed(self):
        stage = self.stage("payload")
        stage["consumes"] = ["out/entry.bin"]
        self.profile["stages"] = [self.stage("entry", output="out/entry.bin"), stage]
        rc, _, record = self.execute()
        self.assertEqual(rc, 0)
        self.assertEqual([item["path"] for item in record["artifacts"]], ["out/boot.img"])
        stage["consumes"] = ["out/undeclared.bin"]
        self.assert_refused("consumes undeclared output")

    def test_pinned_manifest_content_verified(self):
        artifact = self.root / "kernel.o"
        artifact.write_bytes(b"pinned kernel object")
        manifest = self.root / "kernel-pool.json"
        manifest.write_text(json.dumps([{"path": "kernel.o", "sha256": BUILDER.digest(artifact),
                                         "size": artifact.stat().st_size}]))
        self.profile["input_manifests"] = ["kernel-pool.json"]
        self.profile["stages"] = [self.stage("payload")]
        rc, _, record = self.execute()
        self.assertEqual(rc, 0)
        self.assertTrue(any(i["path"] == "kernel.o" for i in record["inputs"]))
        artifact.write_bytes(b"different kernel object")
        self.assert_refused("pinned input differs")

    def test_corrupt_publication_does_not_get_verified_filename(self):
        self.profile["stages"] = [self.stage("payload")]
        original = BUILDER.shutil.copyfile

        def corrupt(source, destination):
            original(source, destination)
            Path(destination).write_bytes(b"corrupt")

        with mock.patch.object(BUILDER.shutil, "copyfile", side_effect=corrupt):
            self.assert_refused("image changed during publication")

    def test_artifact_checker_failure_blocks_publication(self):
        self.profile["stages"] = [self.stage("payload")]
        self.profile["checks"] = [{"argv": [sys.executable, "worker.py", "fail", "out/check.tmp"]}]
        self.assert_refused("artifact check 1 failed")

    def test_artifact_checker_shell_command_refused(self):
        self.profile["stages"] = [self.stage("payload")]
        self.profile["checks"] = [{"argv": ["bash", "-c", "false | true"]}]
        with self.assertRaisesRegex(BUILDER.BuildError, "artifact checks"):
            self.execute()

    def test_unsafe_stage_write_override_refused(self):
        stage = self.stage("payload")
        stage["env"] = {"STAGE90_XNU_HDD_WRITE": "1"}
        self.profile["stages"] = [stage]
        with self.assertRaisesRegex(BUILDER.BuildError, "write path"):
            self.execute()

    def test_zero_failure_count_is_not_a_failure(self):
        log = self.root / "log.txt"
        log.write_text("FAIL:   0\ncheck: PASS\n")
        self.assertIsNone(BUILDER.diagnostic(log))
        log.write_text("FAIL:   1\n")
        self.assertEqual(BUILDER.diagnostic(log), "FAIL:   1")
        log.write_text("  C++ fail: 2\n")
        self.assertEqual(BUILDER.diagnostic(log), "C++ fail: 2")
        log.write_text("  timed out (60s): 1\n")
        self.assertEqual(BUILDER.diagnostic(log), "timed out (60s): 1")
        log.write_text("assemble: 2 ok, 1 failed; 0 files translated\n")
        self.assertEqual(BUILDER.diagnostic(log), "assemble: 2 ok, 1 failed; 0 files translated")


if __name__ == "__main__":
    unittest.main(verbosity=2)
