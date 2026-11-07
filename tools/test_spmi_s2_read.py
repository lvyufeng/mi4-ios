#!/usr/bin/env python3
"""Strict actual-C tests; no production import, hardware or device access."""
import argparse
import hashlib
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile

RELATIVE_FILES = (
    "src/spmi_s2_read.c", "src/spmi_s2_read.h",
    "tools/test_spmi_s2_read.py", "tools/fixtures/spmi_s2_read_harness.c",
    "external/android_kernel_xiaomi_cancro/drivers/spmi/spmi-pmic-arb.c",
    "external/android_kernel_xiaomi_cancro/drivers/regulator/qpnp-regulator.c")
VENDOR = ["91660550640f952c2b8630cfbbe2fbeee423c3178b29a83263c758f78b56fadc",
          "398116398856c841d4d8bdc702f813538b1f67bf2c2525426c1c066089a089bc"]

def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--cc", default="clang", help="compiler name or path; no fallback")
    sanitizer = parser.add_mutually_exclusive_group()
    sanitizer.add_argument("--sanitize", dest="sanitize", action="store_true")
    sanitizer.add_argument("--no-sanitize", dest="sanitize", action="store_false")
    parser.set_defaults(sanitize=True)
    args = parser.parse_args()
    root = args.repo_root.resolve()
    files = [root / p for p in RELATIVE_FILES]
    snapshot = {p: p.read_bytes() for p in files}
    before = {p: hashlib.sha256(data).hexdigest() for p, data in snapshot.items()}
    try:
        assert [before[p] for p in files[-2:]] == VENDOR, "vendor oracle drift"
        cc = shutil.which(args.cc)
        assert cc, f"requested compiler unavailable: {args.cc}"
        flags = ["-std=c11", "-pedantic-errors", "-Wall", "-Wextra", "-Werror",
                 "-Wconversion", "-Wshadow", "-Wstrict-prototypes", "-O1"]
        if args.sanitize:
            flags += ["-fsanitize=address,undefined", "-fno-omit-frame-pointer"]
        print("COMPILER", cc, "SANITIZE", args.sanitize)
        env = dict(os.environ, ASAN_OPTIONS="detect_leaks=0:halt_on_error=1",
                   UBSAN_OPTIONS="halt_on_error=1:print_stacktrace=1")
        source = snapshot[files[0]].decode("utf-8")
        mutations = [
            ("wrong-SID", "0x08517401u", "0x08417401u"),
            ("WRITE-opcode", "0x08517401u", "0x00517401u"),
            ("continue-DENIED", "if (o->completion_status[t] > 1u)",
             "if (o->completion_status[t] > 1u && (o->completion_status[t] & 4u) == 0u)"),
            ("timeout-continue", "if (p == 99u) return fail(&r, SPMI_S2_TIMEOUT);",
             "if (p == 99u) break;"),
            ("bypass-writefault", "if (rc != 0) { (void)fail(r, SPMI_S2_WRITE_FAILED); return false; }",
             "if (rc != 0) { (void)fail(r, SPMI_S2_WRITE_FAILED); return true; }")]
        with tempfile.TemporaryDirectory(prefix="spmi-s2-host-") as directory:
            temp = Path(directory)
            (temp / "spmi_s2_read.h").write_bytes(snapshot[files[1]])
            fixture = temp / "spmi_s2_read_harness.c"
            fixture.write_bytes(snapshot[files[3]])
            def build(text, name):
                src, exe = temp / (name + ".c"), temp / name
                src.write_text(text)
                cmd = [cc, *flags, "-I", str(temp), str(src), str(fixture), "-o", str(exe)]
                result = subprocess.run(cmd, text=True, capture_output=True, timeout=30)
                assert result.returncode == 0, result.stderr
                return exe
            exe = build(source, "golden")
            result = subprocess.run([str(exe)], text=True, capture_output=True, env=env, timeout=30)
            assert result.returncode == 0 and result.stdout.startswith("PASS cases="), result.stderr
            print(result.stdout.strip())
            for name, old, new in mutations:
                assert source.count(old) == 1, (name, "mutation anchor")
                exe = build(source.replace(old, new), name)
                result = subprocess.run([str(exe)], text=True, capture_output=True, env=env, timeout=30)
                assert result.returncode == 1, (name, result.returncode, result.stderr)
                assert re.fullmatch(r"CHECK:[^\r\n]+\n?", result.stderr), (name, result.stderr)
                assert "Sanitizer" not in result.stderr and "runtime error" not in result.stderr
                print("MUTANT", name, "CHECK exit=1 (compiled, no crash)")
            negative = temp / "negative.c"
            negative.write_text('_Static_assert(0, "intentional compiler negative");\n')
            result = subprocess.run([cc, *flags, "-c", str(negative), "-o", str(temp / "negative.o")],
                                    text=True, capture_output=True, timeout=30)
            assert result.returncode != 0 and "intentional compiler negative" in result.stderr
            print("COMPILER-NEGATIVE rejected; not counted as mutant")
    finally:
        assert {p: digest(p) for p in files} == before, "immutable snapshot mismatch"
        for p in files:
            print("SHA256", before[p], p.relative_to(root))
        print("IMMUTABLE 4 deliverables + 2 vendor sources unchanged")

if __name__ == "__main__":
    main()
