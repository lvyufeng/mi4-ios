#!/usr/bin/env python3
"""Immutable host-only tests; no device/production callback or GPL compilation."""
import argparse
import hashlib
import os
from pathlib import Path
import re
import shlex
import subprocess
import tempfile

FILES = ("src/rpm_rbcpr_snapshot.c", "src/rpm_rbcpr_snapshot.h",
         "tools/fixtures/rpm_rbcpr_snapshot_harness.c", "tools/test_rpm_rbcpr_snapshot.py")
VENDOR = ("arch/arm/mach-msm/rpm_rbcpr_stats_v2.c",
          "arch/arm/boot/dts/msm8974-v2-pm.dtsi")


def check(condition, message):
    if not condition:
        raise RuntimeError(message)


def oracle(source, dt):
    # Original arithmetic for ARM32 AAPCS: no copied/compiled vendor structures.
    for name in ("RBCPR_NUM_RECMNDS", "RBCPR_NUM_CORNERS"):
        check(re.search(r"#define\s+" + name + r"\s+3\b", source), name)
    check("#define RBCPR_STATS_MAX_SIZE SZ_2K" in source, "2K cap changed")
    check("uint64_t timestamp;" in source and "uint32_t microvolts;" in source,
          "recommendation field widths changed")
    check('compatible = "qcom,rpmrbcpr-stats";' in dt, "DT compatible changed")
    check(re.search(r"reg\s*=\s*<0xfc000000\s+0x1a0000>", dt), "DT range")
    check("qcom,start-offset = <0x190010>;" in dt, "DT slot")
    align8 = lambda n: (n + 7) & ~7
    recommendation = align8(4) + 8
    corner = align8(5 * 4) + 3 * recommendation
    rail = align8(8 + 3 * corner + 4 * 4)
    volts = [8 + 8 + 4 + i * corner for i in range(3)]
    current = 8 + 8 + 3 * corner
    check((recommendation, corner, rail, volts, current, current + 4) ==
          (16, 72, 240, [0x14, 0x5c, 0xa4], 0xe8, 0xec), "numeric oracle")
    print("numeric oracle: ARM32 align8 rec16/corner72/rail240; inline CX+8; shape only")


def command(argv):
    result = subprocess.run(argv, text=True, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, timeout=90)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--cc", default="clang")
    parser.add_argument("--sanitize", action="store_true")
    parser.add_argument("--vendor-root", type=Path,
                        help="public isolated android kernel root; numeric source checks only")
    args = parser.parse_args()
    root = args.repo_root.resolve()
    vendor = args.vendor_root or root / "external/android_kernel_xiaomi_cancro"
    paths = [root / f for f in FILES] + [vendor / f for f in VENDOR]
    before = {p: p.read_bytes() for p in paths}
    hashes = {p: hashlib.sha256(data).hexdigest() for p, data in before.items()}
    try:
        oracle(before[paths[4]].decode(), before[paths[5]].decode())
        source = before[paths[0]].decode()
        check(sum(data.count(b"\n") for data in list(before.values())[:4]) <= 650,
              "four-file line budget exceeded")
        env = os.environ.copy()
        env["ASAN_OPTIONS"] = "detect_leaks=0:abort_on_error=0"
        with tempfile.TemporaryDirectory(prefix="mi4-rbcpr-host-") as tmp:
            tmp = Path(tmp)
            # All compiles use frozen inputs, never the live source paths.
            (tmp / "rpm_rbcpr_snapshot.h").write_bytes(before[paths[1]])
            fixture = tmp / "fixture.c"
            fixture.write_bytes(before[paths[2]])
            cc = shlex.split(args.cc)
            flags = ["-std=c11", "-O0", "-Wall", "-Wextra", "-Werror", "-pedantic"]
            if args.sanitize:
                flags += ["-fsanitize=address,undefined", "-fno-omit-frame-pointer"]
            mutations = [
                ("pointer bounds", "p >= 0x190014u", "p >= 0x190010u"),
                ("metadata", "&& value != 3u", "&& value != 3u && false"),
                ("counter consistency", "step == 10 && value != s->status_before",
                 "step == 10 && false && value != s->status_before"),
                ("cross-pass comparison", "if (!same_payload(", "if (false && !same_payload("),
                ("callback address injection", "0x14u, 0x5cu", "0x18u, 0x5cu"),
            ]
            for index, (name, old, new) in enumerate([("baseline", "", "")] + mutations):
                text = source
                if old:
                    check(source.count(old) == 1, "mutation anchor: " + name)
                    text = source.replace(old, new)
                cfile, exe = tmp / (str(index) + ".c"), tmp / (str(index) + ".out")
                cfile.write_text(text)
                built = command(cc + flags + ["-I", str(tmp), str(cfile), str(fixture), "-o", str(exe)])
                check(built.returncode == 0, "compile failed " + name + ": " + built.stderr)
                result = subprocess.run([str(exe)], env=env, text=True,
                                        stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=90)
                if index == 0:
                    check(result.returncode == 0 and not result.stderr and re.fullmatch(
                        r"host-only: [0-9]+ cases, [0-9]+ CHECK assertions; "
                        r"no hardware/freshness/power claim\n", result.stdout),
                        "baseline failed: " + result.stderr)
                    print(result.stdout.strip())
                else:
                    check(result.returncode == 1 and not result.stdout and re.fullmatch(
                        r"CHECK line [0-9]+: [^\n]+\n", result.stderr),
                        "mutant not assertion-killed: " + name + ": " + result.stderr)
                    print("mutation killed by CHECK exit1: " + name)
                if index == 5:
                    stopped = subprocess.run([str(exe), "injected-address"], env=env, text=True,
                                             stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=90)
                    check(stopped.returncode == 0 and not stopped.stderr and stopped.stdout ==
                          "address injection: stop at rejected callback, 46 assertions\n",
                          "address-fault prefix: " + stopped.stderr)
                    print(stopped.stdout.strip())
        print("PASS: 5/5 assertion-killed mutants; callback faults stop, poison ignored")
    finally:
        for path, original in before.items():
            check(path.read_bytes() == original, "immutable input changed: " + str(path))
        print("immutable C/H/fixture/script/vendor inputs rechecked")
        for path in paths[:4]:
            print("SHA256", hashes[path], path.relative_to(root))


if __name__ == "__main__":
    main()
