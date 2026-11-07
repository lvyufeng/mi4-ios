#!/usr/bin/env python3
"""Compile/run the original offline TRB codec; no device, network or MMIO.

Reads vendor core.h only as a numerical oracle, never compiles vendor code.
Creates retained artifacts in a fresh system temporary directory, not the repo.
Compiles one frozen C/header/harness snapshot and checks inputs again in finally.
Use --cc gcc with a real GNU GCC installation; Apple's gcc is reported as Clang.
"""
import argparse
import hashlib
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile


# Restricted textual arithmetic contracts, not supplier function implementations.
# Function-like macros below are numerical field expressions only.
VENDOR = {
    "DWC3_TRB_SIZE_MASK": (None, "(0x00ffffff)"),
    "DWC3_TRB_SIZE_LENGTH": ("n", "((n)&DWC3_TRB_SIZE_MASK)"),
    "DWC3_TRB_SIZE_PCM1": ("n", "(((n)&0x03)<<24)"),
    "DWC3_TRB_SIZE_TRBSTS": ("n", "(((n)&(0x0f<<28))>>28)"),
    "DWC3_TRBSTS_OK": (None, "0"),
    "DWC3_TRBSTS_MISSED_ISOC": (None, "1"),
    "DWC3_TRBSTS_SETUP_PENDING": (None, "2"),
    "DWC3_TRB_STS_XFER_IN_PROG": (None, "4"),
    "DWC3_TRB_CTRL_HWO": (None, "(1<<0)"),
    "DWC3_TRB_CTRL_LST": (None, "(1<<1)"),
    "DWC3_TRB_CTRL_CHN": (None, "(1<<2)"),
    "DWC3_TRB_CTRL_CSP": (None, "(1<<3)"),
    "DWC3_TRB_CTRL_TRBCTL": ("n", "(((n)&0x3f)<<4)"),
    "DWC3_TRB_CTRL_ISP_IMI": (None, "(1<<10)"),
    "DWC3_TRB_CTRL_IOC": (None, "(1<<11)"),
    "DWC3_TRBCTL_NORMAL": (None, "DWC3_TRB_CTRL_TRBCTL(1)"),
    "DWC3_TRBCTL_CONTROL_SETUP": (None, "DWC3_TRB_CTRL_TRBCTL(2)"),
    "DWC3_TRBCTL_CONTROL_STATUS2": (None, "DWC3_TRB_CTRL_TRBCTL(3)"),
    "DWC3_TRBCTL_CONTROL_STATUS3": (None, "DWC3_TRB_CTRL_TRBCTL(4)"),
    "DWC3_TRBCTL_CONTROL_DATA": (None, "DWC3_TRB_CTRL_TRBCTL(5)"),
}
CANDIDATE = {
    "DWC3_TRB_BYTES": 16,
    "DWC3_TRB_LENGTH_MAX": 0xFFFFFF,
    "DWC3_TRB_TYPE_NORMAL": 1,
    "DWC3_TRB_TYPE_SETUP": 2,
    "DWC3_TRB_TYPE_STATUS2": 3,
    "DWC3_TRB_TYPE_STATUS3": 4,
    "DWC3_TRB_TYPE_DATA": 5,
    "DWC3_TRB_FLAG_LAST": 2,
    "DWC3_TRB_FLAG_IOC": 2048,
    "DWC3_TRB_STATUS_OK": 0,
    "DWC3_TRB_STATUS_SETUP_PENDING": 2,
}
MUTANTS = {
    "publishes-hwo": (
        "((uint32_t)r.type << 4) | (uint32_t)r.flags",
        "((uint32_t)r.type << 4) | (uint32_t)r.flags | UINT32_C(1)"),
    "oversize-length": (
        "r.length > (int64_t)DWC3_TRB_LENGTH_MAX ||", ""),
    "unbounded-span": (
        "span->size > limit - span->base ||", ""),
    "wrong-setup-shape": (
        "r.type == DWC3_TRB_TYPE_SETUP && r.length != 8",
        "r.type == DWC3_TRB_TYPE_SETUP && r.length < 0"),
    "ignores-dma-high": (
        "if (load_le32(input + 4) != 0)",
        "if (false && load_le32(input + 4) != 0)"),
    "discards-trb-status": (
        "decoded.status = (uint8_t)(size >> 28);", "decoded.status = 0;"),
}


def oracle(data):
    text = data.decode("utf-8")
    clean = re.sub(r"/\*.*?\*/|//[^\n]*", "", text, flags=re.S)
    for name, (parameter, expected) in VENDOR.items():
        suffix = r"\(" + re.escape(parameter) + r"\)" if parameter else ""
        pattern = r"^\s*#\s*define\s+" + re.escape(name) + suffix + r"[ \t]+([^\n]+)$"
        matches = re.findall(pattern, clean, flags=re.M)
        if len(matches) != 1 or re.sub(r"\s+", "", matches[0]) != expected:
            raise ValueError(f"missing/ambiguous/changed vendor numerical field: {name}")
    layouts = re.findall(r"struct\s+dwc3_trb\s*\{([^}]*)\}", clean, flags=re.S)
    if len(layouts) != 1 or re.sub(r"\s+", "", layouts[0]) != \
            "u32bpl;u32bph;u32size;u32ctrl;":
        raise ValueError("vendor TRB four-word layout changed")
    return '\n'.join(f'_Static_assert({name} == {number}u, "{name}");'
                     for name, number in CANDIDATE.items()) + '\n'


def run(command, timeout=60):
    result = subprocess.run([str(x) for x in command], text=True,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            check=False, timeout=timeout)
    print("$", " ".join(str(x) for x in command), flush=True)
    if result.stdout:
        print(result.stdout, end="", flush=True)
    if result.stderr:
        print(result.stderr, file=sys.stderr, end="", flush=True)
    print(f"[exit code: {result.returncode}]", flush=True)
    return result


def require_success(command):
    result = run(command)
    if result.returncode:
        raise RuntimeError(f"command failed: {command[0]} (status {result.returncode})")
    return result.stdout


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", type=Path, default=Path(__file__).resolve().parent.parent)
    parser.add_argument("--vendor-core", type=Path)
    parser.add_argument("--cc", default="clang")
    parser.add_argument("--sanitize", action="store_true",
                        help="also execute actual C under AddressSanitizer/UBSan")
    args = parser.parse_args()
    root = args.repo_root.resolve(strict=True)
    paths = [root / relative for relative in (
        "src/dwc3_trb.c", "src/dwc3_trb.h", "tools/fixtures/dwc3_trb_harness.c")]
    for path in paths:
        if not path.is_file() or not path.resolve().is_relative_to(root):
            raise ValueError(f"missing or escaped candidate file: {path}")
    source, header, fixture = paths
    vendor = (args.vendor_core or root /
              "external/android_kernel_xiaomi_cancro/drivers/usb/dwc3/core.h").resolve(strict=True)
    script = Path(__file__).resolve(strict=True)
    tracked = tuple(dict.fromkeys((*paths, vendor, script)))
    frozen = {path: path.read_bytes() for path in tracked}
    try:
        assertions = oracle(frozen[vendor])  # Reject oracle drift before artifacts.
        compiler = shutil.which(args.cc)
        if compiler is None:
            raise ValueError(f"compiler not found: {args.cc}")
        version = require_success([compiler, "--version"])
        if "clang" in version.lower():
            family = "Clang (including gcc-named aliases)"
        elif "gcc" in version.lower() or "free software foundation" in version.lower():
            family = "GNU GCC"
        else:
            raise ValueError("--cc must identify as Clang or GNU GCC")
        print(f"Compiler family: {family}", flush=True)
        build = Path(tempfile.mkdtemp(prefix="dwc3-trb-"))
        print(f"Vendor core SHA256: {hashlib.sha256(frozen[vendor]).hexdigest()}", flush=True)
        print(f"Retained test artifacts: {build}", flush=True)
        # No compiled source/header is read live after this snapshot.
        snapshot_source = build / "dwc3_trb.c"
        snapshot_source.write_bytes(frozen[source])
        (build / "dwc3_trb.h").write_bytes(frozen[header])
        (build / "dwc3_trb_harness.c").write_bytes(frozen[fixture])
        (build / "vendor-core.h.txt").write_bytes(frozen[vendor])
        (build / "test_dwc3_trb.py.txt").write_bytes(frozen[script])
        harness = build / "acceptance.c"
        harness.write_text('#include "dwc3_trb.h"\n' + assertions +
                           frozen[fixture].decode("utf-8"), encoding="utf-8")
        flags = ["-std=c11", "-O2", "-Wall", "-Wextra", "-Werror", "-pedantic",
                 "-Wconversion", "-Wsign-conversion", "-I", str(build)]
        executable = build / "acceptance"
        require_success([compiler, *flags, snapshot_source, harness, "-o", executable])
        output = require_success([executable])
        if not re.fullmatch(r"PASS: [0-9]+ checks; 100000 randomized TRBs\n", output):
            raise RuntimeError("missing actual-C acceptance count")
        if args.sanitize:
            sanitized = build / "acceptance-sanitized"
            require_success([compiler, *flags, "-fsanitize=address,undefined",
                             "-fno-sanitize-recover=all", "-fno-omit-frame-pointer",
                             snapshot_source, harness, "-o", sanitized])
            if require_success([sanitized]) != output:
                raise RuntimeError("sanitized acceptance differs from strict acceptance")
        text = frozen[source].decode("utf-8")
        for name, (old, replacement) in MUTANTS.items():
            if text.count(old) != 1:
                raise ValueError(f"mutation anchor is not unique: {name}")
            mutant = build / f"mutant-{name}.c"
            mutant.write_text(text.replace(old, replacement, 1), encoding="utf-8")
            binary = build / f"mutant-{name}"
            require_success([compiler, *flags, mutant, harness, "-o", binary])
            result = run([binary])
            if result.returncode != 1 or "FAIL line " not in result.stderr:
                raise RuntimeError(f"mutant escaped or failed for unrelated reason: {name}")
            print(f"MUTANT REJECTED by C assertion: {name}", flush=True)
    finally:
        changed = []
        for path, before in frozen.items():
            try:
                if path.read_bytes() != before:
                    changed.append(str(path))
            except OSError:
                changed.append(str(path))
        if changed:
            raise RuntimeError("input changed during acceptance: " + ", ".join(changed))
        print(f"Input immutability: {len(frozen)}/{len(frozen)} unchanged", flush=True)
    print(f"PASS: {len(VENDOR)} vendor numerical contracts; four-word layout; "
          f"{len(CANDIDATE)} candidate static assertions; {len(MUTANTS)}/6 mutants rejected")
    for path in (*paths, script):
        print(f"SHA256 {hashlib.sha256(frozen[path]).hexdigest()}  {path.relative_to(root)}")
    print("OFFLINE CODEC ACCEPTANCE ONLY: no ownership/coherency/hardware/USB completion proof")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
        print(f"FAIL: {error}", file=sys.stderr)
        sys.exit(1)
