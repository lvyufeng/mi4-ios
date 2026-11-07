#!/usr/bin/env python3
"""Run a build-only profile without hiding stage failures or publishing stale images.

A profile supplies argv lists, not shell pipelines. Every stage must exit zero,
leave no FAIL:/REFUSING: diagnostic, and freshly produce its declared outputs.
Only then are final symbols and embedded entry bytes checked and an immutable
copy of the boot image published in a unique run directory. This tool NEVER
boots a device. A successful record proves build provenance, not iOS usability.

Usage: python3 tools/build_verified.py --profile path/to/profile.json
"""
from __future__ import annotations

import argparse
import datetime as dt
import fcntl
import hashlib
import json
import mmap
import os
from pathlib import Path
import re
import shlex
import shutil
import signal
import subprocess
import sys
import time
import uuid


class BuildError(RuntimeError):
    pass


FAILURE_LINE = re.compile(r"^(?:REFUSING\b|FAIL(?:URE)?\b)(?!\s*:\s*0\s*$)", re.I)


def digest(path: Path) -> str:
    result = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            result.update(block)
    return result.hexdigest()


def within(root: Path, value: str) -> Path:
    if not isinstance(value, str) or not value:
        raise BuildError("file paths must be nonempty strings")
    path = (root / value).resolve()
    if not path.is_relative_to(root):
        raise BuildError(f"path escapes repository: {value}")
    return path


def file_record(root: Path, path: Path) -> dict:
    if not path.is_file() or path.stat().st_size == 0:
        raise BuildError(f"missing or empty artifact: {path}")
    stat = path.stat()
    return {"path": str(path.relative_to(root)), "size": stat.st_size,
            "mtime_ns": stat.st_mtime_ns, "sha256": digest(path)}


def diagnostic(log: Path) -> str | None:
    # Work incrementally; full compiler logs need not fit in memory.
    with log.open(encoding="utf-8", errors="replace") as handle:
        for line in handle:
            text = line.strip()
            if FAILURE_LINE.match(text):
                return text
            count = re.match(r"^(?:C\+\+\s+fail|timed out(?:\s*\([^)]*\))?)\s*:\s*(\d+)\s*$", text)
            if count and int(count.group(1)):
                return text
            assembly = re.match(r"^assemble:\s*\d+\s+ok,\s*(\d+)\s+failed\b", text)
            if assembly and int(assembly.group(1)):
                return text
    return None


def safe_env(env: dict) -> None:
    if env.get("STAGE90_XNU_HDD_WRITE", "0") != "0":
        raise BuildError("physical eMMC write path must remain OFF")
    for name in ("STAGE90_EXTRA_CFLAGS", "XNU_KERNEL_EXTRA_DEFINES"):
        for token in shlex.split(env.get(name, "")):
            if re.fullmatch(r"-DSTAGE90_XNU_HDD_WRITE(?:=(.*))?", token):
                if token != "-DSTAGE90_XNU_HDD_WRITE=0":
                    raise BuildError(f"physical write define forbidden in {name}")


def load_profile(path: Path, contents: bytes | None = None) -> dict:
    profile = json.loads(contents if contents is not None else path.read_bytes())
    if not isinstance(profile, dict) or profile.get("version") != 1:
        raise BuildError("expected version 1 build profile object")
    if not profile.get("stages") or not isinstance(profile["stages"], list):
        raise BuildError("profile needs a nonempty stages list")
    env = profile.get("env", {})
    if not isinstance(env, dict) or any(not isinstance(k, str) or
            not isinstance(v, str) for k, v in env.items()):
        raise BuildError("profile env must map strings to strings")
    safe_env(env)
    names = set()
    for stage in profile["stages"]:
        if not isinstance(stage, dict):
            raise BuildError("each stage must be an object")
        name = stage.get("name", "")
        if not re.fullmatch(r"[a-z][a-z0-9_-]*", name) or name in names:
            raise BuildError("stage names must be unique safe identifiers")
        names.add(name)
        argv = stage.get("argv")
        if not isinstance(argv, list) or not argv or any(
                not isinstance(a, str) or not a for a in argv):
            raise BuildError(f"{name}: argv must be a nonempty string list")
        executable = Path(argv[0]).name
        if executable in {"adb", "fastboot"}:
            raise BuildError("build profiles must not invoke device tools")
        if executable in {"bash", "sh", "zsh"} and any(
                a in {"-c", "--command"} for a in argv[1:]):
            raise BuildError("use a script, not a shell pipeline / inline command")
        stage_env = stage.get("env", {})
        if not isinstance(stage_env, dict) or any(not isinstance(k, str) or not isinstance(v, str)
                for k, v in stage_env.items()):
            raise BuildError(f"{name}: env must map strings to strings")
        safe_env(stage_env)
        if not isinstance(stage.get("outputs"), list) or not stage["outputs"]:
            raise BuildError(f"{name}: declare freshly produced outputs")
        if not isinstance(stage.get("timeout_s", 1800), (int, float)) or \
                stage.get("timeout_s", 1800) <= 0:
            raise BuildError(f"{name}: timeout must be positive")
    for check in profile.get("checks", []):
        argv = check.get("argv")
        if not isinstance(argv, list) or not argv or any(not isinstance(a, str) or not a for a in argv):
            raise BuildError("artifact check needs an argv string list")
        executable = Path(argv[0]).name
        if executable in {"adb", "fastboot"} or (executable in {"bash", "sh", "zsh"} and
                any(a in {"-c", "--command"} for a in argv[1:])):
            raise BuildError("artifact checks must not invoke device tools or inline shell")
    if not isinstance(profile.get("image"), str):
        raise BuildError("declare final image path")
    return profile


def run_process(argv: list[str], cwd: Path, env: dict, log: Path,
                timeout: float) -> int:
    with log.open("wb") as output:
        child = subprocess.Popen(argv, cwd=cwd, env=env, stdout=output,
                                 stderr=subprocess.STDOUT, start_new_session=True)
        try:
            return child.wait(timeout=timeout)
        except (subprocess.TimeoutExpired, KeyboardInterrupt):
            os.killpg(child.pid, signal.SIGTERM)
            try:
                child.wait(timeout=5)
            except subprocess.TimeoutExpired:
                os.killpg(child.pid, signal.SIGKILL)
                child.wait()
            raise BuildError(f"stage interrupted/timed out after {timeout}s; {log}")


def check_symbols(root: Path, check: dict, env: dict) -> None:
    image = within(root, check["artifact"])
    result = subprocess.run([check.get("nm", "arm-none-eabi-nm"),
                             "--defined-only", str(image)], env=env,
                            capture_output=True, text=True, timeout=60)
    if result.returncode:
        raise BuildError(f"nm failed ({result.returncode}): {result.stderr.strip()}")
    symbols = {}
    for line in result.stdout.splitlines():
        parts = line.split()
        if len(parts) >= 3:
            symbols[parts[-1]] = parts[-2]
    for name in check.get("required", []):
        if symbols.get(name) not in {"T", "t"}:
            raise BuildError(f"{image.name}: required function absent: {name}")
    for name in check.get("absent", []):
        if name in symbols:
            raise BuildError(f"{image.name}: forbidden symbol present: {name}")


def check_embedded(root: Path, check: dict) -> None:
    outer, inner = within(root, check["container"]), within(root, check["payload"])
    if not inner.is_file() or not outer.is_file() or min(
            inner.stat().st_size, outer.stat().st_size) <= 0:
        raise BuildError("embedding check requires nonempty regular files")
    with inner.open("rb") as src, outer.open("rb") as dst:
        with mmap.mmap(src.fileno(), 0, access=mmap.ACCESS_READ) as payload, \
                mmap.mmap(dst.fileno(), 0, access=mmap.ACCESS_READ) as image:
            if image.find(payload) < 0:
                raise BuildError(f"{outer.name} does not embed exact current {inner.name}")


def execute(profile_path: Path, root: Path, runs: Path) -> tuple[int, Path]:
    root = root.resolve(strict=True)
    profile_bytes = profile_path.read_bytes()
    profile = load_profile(profile_path, profile_bytes)
    if not runs.resolve().is_relative_to(root):
        raise BuildError("run directory must stay within repository")
    runs.mkdir(parents=True, exist_ok=True)
    lock_path = root / "out/.verified-build.lock"
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    with lock_path.open("a+") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise BuildError("another verified build owns this repository") from exc
        stamp = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        run = runs / f"{stamp}-{uuid.uuid4().hex[:10]}"
        run.mkdir()
        # Store exactly the profile bytes used, not merely an output-image hash.
        profile_copy = run / "profile.json"
        profile_copy.write_bytes(profile_bytes)
        env = os.environ.copy()
        # Don't inherit stale experiment switches from a parent interactive shell.
        for name in list(env):
            if name.startswith(("STAGE90_", "XNU_")):
                del env[name]
        substitutions = {"{repo_root}": str(root), "{run_dir}": str(run)}

        def expand(value):
            for needle, replacement in substitutions.items():
                value = value.replace(needle, replacement)
            return value

        env.update({name: expand(value) for name, value in profile.get("env", {}).items()})
        env["MI4_VERIFIED_BUILD_RUN"] = str(run)
        safe_env(env)
        record = {"version": 1, "status": "failed", "root": str(root),
                  "profile_sha256": digest(profile_copy),
                  "env": {name: env[name] for name in profile.get("env", {})}, "stages": [],
                  "started_ns": time.time_ns(), "inputs": [], "artifacts": []}
        try:
            for manifest_name in profile.get("input_manifests", []):
                manifest = within(root, manifest_name)
                record["inputs"].append(file_record(root, manifest))
                entries = json.loads(manifest.read_text(encoding="utf-8"))
                if not isinstance(entries, list) or not entries:
                    raise BuildError("input manifest must contain nonempty hash records")
                for item in entries:
                    actual = file_record(root, within(root, item["path"]))
                    if actual["sha256"] != item["sha256"] or actual["size"] != item["size"]:
                        raise BuildError(f"pinned input differs: {item['path']}")
                    record["inputs"].append(actual)
            for name in profile.get("inputs", []):
                record["inputs"].append(file_record(root, within(root, name)))
            produced = set()
            pinned_outputs = {}
            for index, stage in enumerate(profile["stages"]):
                cwd = within(root, expand(stage.get("cwd", ".")))
                argv = [expand(a) for a in stage["argv"]]
                stage_env = env.copy()
                stage_env.update({name: expand(value) for name, value in stage.get("env", {}).items()})
                safe_env(stage_env)
                outputs = [within(root, expand(p)) for p in stage["outputs"]]
                before = {str(p): (p.stat().st_mtime_ns, p.stat().st_ctime_ns,
                          p.stat().st_size) if p.exists() else None for p in outputs}
                started_ns = time.time_ns()
                log = run / f"{index + 1:02d}-{stage['name']}.log"
                stage_record = {"name": stage["name"], "argv": argv,
                                "env_overrides": {name: stage_env[name] for name in stage.get("env", {})},
                                "log": log.name, "started_ns": started_ns}
                record["stages"].append(stage_record)
                print(f"[{stage['name']}] start; full log: {log}", flush=True)
                rc = run_process(argv, cwd, stage_env, log,
                                 stage.get("timeout_s", 1800))
                stage_record.update(returncode=rc, finished_ns=time.time_ns())
                if rc != 0:
                    raise BuildError(f"{stage['name']} exited {rc}; no later stage ran")
                failure = diagnostic(log)
                if failure:
                    raise BuildError(f"{stage['name']} reported {failure}")
                changed_outputs = set(outputs)
                consumed_paths = {within(root, expand(p)) for p in stage.get("consumes", [])}
                for prior_path in produced - changed_outputs - consumed_paths:
                    if not prior_path.is_file() or digest(prior_path) != pinned_outputs[prior_path]["sha256"]:
                        raise BuildError(f"{stage['name']} changed earlier stage output: {prior_path}")
                fresh = []
                for output in outputs:
                    item = file_record(root, output)
                    stat = output.stat()
                    state = (stat.st_mtime_ns, stat.st_ctime_ns, stat.st_size)
                    if state == before[str(output)] or stat.st_mtime_ns < started_ns:
                        raise BuildError(f"{stage['name']} left stale output: {output}")
                    fresh.append(item)
                    produced.add(output)
                    pinned_outputs[output] = item
                for consumed_name in stage.get("consumes", []):
                    consumed = within(root, expand(consumed_name))
                    if consumed not in produced:
                        raise BuildError(f"{stage['name']} consumes undeclared output: {consumed}")
                    produced.remove(consumed)
                stage_record["outputs"] = fresh
                stage_record["consumes"] = stage.get("consumes", [])
                print(f"[{stage['name']}] PASS (exit=0, fresh outputs)", flush=True)
            for item in record["inputs"]:
                if digest(within(root, item["path"])) != item["sha256"]:
                    raise BuildError(f"input changed during build: {item['path']}")
            image = within(root, profile["image"])
            if image not in produced:
                raise BuildError("final image was not a declared fresh stage output")
            for check in profile.get("symbols", []):
                if within(root, check["artifact"]) not in produced:
                    raise BuildError("symbol check must name a fresh stage artifact")
                check_symbols(root, check, env)
            for check in profile.get("embedded", []):
                if any(within(root, check[key]) not in produced
                       for key in ("container", "payload")):
                    raise BuildError("embedding check must name fresh stage artifacts")
                check_embedded(root, check)
            for index, check in enumerate(profile.get("checks", [])):
                argv = [expand(a) for a in check["argv"]]
                log = run / f"check-{index + 1:02d}.log"
                rc = run_process(argv, within(root, check.get("cwd", ".")), env,
                                 log, check.get("timeout_s", 180))
                record.setdefault("checks", []).append({"argv": argv, "log": log.name,
                                                          "returncode": rc})
                if rc != 0 or diagnostic(log):
                    raise BuildError(f"artifact check {index + 1} failed (exit={rc}); {log}")
            if profile.get("android_boot_header", False):
                with image.open("rb") as handle:
                    if handle.read(8) != b"ANDROID!":
                        raise BuildError("final image lacks Android boot header")
            # Validators are intended to be read-only, but do not trust that
            # intention: recheck both inputs and previously validated outputs.
            for item in record["inputs"]:
                path = within(root, item["path"])
                if not path.is_file() or digest(path) != item["sha256"]:
                    raise BuildError(f"input changed after artifact checks: {item['path']}")
            for path in produced:
                if not path.is_file() or digest(path) != pinned_outputs[path]["sha256"]:
                    raise BuildError(f"validated artifact changed after checks: {path}")
            record["artifacts"] = [pinned_outputs[p] for p in sorted(produced)]
            candidate = run / "candidate-image.img"
            expected_image_hash = next(item["sha256"] for item in record["artifacts"]
                                       if item["path"] == str(image.relative_to(root)))
            shutil.copyfile(image, candidate)
            if digest(candidate) != expected_image_hash or digest(image) != expected_image_hash:
                raise BuildError("image changed during publication")
            published = run / "verified-image.img"
            if published.exists() or published.is_symlink() or published.resolve() != published:
                raise BuildError("unexpected verified-image publication target")
            # Both absolute paths were checked inside this unique run before the move.
            os.replace(candidate, published)
            record["status"] = "verified"
            record["published_image"] = {"path": str(published), "sha256": digest(published)}
        except (BuildError, OSError, subprocess.SubprocessError) as exc:
            record["error"] = str(exc)
            print(f"BUILD REFUSED: {exc}", file=sys.stderr, flush=True)
        finally:
            record["finished_ns"] = time.time_ns()
            (run / "result.json").write_text(json.dumps(record, ensure_ascii=False,
                                                   indent=2) + "\n", encoding="utf-8")
        return (0 if record["status"] == "verified" else 1), run


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", type=Path, required=True)
    parser.add_argument("--repo-root", type=Path,
                        default=Path(__file__).resolve().parents[1])
    parser.add_argument("--runs", type=Path, default=Path("out/verified-builds"))
    args = parser.parse_args()
    try:
        rc, run = execute(args.profile.resolve(), args.repo_root,
                          args.repo_root / args.runs)
    except (BuildError, OSError, ValueError, TypeError, KeyError) as exc:
        print(f"BUILD REFUSED: {exc}", file=sys.stderr)
        return 1
    print(f"build record: {run / 'result.json'}", flush=True)
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
