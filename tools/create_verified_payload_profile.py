#!/usr/bin/env python3
"""Create a PAYLOAD-ONLY profile reusing an OLD verified entry (no build/exec).

Clock/root modes require a fully verified original five-stage recovery run, unchanged
input lists and all other checks/configuration. Only six explicitly allowed
payload paths and a proved config-recording script delta may differ.
The old script must match its prior recorded hash and live under root/out; both
old and current script bytes are pinned in snapshot proof. This validates build
provenance, NOT dependency closure, voltage/ownership, safe MMIO, or hardware authorization.
"""
from __future__ import annotations
import argparse
import copy
import json
import os
from pathlib import Path
import re
import shlex
import sys
from restore_verified_entry import (ENTRY, build_lock, checked, encoded, new_file,
                                    parent, read_bytes, record, records, relative, require, sha)

# Explicit opt-in only; this is NOT a dependency scanner or universal safe-reuse list.
PAYLOAD = frozenset(('src/mmu.c', 'src/xnu_kernel.c', 'src/stage90_main.c', 'src/stage90.h',
    'src/vectors.S', 'src/xnu_arm_vm_init_high_va_data_abort_handler.c',
    'src/dwc3_identify.c', 'src/dwc3_identify.h', 'src/dwc3_probe.c',
    'src/stage90_guarded_read32.c', 'src/stage90_guarded_read32.h',
    'src/stage90_guarded_read32_arm.S', 'tools/test_dwc3_identify.py',
    'tools/test_dwc3_probe.py', 'tools/test_guarded_read32.py',
    'tools/fixtures/dwc3_guarded_read32_harness.c', 'tools/check_dwc3_readonly_probe.py'))
TOOLS = ('tools/create_verified_payload_profile.py', 'tools/restore_verified_entry.py')
NAMES = ['assembly', 'entry-preparation', 'kernel', 'entry', 'payload']
KSM = 'out/xnu_kernel_src_d13.sha256'
IDENT_CHECK = ['python3', 'tools/check_dwc3_readonly_probe.py', '--payload',
    'out/stage90/stage90.elf', '--entry', 'out/stage90/xnu_arm_entry.elf',
    '--config', 'out/stage90/stage90-build-config.txt', '--irq-only']
IRQ_ONLY = '-DSTAGE90_GUARDED_IRQ_ONLY=1'
TARGET_READS = '-DSTAGE90_DWC3_TARGET_READS='
CLOCK_FLAG = '-DSTAGE90_DWC3_CLOCK_SNAPSHOT=1'
ROOT_FLAG = '-DSTAGE90_DWC3_ROOT_SNAPSHOT=1'
CLOCK_INPUTS = frozenset(('src/dwc3_identify.c', 'src/dwc3_identify.h', 'src/dwc3_probe.c',
    'tools/test_dwc3_identify.py', 'tools/test_dwc3_probe.py', 'tools/check_dwc3_readonly_probe.py'))
SCRIPT_OLD = b'|DWC3_TARGET_READS) '
SCRIPT_NEW = b'|DWC3_TARGET_READS|DWC3_CLOCK_SNAPSHOT) '
SCRIPT_ROOT = b'|DWC3_TARGET_READS|DWC3_CLOCK_SNAPSHOT|DWC3_ROOT_SNAPSHOT) '


def recovery_transition(old: dict, wanted: dict, allowed: tuple[str, ...], clock: bool = False,
                        root: bool = False) -> None:
    """Exact build-only transition; hardware authorization is always a separate gate."""
    snapshot = clock or root
    require(set(allowed) <= CLOCK_INPUTS if snapshot else not allowed,
            'snapshot transition allowlist is limited to six payload paths' if snapshot
            else 'transition forbids --allow-payload-input')
    require(old['inputs'] == wanted['inputs'], 'transition requires identical input lists')
    before, after = old.get('checks', []), wanted.get('checks', [])
    require(before and len(before) == len(after) and before[:-1] == after[:-1],
            'transition changed another check/list')
    require(before[-1]['argv'] == IDENT_CHECK + ['--recovery-only'] and
            after[-1]['argv'] == IDENT_CHECK + (['--root-snapshot'] if root else
                                               ['--clock-snapshot'] if clock else []),
            'transition requires exact final recovery/identity checker argv')
    require({k: v for k, v in before[-1].items() if k != 'argv'} ==
            {k: v for k, v in after[-1].items() if k != 'argv'}, 'transition changed final checker settings')
    flags = [shlex.split(p['stages'][-1]['env']['STAGE90_EXTRA_CFLAGS']) for p in (old, wanted)]
    for tokens, value in zip(flags, ('0', '1')):
        for token in (IRQ_ONLY, '-DSTAGE90_DWC3_READONLY=1', TARGET_READS + value):
            key = token.split('=', 1)[0]
            require([t for t in tokens if t == key or t.startswith(key + '=')] == [token],
                    f'transition requires exactly one {token}')
    expected = [TARGET_READS + '1' if t == TARGET_READS + '0' else t for t in flags[0]]
    if snapshot:
        appended = (CLOCK_FLAG, ROOT_FLAG) if root else (CLOCK_FLAG,)
        for flag in (CLOCK_FLAG, ROOT_FLAG):
            key = flag.split('=', 1)[0]
            require(not any(t == key or t.startswith(key + '=') for t in flags[0]),
                    f'old recovery must not define {key}')
        expected.extend(appended)
    require(flags[1] == expected, 'transition permits only TARGET_READS=0 -> 1 and exact snapshot append')


def clock_script_proof(root: Path, path: Path, inputs: dict,
                       replacement: bytes = SCRIPT_NEW) -> tuple[bytes, dict]:
    require(path.is_absolute() and path == path.resolve(strict=True), 'prior build script must be canonical')
    name = relative(root, path)
    require(name.startswith('out/') and name not in inputs, 'prior build script must be separate root/out evidence')
    item = inputs['scripts/build.sh']
    data = checked(root, dict(item, path=name))
    require(data.count(SCRIPT_OLD) == 1 and b'DWC3_CLOCK_SNAPSHOT' not in data
            and b'DWC3_ROOT_SNAPSHOT' not in data, 'prior build script lacks unique original config regex')
    require(read_bytes(root, 'scripts/build.sh') == data.replace(SCRIPT_OLD, replacement, 1),
            'build script differs beyond exact snapshot config-recording insertion')
    return data, record(root, name, data)


def external(path: Path) -> bytes:
    require(path.is_absolute(), 'use absolute CLI paths')
    return read_bytes(Path('/'), str(path)[1:])


def expand(value: str, root: Path, run: Path) -> str:
    return value.replace('{repo_root}', str(root)).replace('{run_dir}', str(run))


def create(profile_path: Path, prior_path: Path, output: Path,
           snapshot: Path | None = None, allowed: tuple[str, ...] = (),
           recovery_to_identification: bool = False, recovery_to_clock_snapshot: bool = False,
           prior_build_script: Path | None = None, recovery_to_root_snapshot: bool = False) -> dict:
    modes = (recovery_to_identification, recovery_to_clock_snapshot, recovery_to_root_snapshot)
    require(sum(bool(mode) for mode in modes) <= 1, 'transition modes are mutually exclusive')
    snapshot_mode = recovery_to_clock_snapshot or recovery_to_root_snapshot
    script_replacement = SCRIPT_ROOT if recovery_to_root_snapshot else SCRIPT_NEW
    require((prior_build_script is not None) == snapshot_mode,
            '--prior-build-script is required only for recovery-to-clock-snapshot or recovery-to-root-snapshot')
    transition = any(modes)
    # This initial read only discovers the recorded root; re-read while locked below.
    initial = external(prior_path)
    root = Path(json.loads(initial)['root'])
    require(root.is_absolute() and root == root.resolve(strict=True), 'recorded root must exist/canonical')
    prior_name, profile_name = relative(root, prior_path), relative(root, profile_path)
    out = relative(root, output)
    require(out.startswith('out/'), 'profile output must be under root/out')
    snap = relative(root, snapshot) if snapshot else out + '.snapshot'
    require(snap.startswith('out/') and not out.startswith(snap + '/'), 'snapshot must be under root/out')
    require(len(allowed) == len(set(allowed)) and set(allowed) <= PAYLOAD, 'invalid payload allowlist')
    with build_lock(root):
        raw = read_bytes(root, prior_name)
        require(raw == initial, 'prior result changed before locking')
        prior = json.loads(raw)
        require(prior.get('version') == 1 and prior.get('status') == 'verified', 'prior must be fully verified')
        old_run = prior_path.parent
        original_name = str(Path(prior_name).with_name('profile.json'))
        original_bytes = read_bytes(root, original_name)
        require(sha(original_bytes) == prior['profile_sha256'], 'prior profile hash changed')
        requested_bytes = read_bytes(root, profile_name)
        old, wanted = json.loads(original_bytes), json.loads(requested_bytes)
        if transition:
            recovery_transition(old, wanted, allowed, recovery_to_clock_snapshot, recovery_to_root_snapshot)
        require(old.get('version') == 1 and not old.get('input_manifests'), 'require original full profile')
        require([s['name'] for s in old['stages']] == NAMES and
                [s['name'] for s in prior['stages']] == NAMES, 'require all five original successful stages')
        require(old['stages'][3]['outputs'] == list(ENTRY), 'unexpected entry output ownership')
        require(old['stages'][4]['argv'] == ['bash', 'scripts/build.sh'], 'require actual payload build script')
        old_inputs = old['inputs']
        old_set, wanted_set = set(old_inputs), set(wanted['inputs'])
        added = wanted_set - old_set
        require(len(old_inputs) == len(old_set) and len(wanted['inputs']) == len(wanted_set)
                and old_set <= wanted_set and added <= set(allowed)
                and set(allowed) <= wanted_set, 'input lists differ')
        # All profile semantics must be identical except description, input ordering,
        # the run-specific locore path, and ONLY the payload-stage CFLAGS override.
        a, b = copy.deepcopy(old), copy.deepcopy(wanted)
        if transition:
            a['checks'][-1]['argv'] = copy.deepcopy(wanted['checks'][-1]['argv'])
        for p in (a, b):
            p.pop('description', None)
            p['inputs'] = sorted(old_inputs)
            p['env'].pop('STAGE90_ENTRY_LOCORE_OBJ', None)
            p['stages'][-1].get('env', {}).pop('STAGE90_EXTRA_CFLAGS', None)
        require(a == b, 'profile semantics/global or entry/kernel environment changed')
        for p in (old, wanted):
            env = {k: expand(v, root, old_run) for k, v in p['env'].items()}
            require(env == prior['env'], 'effective global environment changed')
        stage_records = {}
        for stage, actual in zip(old['stages'], prior['stages']):
            require(type(actual.get('returncode')) is int and actual['returncode'] == 0,
                    'prior stage failed/partial')
            require(actual['argv'] == [expand(x, root, old_run) for x in stage['argv']] and
                    actual.get('env_overrides', {}) == {k: expand(v, root, old_run)
                    for k, v in stage.get('env', {}).items()}, 'prior effective stage differs')
            rows = records(actual['outputs'])
            require(list(rows) == [relative(root, expand(x, root, old_run)) for x in stage['outputs']],
                    'prior stage output lists differ')
            stage_records[stage['name']] = rows
        require(old.get('checks') and len(old['checks']) == len(prior.get('checks', [])), 'prior checks partial')
        for check, actual in zip(old['checks'], prior['checks']):
            require(type(actual.get('returncode')) is int and actual['returncode'] == 0 and
                    actual['argv'] == [expand(x, root, old_run) for x in check['argv']], 'prior check failed/differs')
        inputs = records(prior['inputs'])
        require(set(inputs) == set(old_inputs), 'prior recorded input set differs')
        script_bytes, script_pin = (clock_script_proof(root, prior_build_script, inputs, script_replacement)
                                    if snapshot_mode else (None, None))
        artifacts = records(prior['artifacts'])
        entry = stage_records['entry']
        require(all(artifacts.get(n) == entry[n] for n in ENTRY), 'entry artifact/stage hashes differ')
        image = artifacts[old['image']]
        require(image == stage_records['payload'][old['image']], 'image artifact/stage hashes differ')
        published = prior.get('published_image')
        if published is not None:
            require(published['sha256'] == image['sha256'], 'published hash differs from payload')
            image_data = checked(root, dict(image, path=relative(root, published['path'])))
        else:
            image_data = checked(root, image)
        require(not old.get('android_boot_header') or image_data.startswith(b'ANDROID!'), 'bad prior image header')
        kernel_manifest = stage_records['kernel'][KSM]
        source_bytes = checked(root, kernel_manifest)
        compiled = {}
        for line in source_bytes.decode().splitlines():
            if not line or line.startswith('#'):
                continue
            match = re.fullmatch(r'([0-9a-f]{64})  (.+)', line)
            require(match is not None, 'malformed compiled source manifest')
            digest, name = match.groups()
            name = relative(root, name)
            require(name not in compiled, 'duplicate compiled source path')
            item = record(root, name)
            require(item['sha256'] == digest, f'compiled kernel source changed: {name}')
            compiled[name] = item
        require(bool(compiled), 'empty compiled source manifest')
        pins = dict(compiled)
        if script_pin:
            require(script_pin['path'] not in pins, 'script evidence overlaps compiled source')
            pins[script_pin['path']] = script_pin
        for name, item in stage_records['kernel'].items():
            require(artifacts.get(name) == item, 'kernel artifact/stage hashes differ')
            checked(root, item)
            pins[name] = item
        changed = []
        for name, item in inputs.items():
            if snapshot_mode and name == 'scripts/build.sh':
                data = read_bytes(root, name)
                require(data == script_bytes.replace(SCRIPT_OLD, script_replacement, 1), 'build script changed after proof')
                current = record(root, name, data)
            else:
                current = record(root, name)
            if current != item:
                permitted = name in allowed or (snapshot_mode and name == 'scripts/build.sh')
                require(not recovery_to_identification and permitted and name not in compiled,
                        f'non-payload prior input changed: {name}')
                changed.append(name)
            pins[name] = current
        for name in sorted(added):
            require(name not in compiled, 'new payload input overlaps compiled source')
            pins[name] = record(root, name)
        for name in TOOLS:
            require(name not in pins, 'helper collides with prior inputs')
            pins[name] = record(root, name)
        entry_bytes = {name: checked(root, item) for name, item in entry.items()}
        # Recheck everything before the first output write. The lock does not grant
        # permission to race noncooperating writers; any observed drift refuses.
        for item in pins.values():
            checked(root, item)
        for item in entry.values():
            checked(root, item)
        require(read_bytes(root, prior_name) == raw and read_bytes(root, original_name) == original_bytes
                and read_bytes(root, profile_name) == requested_bytes, 'prior/requested evidence changed')
        with parent(root, out) as (directory, leaf):
            try:
                os.stat(leaf, dir_fd=directory, follow_symlinks=False)
            except FileNotFoundError:
                pass
            else:
                raise ValueError('refuse existing output profile')
        with parent(root, snap) as (directory, leaf):
            os.mkdir(leaf, 0o700, dir_fd=directory)  # Exclusive, no cleanup/overwrite.
        cache = []
        for index, name in enumerate(ENTRY):
            cached = snap + f'/entry-{index}'
            new_file(root, cached, entry_bytes[name])
            cache.append(record(root, cached))
        for leaf, data in (('prior-result.json', raw), ('prior-profile.json', original_bytes),
                           ('requested-profile.json', requested_bytes)):
            name = snap + '/' + leaf
            new_file(root, name, data)
            pins[name] = record(root, name, data)
        if script_pin:
            name = snap + '/prior-build.sh'
            new_file(root, name, script_bytes)
            pins[name] = record(root, name, script_bytes)
        proof = {'kind': 'payload-only-old-entry-reuse-v1', 'root': str(root),
                 'prior_result_sha256': sha(raw), 'compiled_source_count': len(compiled),
                 'allowed_payload_inputs': list(allowed), 'changed_payload_inputs': changed,
                 'added_payload_inputs': sorted(added),
                 'recovery_to_identification': recovery_to_identification,
                 'recovery_to_clock_snapshot': recovery_to_clock_snapshot,
                 'recovery_to_root_snapshot': recovery_to_root_snapshot,
                 'prior_build_script': script_pin,
                 'entry': list(entry.values()), 'cache': cache, 'pins': list(pins.values())}
        manifest = snap + '/reuse.json'
        new_file(root, manifest, encoded(proof))
        manifest_hash = sha(read_bytes(root, manifest))
        pinfile = snap + '/inputs.json'
        new_file(root, pinfile, encoded(list(pins.values()) + cache + [record(root, manifest)]))
        result = copy.deepcopy(wanted)
        result['description'] = 'PAYLOAD-ONLY: OLD verified entry restored byte-identically; kernel/entry NOT rebuilt'
        result['stages'] = [{'name': 'verified-entry-reuse', 'argv': ['python3', TOOLS[1], '--root',
            '{repo_root}', '--manifest', manifest, '--sha256', manifest_hash], 'outputs': list(ENTRY), 'timeout_s': 120},
            copy.deepcopy(wanted['stages'][-1])]
        result['input_manifests'] = [pinfile]
        result['inputs'] = list(dict.fromkeys(result['inputs'] + [manifest, pinfile] + list(TOOLS)))
        result['payload_only_reuse'] = {k: proof[k] for k in ('kind', 'prior_result_sha256',
            'compiled_source_count', 'allowed_payload_inputs', 'changed_payload_inputs', 'added_payload_inputs',
            'recovery_to_identification', 'recovery_to_clock_snapshot', 'recovery_to_root_snapshot', 'prior_build_script')}
        if transition:
            mode = ('ROOT SNAPSHOT' if recovery_to_root_snapshot else
                    'CLOCK SNAPSHOT' if recovery_to_clock_snapshot else 'IDENTIFICATION')
            result['description'] += f'; RECOVERY -> {mode} (build proof only; NOT hardware authorization)'
        for item in list(pins.values()) + cache:
            checked(root, item)
        require(sha(read_bytes(root, manifest)) == manifest_hash, 'manifest changed during snapshot')
        new_file(root, out, encoded(result))
    checks_summary = (f'{len(old["checks"]) - 1} unchanged checks + exact final transition checker'
                      if transition else f'{len(old["checks"])} unchanged checks')
    print(f'PAYLOAD-ONLY profile: {output}; 4 OLD entry artifacts; {len(compiled)} pinned compiled sources; '
          f'{checks_summary}. NOT a full rebuild.')
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('profile', 'prior-result', 'output'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--snapshot', type=Path)
    parser.add_argument('--allow-payload-input', action='append', default=[])
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument('--recovery-to-identification', action='store_true',
                       help='exact build-only recovery -> identity transition; forbids all input changes')
    modes.add_argument('--recovery-to-clock-snapshot', action='store_true',
                       help='exact build-only clock transition; six explicit payload paths and proved script delta only')
    modes.add_argument('--recovery-to-root-snapshot', action='store_true',
                       help='exact build-only root transition; six explicit payload paths and proved script delta only')
    parser.add_argument('--prior-build-script', type=Path,
                        help='snapshot modes only: prior-hash-matching original build script under root/out')
    args = parser.parse_args()
    try:
        create(args.profile, args.prior_result, args.output, args.snapshot, tuple(args.allow_payload_input),
               args.recovery_to_identification, args.recovery_to_clock_snapshot, args.prior_build_script,
               args.recovery_to_root_snapshot)
        return 0
    except (OSError, ValueError, KeyError, TypeError) as exc:
        print(f'REFUSING: {exc}', file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
