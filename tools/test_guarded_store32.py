#!/usr/bin/env python3
"""Test actual guarded-store C with host fakes; no ARM execution or MMIO.

All compiles use immutable input snapshots in a temporary directory. FIQ uses
explicit test-only instrumentation/longjmp, not real exception delivery.
"""
import argparse
import hashlib
from pathlib import Path
import re
import shlex
import subprocess
import tempfile


INPUTS = (
    'src/stage90_guarded_read32.c',
    'src/stage90_guarded_read32.h',
    'src/stage90_guarded_profile.h',
    'src/stage90_guarded_read32_arm.S',  # hash only: never assembled/executed
    'tools/fixtures/guarded_store_harness.c',
    'tools/fixtures/guarded_irq_only_harness.c',
)
FLAGS = ('-std=c11', '-O2', '-Wall', '-Wextra', '-Werror', '-pedantic', '-fno-common',
         '-DSTAGE90_DWC3_READONLY=1', '-DSTAGE90_GUARDED_IRQ_ONLY=1',
         '-DSTAGE90_GUARDED_STORE32=1')
HOOK = 'stage90_guarded_fiq_hook_contract'
MUTATIONS = (
    ('write-direction', '!= 0u) == write', '!= 0u) <= write'),
    ('exact-PC', 'frame[5] == state->fault_pc &&', '1 &&'),
    ('false-success',
     'if (rc == 0 && state->status == STAGE90_GUARDED_ARMED && state->active == 1u &&\n'
     '        state->fault_count == 0u)', 'if (rc == 0)'),
    ('operation', 'state->operation != 1u ||', '0 ||'),
    ('external-write-recovery',
     'if (write && (status == 0x08u || status == 0x0cu || status == 0x0eu))',
     'if (0 && write && (status == 0x08u || status == 0x0cu || status == 0x0eu))'),
)
STORE_REPORT = (r'PASS store actual C: {} cases, {} assertions; host fake only, '
                r'write fault side effect INDETERMINATE\n')


def replace_once(text, old, new, label):
    if text.count(old) != 1:
        raise ValueError(label + ' anchor must occur exactly once')
    return text.replace(old, new, 1)


def run(command, directory):
    return subprocess.run(command, cwd=directory, text=True, capture_output=True,
                          timeout=30)


def require_success(result, label):
    if result.returncode != 0:
        raise ValueError('{} failed (exit {}):\n{}{}'.format(
            label, result.returncode, result.stdout, result.stderr))


def build(cc, flags, directory, label, source, harness, extra=()):
    output = directory / label
    result = run(cc + flags + [str(source), str(harness)] +
                 [str(p) for p in extra] + ['-o', str(output)], directory)
    require_success(result, label + ' strict compile/link')
    return output


def positive(cc, flags, directory, label, source, harness, expected, extra=()):
    output = build(cc, flags, directory, label, source, harness, extra)
    result = run([str(output)], directory)
    require_success(result, label + ' behavior')
    if result.stderr or not re.fullmatch(expected, result.stdout):
        raise ValueError(label + ' unexpected report:\n' + result.stdout + result.stderr)
    print(result.stdout, end='', flush=True)


def instrument_fiq(source, harness):
    marker = 'int stage90_guarded_write32('
    if source.count(marker) != 1:
        raise ValueError('store wrapper boundary changed')
    head, body = source.split(marker, 1)
    body = replace_once(body, '    state->active = 1u;',
                        '    state->active = 1u;\n    store_fiq_test_site(1);\n'
                        '    store_fiq_test_site(6);', 'FIQ arm')
    body = replace_once(body, '    state->active = 0u;',
                        '    store_fiq_test_site(5);\n    state->active = 0u;', 'FIQ clear')
    text = 'extern void store_fiq_test_site(unsigned);\n' + head + marker + body
    for site in range(1, 7):
        call = 'store_fiq_test_site({});'.format(site)
        owner, other = (harness, text) if site in (2, 3, 4) else (text, harness)
        if owner.count(call) != 1 or other.count(call) != 0:
            raise ValueError('changed fake FIQ injection site {}'.format(site))
    return text


def missing_hook(cc, flags, directory, source, harness):
    objects = []
    for label, path in (('actual', source), ('harness', harness)):
        output = directory / ('missing-hook-' + label + '.o')
        result = run(cc + flags + ['-DOMIT_HOOK', '-c', str(path), '-o', str(output)], directory)
        require_success(result, 'missing-hook ' + label + ' strict object compile')
        objects.append(str(output))
    result = run(cc + flags + objects + ['-o', str(directory / 'missing-hook')], directory)
    if result.returncode == 0 or HOOK not in result.stdout + result.stderr:
        raise ValueError('missing-hook must fail final link for ' + HOOK + ':\n' +
                         result.stdout + result.stderr)
    print('PASS missing FIQ-hook final link rejected; both strict objects compiled', flush=True)


def test_snapshots(cc, sanitize, snapshots):
    with tempfile.TemporaryDirectory(prefix='mi4-guarded-store32-') as name:
        directory = Path(name)
        for relative, data in snapshots.items():
            (directory / Path(relative).name).write_bytes(data)
        flags = list(FLAGS) + ['-I', str(directory)]
        if sanitize:
            flags += ['-fsanitize=address,undefined', '-fno-omit-frame-pointer']
        source = snapshots['src/stage90_guarded_read32.c'].decode('utf-8')
        source_path = directory / 'stage90_guarded_read32.c'
        harness = directory / 'guarded_store_harness.c'
        positive(cc, flags, directory, 'actual-store', source_path, harness,
                 STORE_REPORT.format(245, 1034))
        for label, old, new in MUTATIONS:
            mutated = directory / (label + '.c')
            mutated.write_text(replace_once(source, old, new, label), encoding='utf-8')
            output = build(cc, flags, directory, label, mutated, harness)
            result = run([str(output)], directory)
            if (result.returncode != 1 or result.stdout or
                    not re.fullmatch(r'FAIL line [0-9]+: [^\n]+\n', result.stderr)):
                raise ValueError(label + ' must fail an assertion, not compile/crash/sanitizer:\n' +
                                 result.stdout + result.stderr)
            print('PASS negative {} rejected by actual C behavior'.format(label), flush=True)
        print('PASS 5 store behavioral negative controls rejected', flush=True)
        instrumented = directory / 'instrumented-store.c'
        instrumented.write_text(instrument_fiq(
            source, snapshots['tools/fixtures/guarded_store_harness.c'].decode('utf-8')),
            encoding='utf-8')
        positive(cc, flags + ['-DFIQ_INSTRUMENTED'], directory, 'fake-fiq',
                 instrumented, harness, STORE_REPORT.format(251, 1075))
        missing_hook(cc, flags, directory, source_path, harness)
        # The unchanged read fixture must still pass with the store feature ON.
        stub = directory / 'unused-store.c'
        stub.write_text('#include "stage90_guarded_read32.h"\n#include <stdlib.h>\n'
                        'const unsigned char stage90_guarded_write32_fault[4]={0};\n'
                        'const unsigned char stage90_guarded_write32_recovery[4]={0};\n'
                        'int stage90_guarded_write32_store_arm(uint32_t a,uint32_t v)\n'
                        '{(void)a;(void)v;abort();}\n', encoding='utf-8')
        positive(cc, flags, directory, 'read-with-store', source_path,
                 directory / 'guarded_irq_only_harness.c',
                 r'PASS future actual C: 2188 cases, 12710 assertions; '
                 r'fake leaf, NOT FIQ runtime\n', (stub,))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repo-root', type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument('--cc', default='cc', help='host compiler command (shell quoting allowed)')
    parser.add_argument('--sanitize', action='store_true', help='ASan+UBSan on every build')
    args = parser.parse_args()
    cc = shlex.split(args.cc)
    if not cc:
        raise ValueError('empty compiler command')
    root = args.repo_root.resolve()
    snapshots = {relative: (root / relative).read_bytes() for relative in INPUTS}
    try:
        test_snapshots(cc, args.sanitize, snapshots)
    finally:
        for relative, before in snapshots.items():
            if (root / relative).read_bytes() != before:
                raise ValueError('input changed during tests: ' + relative)
    for relative, data in snapshots.items():
        print('SHA256', hashlib.sha256(data).hexdigest(), relative)
    print('LIMIT: host fake leaf and longjmp FIQ disposition only; NOT ARM execution, '
          'exception delivery, routing, hardware, MMIO, or bus timeout proof')


if __name__ == '__main__':
    try:
        main()
    except (OSError, UnicodeError, ValueError, subprocess.SubprocessError) as error:
        raise SystemExit('FAIL: ' + str(error))
