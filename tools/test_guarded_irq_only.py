#!/usr/bin/env python3
"""Test live IRQ-only guarded-read C in temporary host builds; no ARM or MMIO.

The fixtures supply fake ARM leaves and fake nonreturning FIQ disposition.
Lifecycle instrumentation is applied only to generated copies of the actual C.
Nothing here proves ARM instructions, exception delivery, routing, or hardware.
"""

import argparse
import hashlib
from pathlib import Path
import re
import shlex
import subprocess
import tempfile


STRICT_FLAGS = ('-std=c11', '-O2', '-Wall', '-Wextra', '-Werror', '-pedantic',
                '-fno-common')
PROFILE_FLAGS = ('-DSTAGE90_DWC3_READONLY=1', '-DSTAGE90_GUARDED_IRQ_ONLY=1')
HOOK_SYMBOL = 'stage90_guarded_fiq_hook_contract'
INPUTS = (
    'src/stage90_guarded_read32.h',
    'src/stage90_guarded_read32.c',
    'src/stage90_guarded_profile.h',
    'tools/fixtures/guarded_irq_only_harness.c',
    'tools/fixtures/guarded_fiq_lifecycle_harness.c',
)

# Each control must compile cleanly and then fail a fixture assertion at runtime.
# A compiler/linker/sanitizer failure is not a behavioral mutant kill.
MUTATIONS = (
    ('mask-I', '(after & 0x80u) != 0u', '1'),
    ('stable-F', '(STAGE90_GUARD_STABLE_CPSR & ~0x80u)',
     '(STAGE90_GUARD_STABLE_CPSR & ~0xc0u)'),
    ('wrong-PC', 'frame[5] == state->fault_pc &&', '1 &&'),
    ('SPSR-equality',
     '((saved_cpsr ^ state->cpsr_after_mask) & STAGE90_GUARD_STABLE_CPSR) == 0u',
     '1'),
    ('imprecise', 'case 0x03u: /* access flag, section */',
     'case 0x16u:\n    case 0x03u: /* access flag, section */'),
    ('false-success',
     'if (rc == 0 && state->active == 1u && state->status == STAGE90_GUARDED_ARMED &&\n'
     '        state->fault_count == 0u)', 'if (rc == 0)'),
)

# Fail closed if an exact call-site anchor changes. Sites 3 (pre-LDR) and 5
# (recovery) live in the fake leaf, not fabricated inside production C.
LIFECYCLE_ANCHORS = (
    ('    state->active = 1u;',
     '    fiq_test_site(1);\n    state->active = 1u;\n'
     '    fiq_test_site(2);\n    fiq_test_site(9);'),
    ('    rc = stage90_guarded_read32_load_arm(address, &sample);',
     '    rc = stage90_guarded_read32_load_arm(address, &sample);'),
    ('    /* RAM breadcrumb before returning a disposition;',
     '    fiq_test_site(4);\n    /* RAM breadcrumb before returning a disposition;'),
    ('        *out = sample;',
     '        fiq_test_site(6);\n        *out = sample;\n        fiq_test_site(7);'),
    ('    state->active = 0u;',
     '    fiq_test_site(8);\n    state->active = 0u;\n    fiq_test_site(10);'),
)


def run(command, directory):
    """Run only the selected host compiler or an executable built in temp."""
    return subprocess.run(command, cwd=directory, text=True, capture_output=True,
                          timeout=30)


def require_success(result, label):
    if result.returncode != 0:
        raise ValueError('{} failed (exit {}):\n{}{}'.format(
            label, result.returncode, result.stdout, result.stderr))


def replace_anchor(source, old, new, label):
    count = source.count(old)
    if count != 1:
        raise ValueError('{} anchor occurs {} times, expected exactly 1'.format(label, count))
    return source.replace(old, new, 1)


def instrument_lifecycle(source, harness):
    # The optional store wrapper has its own independent lifecycle tests. Never
    # instrument its similarly named active stores as if they were read sites.
    marker = 'int stage90_guarded_write32('
    if source.count(marker) > 1:
        raise ValueError('ambiguous optional store wrapper')
    read_source, boundary, store_source = source.partition(marker)
    for index, (old, new) in enumerate(LIFECYCLE_ANCHORS, 1):
        read_source = replace_anchor(read_source, old, new, 'lifecycle {}'.format(index))
    source = read_source + boundary + store_source
    # Verify all ten injection sites still exist exactly once across the actual
    # generated wrapper/policy and fake leaf. The latter owns only sites 3 and 5.
    for site in range(1, 11):
        call = 'fiq_test_site({});'.format(site)
        owner, other = (harness, source) if site in (3, 5) else (source, harness)
        if owner.count(call) != 1 or other.count(call) != 0:
            raise ValueError('changed lifecycle injection site {}'.format(site))
    return 'extern void fiq_test_site(unsigned);\n' + source


def build(cc, flags, directory, source, harness, label):
    output = directory / label
    result = run(cc + flags + [str(source), str(harness), '-o', str(output)], directory)
    require_success(result, label + ' strict compile/link')
    return output


def positive(cc, flags, directory, source, harness, label, expected):
    output = build(cc, flags, directory, source, harness, label)
    result = run([str(output)], directory)
    require_success(result, label + ' behavior')
    if result.stderr or not re.fullmatch(expected, result.stdout):
        raise ValueError(label + ' unexpected fixture report:\n' + result.stdout + result.stderr)
    print(result.stdout, end='', flush=True)


def negative(cc, flags, directory, source, harness, label):
    output = build(cc, flags, directory, source, harness, label)
    result = run([str(output)], directory)
    if (result.returncode != 1 or result.stdout or
            not re.fullmatch(r'FAIL line [0-9]+: [^\n]+\n', result.stderr)):
        raise ValueError(label + ' must fail a behavioral assertion, not compile/crash/sanitizer:\n' +
                         result.stdout + result.stderr)
    print('PASS negative {} rejected by actual C behavior'.format(label), flush=True)


def missing_hook(cc, flags, directory, source, harness):
    """Compile both inputs strictly first; only the final link must fail."""
    objects = []
    for label, path in (('actual', source), ('harness', harness)):
        output = directory / ('missing-hook-' + label + '.o')
        result = run(cc + flags + ['-DOMIT_HOOK', '-c', str(path), '-o', str(output)], directory)
        require_success(result, 'missing-hook ' + label + ' strict object compile')
        objects.append(str(output))
    result = run(cc + flags + objects + ['-o', str(directory / 'missing-hook')], directory)
    if result.returncode == 0 or HOOK_SYMBOL not in result.stdout + result.stderr:
        raise ValueError('missing-hook must fail linking the required symbol:\n' +
                         result.stdout + result.stderr)
    print('PASS missing assembly-hook symbol link rejected '
          '(strict objects compiled; host fake omitted)', flush=True)


def test_snapshots(cc, sanitize, snapshots):
    with tempfile.TemporaryDirectory(prefix='mi4-guarded-irq-only-') as name:
        directory = Path(name)
        # Compile against snapshots only, including the helper profile header;
        # no include path points back into the live tree.
        for relative, data in snapshots.items():
            (directory / Path(relative).name).write_bytes(data)
        source_path = directory / 'stage90_guarded_read32.c'
        harness = directory / 'guarded_irq_only_harness.c'
        lifecycle_harness = directory / 'guarded_fiq_lifecycle_harness.c'
        source = snapshots['src/stage90_guarded_read32.c'].decode('utf-8')
        lifecycle = instrument_lifecycle(
            source, snapshots['tools/fixtures/guarded_fiq_lifecycle_harness.c'].decode('utf-8'))
        flags = list(STRICT_FLAGS + PROFILE_FLAGS) + ['-I', str(directory)]
        if sanitize:
            flags += ['-fsanitize=address,undefined', '-fno-omit-frame-pointer']
        positive(cc, flags, directory, source_path, harness, 'actual',
                 r'PASS future actual C: 2188 cases, 12710 assertions; '
                 r'fake leaf, NOT FIQ runtime\n')
        for label, old, new in MUTATIONS:
            mutated = directory / (label + '.c')
            mutated.write_text(replace_anchor(source, old, new, label), encoding='utf-8')
            negative(cc, flags, directory, mutated, harness, label)
        print('PASS 6 actual-C behavioral negative controls rejected', flush=True)
        instrumented = directory / 'instrumented-lifecycle.c'
        instrumented.write_text(lifecycle, encoding='utf-8')
        positive(cc, flags, directory, instrumented, lifecycle_harness, 'fiq-lifecycle',
                 r'PASS actual-C test-only FIQ injection: 20 cases, 116 assertions; '
                 r'fake disposition, NOT runtime FIQ\n')
        missing_hook(cc, flags, directory, source_path, harness)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repo-root', type=Path, default=Path(__file__).resolve().parents[1],
                        help='repository containing src/ and tools/fixtures/')
    parser.add_argument('--cc', default='cc', help='host C compiler command (shell quoting allowed)')
    parser.add_argument('--sanitize', action='store_true',
                        help='enable address and undefined-behavior sanitizers on every build')
    args = parser.parse_args()
    cc = shlex.split(args.cc)
    if not cc:
        raise ValueError('empty compiler command')
    root = args.repo_root.resolve()
    snapshots = {relative: (root / relative).read_bytes() for relative in INPUTS}
    try:
        test_snapshots(cc, args.sanitize, snapshots)
    finally:
        # Check even on compilation/test failure: live source/profile/fixtures
        # must never be modified or swapped unnoticed during the test run.
        for relative, before in snapshots.items():
            if (root / relative).read_bytes() != before:
                raise ValueError('input changed during tests: ' + relative)
    for relative, data in snapshots.items():
        print('SHA256', hashlib.sha256(data).hexdigest(), relative)
    print('LIMIT: host fake leaf and longjmp FIQ disposition only; NOT ARM execution, '
          'exception delivery, routing, hardware, or bus timeout proof')


if __name__ == '__main__':
    try:
        main()
    except (OSError, UnicodeError, ValueError, subprocess.SubprocessError) as error:
        raise SystemExit('FAIL: ' + str(error))
