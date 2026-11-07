#!/usr/bin/env python3
"""Run actual guarded-read C with a host-only fake leaf; never executes ARM/MMIO."""
import argparse
import hashlib
from pathlib import Path
import shlex
import subprocess
import tempfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repo-root', type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument('--cc', default='cc')
    parser.add_argument('--sanitize', action='store_true')
    args = parser.parse_args()
    root = args.repo_root.resolve()
    paths = [root/'src/stage90_guarded_read32.h', root/'src/stage90_guarded_read32.c',
             root/'tools/fixtures/dwc3_guarded_read32_harness.c']
    snapshots = [p.read_bytes() for p in paths]
    source = snapshots[1].decode()
    cc = shlex.split(args.cc)
    if not cc:
        raise ValueError('empty compiler command')
    with tempfile.TemporaryDirectory(prefix='mi4-guarded-read32-') as name:
        temp = Path(name)
        (temp/'stage90_guarded_read32.h').write_bytes(snapshots[0])
        (temp/'harness.c').write_bytes(snapshots[2])
        def run(label, text, negative=False):
            candidate = temp/(label+'.c')
            candidate.write_text(text)
            output = temp/label
            flags = ['-std=c11', '-O2', '-Wall', '-Wextra', '-Werror', '-pedantic',
                     '-fno-common', '-I', str(temp)]
            if args.sanitize:
                flags += ['-fsanitize=address,undefined', '-fno-omit-frame-pointer']
            built = subprocess.run(cc+flags+[str(candidate), str(temp/'harness.c'), '-o', str(output)],
                                   text=True, capture_output=True, timeout=30)
            if built.returncode:
                raise ValueError(label+' compile failed: '+built.stderr)
            result = subprocess.run([str(output)], text=True, capture_output=True, timeout=15)
            if negative:
                if result.returncode != 1 or 'FAIL line ' not in result.stderr:
                    raise ValueError('negative must fail behavior: '+label+'\n'+result.stdout+result.stderr)
                print('PASS negative', label, 'rejected by actual C behavior')
            else:
                if result.returncode:
                    raise ValueError('actual C failed: '+result.stdout+result.stderr)
                print(result.stdout, end='')
        run('actual', source)
        controls = [
            ('mask-readback', '(state->cpsr_after_mask & 0xc0u) != 0xc0u', '0'),
            ('wrong-pc', 'frame[5] == state->fault_pc &&', '(1) &&'),
            ('imprecise', 'case 0x03u: /* access flag, section */',
             'case 0x16u:\n    case 0x03u: /* access flag, section */'),
            ('false-success',
             'if (rc == 0 && state->active == 1u && state->status == STAGE90_GUARDED_ARMED &&\n        state->fault_count == 0u)',
             'if (rc == 0)')]
        for label, old, new in controls:
            if source.count(old) != 1:
                raise ValueError('changed mutation anchor '+label)
            run(label, source.replace(old, new, 1), True)
    for path, before in zip(paths, snapshots):
        if path.read_bytes() != before:
            raise ValueError('input changed during tests '+str(path))
        print('SHA256', hashlib.sha256(before).hexdigest(), path.name)
    print('LIMIT: host fake leaf only; not exception delivery, hardware or bus timeout proof')


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        raise SystemExit('FAIL: '+str(error))
