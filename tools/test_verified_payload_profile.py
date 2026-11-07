#!/usr/bin/env python3
"""Synthetic-only tests: opaque ELF-ish bytes, no shell/compiler/build/device."""
from __future__ import annotations
import copy
import fcntl
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import create_verified_payload_profile as creator
import restore_verified_entry as reuse

BASE = Path(__file__).resolve().parents[1]


class PayloadProfileTests(unittest.TestCase):
    def setUp(self):
        # Retain fixtures in canonical system temp storage; never write repository outputs.
        self.root = Path(tempfile.mkdtemp(prefix='mi4-payload-synthetic-',
                         dir=Path(tempfile.gettempdir()).resolve())).resolve()
        self.run = self.root / 'out/prior'
        self.run.mkdir(parents=True)
        self.output = self.root / 'out/payload.json'
        self.prior_path = self.run / 'result.json'
        self.profile_path = self.root / 'wanted.json'
        self.input_names = ['tools/build_verified.py', 'src/entry/build_entry.sh', 'scripts/build.sh',
                            'src/entry/entry_usb_dev.h', 'external/xnu/source.c',
                            'src/stage90_guarded_read32.c', 'tools/check_dwc3_readonly_probe.py', 'src/stage90.h']
        for name in self.input_names:
            self.put(name, ('synthetic:' + name).encode())
        for name in creator.TOOLS:
            self.put(name, (BASE / name).read_bytes())
        self.put(creator.KSM, (reuse.sha(self.get('external/xnu/source.c')) + '  ' +
                              str(self.root / 'external/xnu/source.c') + '\n').encode())
        stages = []
        outputs = [['out/xnu_asm_obj_d13/' + n + '.o' for n in ('locore', 'traps_lo', 'cswitch')],
                   ['{run_dir}/legacy-locore.o'],
                   ['out/xnu_kernel_obj_d13/' + n + '.o' for n in ('pmap', 'arm_vm_init', 'commpage')] +
                   ['out/xnu_platform_obj_d13/root.o', creator.KSM], list(reuse.ENTRY),
                   ['out/stage90/stage90' + s for s in ('.elf', '.bin', '-qcdt.img', '-build-config.txt')]]
        argv = [['bash', 'tools/assemble_arm_layer.sh'], ['python3', 'tools/prepare_verified_entry.py'],
                ['bash', 'tools/build_xnu_arm_kernel.sh'], ['bash', 'build_entry.sh'], ['bash', 'scripts/build.sh']]
        for name, command, paths in zip(creator.NAMES, argv, outputs):
            stage = {'name': name, 'argv': command, 'outputs': paths, 'timeout_s': 60}
            if name in ('entry', 'payload'):
                stage['env'] = {'STAGE90_EXTRA_CFLAGS': '-DORIGINAL=1'}
            if name == 'entry':
                stage['cwd'] = 'src/entry'
            stages.append(stage)
            for path in paths:
                actual = creator.expand(path, self.root, self.run)
                if actual != creator.KSM:
                    self.put(reuse.relative(self.root, actual), b'ANDROID!opaque' if path.endswith('.img') else
                             b'\x7fELFopaque:' + path.encode())
        self.profile = {'version': 1, 'description': 'synthetic full build',
            'env': {'LC_ALL': 'C', 'XNU_TREE': '{repo_root}/external/xnu',
                    'STAGE90_ENTRY_LOCORE_OBJ': '{run_dir}/legacy-locore.o', 'STAGE90_EXTRA_CFLAGS': '-DGLOBAL=1'},
            'inputs': self.input_names, 'stages': stages, 'image': 'out/stage90/stage90-qcdt.img',
            'android_boot_header': True, 'symbols': [{'artifact': reuse.ENTRY[0], 'required': ['synthetic']}],
            'embedded': [{'container': 'out/stage90/stage90.bin', 'payload': reuse.ENTRY[1]}],
            'checks': [{'argv': ['python3', 'tools/check_dwc3_readonly_probe.py', '--synthetic', str(i)],
                        'timeout_s': 30} for i in range(27)]}
        self.prior = {'version': 1, 'status': 'verified', 'root': str(self.root),
            'env': {k: creator.expand(v, self.root, self.run) for k, v in self.profile['env'].items()},
            'stages': [], 'inputs': [reuse.record(self.root, n) for n in self.input_names],
            'checks': [{'argv': c['argv'], 'returncode': 0} for c in self.profile['checks']]}
        for stage in stages:
            self.prior['stages'].append({'name': stage['name'], 'argv': stage['argv'], 'returncode': 0,
                'env_overrides': copy.deepcopy(stage.get('env', {})), 'outputs': [reuse.record(self.root,
                reuse.relative(self.root, creator.expand(n, self.root, self.run))) for n in stage['outputs']]})
        self.prior['artifacts'] = [item for s in self.prior['stages'] for item in s['outputs']]
        image = self.get(self.profile['image'])
        self.put('out/prior/verified-image.img', image)
        self.prior['published_image'] = {'path': str(self.run / 'verified-image.img'), 'sha256': reuse.sha(image)}
        self.save_original()
        self.save()

    def put(self, name, data):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)

    def get(self, name):
        return (self.root / name).read_bytes()

    def save_original(self):
        raw = reuse.encoded(self.profile)
        self.put('out/prior/profile.json', raw)
        self.prior['profile_sha256'] = reuse.sha(raw)

    def save(self):
        self.profile_path.write_bytes(reuse.encoded(self.profile))
        self.prior_path.write_bytes(reuse.encoded(self.prior))

    def create(self, allowed=(), snapshot=None, recovery_to_identification=False,
               recovery_to_clock_snapshot=False, prior_build_script=None, recovery_to_root_snapshot=False):
        self.save()
        with (patch('subprocess.Popen', side_effect=AssertionError('no execution')),
              patch('subprocess.run', side_effect=AssertionError('no execution'))):
            return creator.create(self.profile_path, self.prior_path, self.output, snapshot, allowed,
                                  recovery_to_identification, recovery_to_clock_snapshot, prior_build_script,
                                  recovery_to_root_snapshot)

    def refuses(self, text=None, **kwargs):
        with self.assertRaises((ValueError, OSError)) as caught:
            self.create(**kwargs)
        if text:
            self.assertIn(text, str(caught.exception))
        self.assertFalse(self.output.exists())

    def restore(self, profile):
        args = profile['stages'][0]['argv']
        with reuse.build_lock(self.root), patch.dict(os.environ, {'MI4_VERIFIED_BUILD_RUN': str(self.run)}):
            return reuse.restore(self.root, args[args.index('--manifest') + 1], args[-1])

    def test_two_stages_unchanged_checks_and_fresh_identical_entry(self):
        before = {n: (self.get(n), (self.root / n).stat().st_mtime_ns) for n in reuse.ENTRY}
        result = self.create()
        self.assertEqual([s['name'] for s in result['stages']], ['verified-entry-reuse', 'payload'])
        for key in ('checks', 'symbols', 'embedded', 'env'):
            self.assertEqual(result[key], self.profile[key])
        self.assertEqual(result['stages'][1], self.profile['stages'][-1])
        self.assertIn('OLD', result['description'])
        self.assertEqual(self.restore(result), 0)
        for n, (data, old_time) in before.items():
            self.assertEqual(self.get(n), data)
            self.assertGreater((self.root / n).stat().st_mtime_ns, old_time)
        for manifest in result['input_manifests']:
            for item in json.loads(self.get(manifest)):
                reuse.checked(self.root, item)

    def test_failed_status(self):
        self.prior['status'] = 'failed'; self.refuses('fully verified')

    def test_partial_stage(self):
        self.prior['stages'].pop(); self.refuses('five')

    def test_failed_stage(self):
        self.prior['stages'][3]['returncode'] = 1; self.refuses('stage failed')

    def test_partial_checks(self):
        self.prior['checks'].pop(); self.refuses('checks partial')

    def test_failed_check(self):
        self.prior['checks'][0]['returncode'] = 1; self.refuses('check failed')

    def test_nonpayload_input_changed(self):
        self.put('src/entry/build_entry.sh', b'changed'); self.refuses('non-payload')

    def test_entry_artifact_changed(self):
        self.put(reuse.ENTRY[0], b'changed'); self.refuses('hash/size changed')

    def test_published_hash_bad(self):
        self.prior['published_image']['sha256'] = '0' * 64; self.refuses('published hash')

    def test_published_bytes_bad_no_fallback(self):
        self.put('out/prior/verified-image.img', b'bad'); self.refuses('hash/size changed')

    def test_fallback_artifact_hash(self):
        self.prior.pop('published_image'); self.create()

    def test_missing_source(self):
        self.profile['inputs'].append('missing.c'); self.refuses('input lists')

    def test_bad_hash_record(self):
        self.prior['inputs'][0]['sha256'] = 'bad'; self.refuses('bad/duplicate')

    def test_duplicate_paths(self):
        self.prior['inputs'].append(self.prior['inputs'][0]); self.refuses('bad/duplicate')

    def test_source_symlink(self):
        # A new alias is enough: no delete/move even in synthetic fixtures.
        alias = 'src/alias.c'; (self.root / alias).symlink_to('stage90.h')
        self.profile['inputs'].append(alias); self.save_original()
        self.prior['inputs'].append(dict(self.prior['inputs'][-1], path=alias))
        self.refuses()

    def test_existing_output(self):
        self.put('out/payload.json', b'keep')
        with self.assertRaises(ValueError): self.create()
        self.assertEqual(self.get('out/payload.json'), b'keep')

    def test_global_env_difference(self):
        self.profile['env']['STAGE90_EXTRA_CFLAGS'] += ' -DNEW=1'; self.refuses('environment')

    def test_entry_env_difference(self):
        self.profile['stages'][3]['env']['NEW'] = '1'; self.refuses('environment')

    def test_payload_env_only_cflags(self):
        self.profile['stages'][-1]['env']['STAGE90_EXTRA_CFLAGS'] += ' -DIRQ_ONLY=1'
        self.assertIn('-DIRQ_ONLY', self.create()['stages'][-1]['env']['STAGE90_EXTRA_CFLAGS'])

    def test_other_payload_env_refused(self):
        self.profile['stages'][-1]['env']['CC'] = 'other'; self.refuses('environment')

    def test_check_list_changed(self):
        self.profile['checks'].pop(); self.refuses('semantics')

    def test_kernel_manifest_changed(self):
        self.put(creator.KSM, b'bad'); self.refuses('hash/size changed')

    def test_compiled_source_changed(self):
        self.put('external/xnu/source.c', b'changed'); self.refuses('compiled kernel source')

    def test_explicit_payload_change(self):
        self.put('src/stage90_guarded_read32.c', b'future fix')
        result = self.create(('src/stage90_guarded_read32.c',))
        self.assertEqual(result['payload_only_reuse']['changed_payload_inputs'], ['src/stage90_guarded_read32.c'])

    def test_unlisted_payload_change_refused(self):
        self.put('src/stage90_guarded_read32.c', b'future fix'); self.refuses('non-payload')

    def test_wrong_allowlist(self):
        for name in ('src/entry/build_entry.sh', 'external/xnu/source.c', 'scripts/build.sh'):
            with self.subTest(name=name): self.refuses('allowlist', allowed=(name,))

    def test_header_compiled_manifest_cannot_be_bypassed(self):
        name = 'src/stage90.h'
        data = (reuse.sha(self.get(name)) + '  ' + str(self.root / name) + '\n').encode()
        self.put(creator.KSM, data)
        item = reuse.record(self.root, creator.KSM)
        self.prior['stages'][2]['outputs'][-1] = item
        self.prior['artifacts'] = [r for r in self.prior['artifacts'] if r['path'] != creator.KSM] + [item]
        self.put(name, b'changed'); self.refuses('compiled kernel source', allowed=(name,))

    def test_restore_modified_output_refuses_without_other_writes(self):
        result = self.create(); self.put(reuse.ENTRY[-1], b'full build changed it')
        times = [(self.root / n).stat().st_mtime_ns for n in reuse.ENTRY]
        with self.assertRaises(ValueError): self.restore(result)
        self.assertEqual(times, [(self.root / n).stat().st_mtime_ns for n in reuse.ENTRY])

    def test_snapshot_no_overwrite(self):
        snapshot = self.root / 'out/cache'; snapshot.mkdir()
        self.refuses(snapshot=snapshot)

    def test_output_parent_symlink(self):
        (self.root / 'out/link').symlink_to(self.run, target_is_directory=True)
        self.output = self.root / 'out/link/new.json'; self.refuses()

    def test_lock_contention(self):
        with reuse.build_lock(self.root): self.refuses('another verified build')

    def test_restore_needs_builder_lock(self):
        result = self.create(); args = result['stages'][0]['argv']
        with patch.dict(os.environ, {'MI4_VERIFIED_BUILD_RUN': str(self.run)}):
            with self.assertRaisesRegex(ValueError, 'builder-held'):
                reuse.restore(self.root, args[-3], args[-1])

    def test_snapshot_hash_tamper(self):
        result = self.create(); args = result['stages'][0]['argv']; self.put(args[-3], b'{}')
        with self.assertRaisesRegex(ValueError, 'manifest hash'): self.restore(result)

    def test_new_payload_input_explicitly_allowed(self):
        name = 'src/stage90_guarded_read32.h'
        self.put(name, b'new guarded header'); self.profile['inputs'].append(name)
        result = self.create((name,))
        self.assertEqual(result['payload_only_reuse']['added_payload_inputs'], [name])
        self.assertTrue(set(self.input_names) <= set(result['inputs']))

    def test_new_payload_input_without_opt_in_refused(self):
        self.put('src/stage90_guarded_read32.h', b'new')
        self.profile['inputs'].append('src/stage90_guarded_read32.h'); self.refuses('input lists')

    def test_prior_input_cannot_be_dropped(self):
        self.profile['inputs'] = self.profile['inputs'][:-1]; self.refuses('input lists')

    def test_missing_compiled_file(self):
        data = ('0' * 64 + '  ' + str(self.root / 'external/xnu/absent.c') + '\n').encode()
        self.put(creator.KSM, data)
        self.prior['stages'][2]['outputs'][-1] = reuse.record(self.root, creator.KSM)
        self.refuses()

    def test_prior_profile_hash_required(self):
        self.put('out/prior/profile.json', b'{}'); self.refuses('prior profile hash')
    def recovery_fixture(self):
        flags = '-DORIGINAL=1 -DSTAGE90_GUARDED_IRQ_ONLY=1 -DSTAGE90_DWC3_READONLY=1 -DSTAGE90_DWC3_TARGET_READS=0'
        self.profile['stages'][-1]['env']['STAGE90_EXTRA_CFLAGS'] = flags
        self.prior['stages'][-1]['env_overrides']['STAGE90_EXTRA_CFLAGS'] = flags
        self.profile['checks'] = copy.deepcopy(self.profile['checks'][:26]) + [
            {'argv': ['python3', 'synthetic-extra-check.py', str(i)], 'timeout_s': 30} for i in range(2)] + [
            {'argv': list(creator.IDENT_CHECK) + ['--recovery-only'], 'timeout_s': 180}]
        self.prior['checks'] = [{'argv': copy.deepcopy(c['argv']), 'returncode': 0}
                                for c in self.profile['checks']]
        self.save_original()
        self.recovery_profile = copy.deepcopy(self.profile)
        self.profile['stages'][-1]['env']['STAGE90_EXTRA_CFLAGS'] = flags.replace('TARGET_READS=0', 'TARGET_READS=1')
        self.profile['checks'][-1]['argv'].pop()

    def test_recovery_transition_exact_and_default_off(self):
        self.recovery_fixture(); self.refuses('semantics')
        result = self.create(recovery_to_identification=True)
        self.assertEqual(len(result['checks']), 29)
        self.assertEqual(result['checks'][:-1], self.recovery_profile['checks'][:-1])
        self.assertEqual(result['checks'][-1]['argv'], creator.IDENT_CHECK)
        self.assertNotIn('--recovery-only', result['checks'][-1]['argv'])
        self.assertEqual([s['name'] for s in result['stages']], ['verified-entry-reuse', 'payload'])
        self.assertTrue(result['payload_only_reuse']['recovery_to_identification'])
        self.assertEqual(result['payload_only_reuse']['changed_payload_inputs'], [])
        for key in ('env', 'symbols', 'embedded'):
            self.assertEqual(result[key], self.recovery_profile[key])
        self.assertEqual(self.restore(result), 0)

    def test_recovery_transition_rejects_every_unrelated_change(self):
        mutations = [
            ('target unchanged', lambda: self.profile['stages'][-1]['env'].update(
                STAGE90_EXTRA_CFLAGS=self.recovery_profile['stages'][-1]['env']['STAGE90_EXTRA_CFLAGS'])),
            ('extra flag', lambda: self.profile['stages'][-1]['env'].update(
                STAGE90_EXTRA_CFLAGS=self.profile['stages'][-1]['env']['STAGE90_EXTRA_CFLAGS'] + ' -DOTHER=1')),
            ('duplicate IRQ', lambda: self.profile['stages'][-1]['env'].update(
                STAGE90_EXTRA_CFLAGS=self.profile['stages'][-1]['env']['STAGE90_EXTRA_CFLAGS'] + ' ' + creator.IRQ_ONLY)),
            ('wrong readonly', lambda: self.profile['stages'][-1]['env'].update(
                STAGE90_EXTRA_CFLAGS=self.profile['stages'][-1]['env']['STAGE90_EXTRA_CFLAGS'].replace('READONLY=1', 'READONLY=0'))),
            ('other config', lambda: self.profile.update(android_boot_header=False)),
            ('other check argv', lambda: self.profile['checks'][0]['argv'].append('--waived')),
            ('other check timeout', lambda: self.profile['checks'][0].update(timeout_s=1)),
            ('last timeout', lambda: self.profile['checks'][-1].update(timeout_s=1)),
            ('missing irq mode', lambda: self.profile['checks'][-1]['argv'].pop()),
            ('payload input bytes', lambda: self.put('src/stage90_guarded_read32.c', b'changed')),
            ('global env', lambda: self.profile['env'].update(STAGE90_EXTRA_CFLAGS='changed')),
            ('input added', lambda: self.profile['inputs'].append('src/stage90_guarded_read32.h'))]
        for label, mutate in mutations:
            with self.subTest(case=label):
                self.setUp(); self.recovery_fixture(); mutate()
                self.refuses(recovery_to_identification=True)

    def test_recovery_transition_disallows_allowlist_even_unchanged(self):
        self.recovery_fixture()
        self.refuses('forbids --allow-payload-input', allowed=('src/stage90_guarded_read32.c',),
                     recovery_to_identification=True)

    def test_recovery_transition_count_from_original_not_constant(self):
        self.recovery_fixture()
        self.profile = copy.deepcopy(self.recovery_profile)
        self.profile['checks'].insert(0, {'argv': ['python3', 'extra.py'], 'timeout_s': 12})
        self.prior['checks'].insert(0, {'argv': ['python3', 'extra.py'], 'returncode': 0})
        self.save_original()
        self.profile['stages'][-1]['env']['STAGE90_EXTRA_CFLAGS'] = self.profile['stages'][-1]['env'][
            'STAGE90_EXTRA_CFLAGS'].replace('TARGET_READS=0', 'TARGET_READS=1')
        self.profile['checks'][-1]['argv'].pop()
        self.assertEqual(len(self.create(recovery_to_identification=True)['checks']), 30)

    def clock_fixture(self):
        self.recovery_fixture()
        self.profile = copy.deepcopy(self.recovery_profile)
        for name in sorted(creator.CLOCK_INPUTS - set(self.profile['inputs'])):
            self.put(name, ('prior:' + name).encode())
            self.profile['inputs'].append(name)
            self.prior['inputs'].append(reuse.record(self.root, name))
        baseline = b'#!/bin/sh\n# synthetic config record\n' + creator.SCRIPT_OLD + b'\n'
        self.put('scripts/build.sh', baseline)
        self.prior['inputs'] = [reuse.record(self.root, n['path']) for n in self.prior['inputs']]
        self.put('out/prior-build.sh', baseline)
        self.save_original()
        self.clock_original = copy.deepcopy(self.profile)
        env = self.profile['stages'][-1]['env']
        env['STAGE90_EXTRA_CFLAGS'] = env['STAGE90_EXTRA_CFLAGS'].replace('TARGET_READS=0', 'TARGET_READS=1')
        env['STAGE90_EXTRA_CFLAGS'] += ' ' + creator.CLOCK_FLAG
        self.profile['checks'][-1]['argv'][-1] = '--clock-snapshot'
        self.put('scripts/build.sh', baseline.replace(creator.SCRIPT_OLD, creator.SCRIPT_NEW))
        return {'recovery_to_clock_snapshot': True, 'prior_build_script': self.root / 'out/prior-build.sh'}

    def test_clock_transition_cli_and_mutual_exclusion(self):
        options = self.clock_fixture(); self.save()
        argv = ['creator', '--profile', str(self.profile_path), '--prior-result', str(self.prior_path),
                '--output', str(self.output), '--recovery-to-clock-snapshot', '--prior-build-script',
                str(options['prior_build_script'])]
        with (patch('sys.argv', argv), patch('subprocess.Popen', side_effect=AssertionError('no execution')),
              patch('subprocess.run', side_effect=AssertionError('no execution'))):
            self.assertEqual(creator.main(), 0)
        self.assertEqual(len(json.loads(self.output.read_bytes())['checks']), 29)
        with patch('sys.argv', argv + ['--recovery-to-identification']):
            with self.assertRaises(SystemExit) as caught:
                creator.main()
        self.assertEqual(caught.exception.code, 2)

    def test_clock_transition_exact_proof_and_six_explicit_inputs(self):
        options = self.clock_fixture()
        for name in creator.CLOCK_INPUTS:
            self.put(name, ('clock update:' + name).encode())
        result = self.create(allowed=tuple(sorted(creator.CLOCK_INPUTS)), **options)
        self.assertEqual(result['checks'][:-1], self.clock_original['checks'][:-1])
        self.assertEqual(result['checks'][-1]['argv'], creator.IDENT_CHECK + ['--clock-snapshot'])
        self.assertEqual(len(result['checks']), 29)
        self.assertEqual([s['name'] for s in result['stages']], ['verified-entry-reuse', 'payload'])
        proof = result['payload_only_reuse']
        self.assertTrue(proof['recovery_to_clock_snapshot'])
        self.assertFalse(proof['recovery_to_identification'])
        self.assertEqual(set(proof['changed_payload_inputs']), creator.CLOCK_INPUTS | {'scripts/build.sh'})
        self.assertEqual(proof['added_payload_inputs'], [])
        for key in ('env', 'symbols', 'embedded'):
            self.assertEqual(result[key], self.clock_original[key])
        reuse.checked(self.root, proof['prior_build_script'])
        for manifest in result['input_manifests']:
            pins = json.loads(self.get(manifest))
            for pin in pins:
                reuse.checked(self.root, pin)
            saved = next(pin for pin in pins if pin['path'].endswith('/prior-build.sh') and
                         '.snapshot/' in pin['path'])
            self.assertEqual(saved['sha256'], proof['prior_build_script']['sha256'])
        self.assertEqual(self.restore(result), 0)

    def test_clock_transition_rejects_unproved_or_unrelated_changes(self):
        mutations = [
            ('baseline bytes', lambda: self.put('out/prior-build.sh', b'wrong baseline')),
            ('extra script edit', lambda: self.put('scripts/build.sh', self.get('scripts/build.sh') + b'extra')),
            ('script unchanged', lambda: self.put('scripts/build.sh', self.get('out/prior-build.sh'))),
            ('unlisted payload', lambda: self.put('src/dwc3_identify.c', b'unlisted')),
            ('header change', lambda: self.put('src/stage90.h', b'changed')),
            ('entry change', lambda: self.put('src/entry/build_entry.sh', b'changed')),
            ('compiled source change', lambda: self.put('external/xnu/source.c', b'changed')),
            ('new input', lambda: self.profile['inputs'].append('src/new.h')),
            ('drop input', lambda: self.profile['inputs'].pop()),
            ('reorder input', lambda: self.profile['inputs'].reverse()),
            ('wrong checker', lambda: self.profile['checks'][-1]['argv'].append('--recovery-only')),
            ('irq removed', lambda: self.profile['checks'][-1]['argv'].remove('--irq-only')),
            ('other check', lambda: self.profile['checks'][0]['argv'].append('--skip')),
            ('last timeout', lambda: self.profile['checks'][-1].update(timeout_s=1)),
            ('global env', lambda: self.profile['env'].update(STAGE90_EXTRA_CFLAGS='changed')),
            ('other flag', lambda: self.profile['stages'][-1]['env'].update(
                STAGE90_EXTRA_CFLAGS=self.profile['stages'][-1]['env']['STAGE90_EXTRA_CFLAGS'] + ' -DOTHER=1')),
            ('clock duplicated', lambda: self.profile['stages'][-1]['env'].update(
                STAGE90_EXTRA_CFLAGS=self.profile['stages'][-1]['env']['STAGE90_EXTRA_CFLAGS'] + ' ' + creator.CLOCK_FLAG)),
            ('clock absent', lambda: self.profile['stages'][-1]['env'].update(
                STAGE90_EXTRA_CFLAGS=self.profile['stages'][-1]['env']['STAGE90_EXTRA_CFLAGS'].replace(' ' + creator.CLOCK_FLAG, ''))),
            ('wrong target', lambda: self.profile['stages'][-1]['env'].update(
                STAGE90_EXTRA_CFLAGS=self.profile['stages'][-1]['env']['STAGE90_EXTRA_CFLAGS'].replace('TARGET_READS=1', 'TARGET_READS=0')))]
        for label, mutate in mutations:
            with self.subTest(case=label):
                self.setUp(); options = self.clock_fixture(); mutate(); self.refuses(**options)

    def test_clock_transition_requires_mode_and_prior_script(self):
        options = self.clock_fixture()
        self.refuses('required only', recovery_to_clock_snapshot=True)
        self.refuses('required only', prior_build_script=options['prior_build_script'])
        self.refuses('mutually exclusive', recovery_to_identification=True, **options)
        for name in ('scripts/build.sh', 'src/stage90.h', 'src/stage90_guarded_read32.c'):
            with self.subTest(name=name):
                self.refuses('allowlist', allowed=(name,), **options)

    def test_clock_prior_script_symlink_and_wrong_location(self):
        options = self.clock_fixture()
        alias = self.root / 'out/prior-link.sh'; alias.symlink_to('prior-build.sh')
        self.refuses('canonical', recovery_to_clock_snapshot=True, prior_build_script=alias)
        self.put('prior-build.sh', self.get('out/prior-build.sh'))
        self.refuses('root/out', recovery_to_clock_snapshot=True, prior_build_script=self.root / 'prior-build.sh')

    def test_clock_old_flag_absent_and_regex_unique_mandatory(self):
        for flag in (' -DSTAGE90_DWC3_CLOCK_SNAPSHOT=0', ' -DSTAGE90_DWC3_CLOCK_SNAPSHOT=1'):
            with self.subTest(flag=flag):
                self.setUp(); options = self.clock_fixture()
                old = copy.deepcopy(self.clock_original)
                old['stages'][-1]['env']['STAGE90_EXTRA_CFLAGS'] += flag
                self.put('out/prior/profile.json', reuse.encoded(old))
                self.prior['profile_sha256'] = reuse.sha(reuse.encoded(old))
                self.refuses('old recovery', **options)
        self.setUp(); options = self.clock_fixture()
        duplicate = self.get('out/prior-build.sh') + creator.SCRIPT_OLD
        self.put('out/prior-build.sh', duplicate)
        for item in self.prior['inputs']:
            if item['path'] == 'scripts/build.sh': item.update(size=len(duplicate), sha256=reuse.sha(duplicate))
        self.refuses('unique original config regex', **options)

    def test_clock_allowlist_cannot_bypass_compiled_source_pin(self):
        options = self.clock_fixture(); name = 'src/dwc3_identify.c'
        data = (reuse.sha(self.get(name)) + '  ' + str(self.root / name) + '\n').encode()
        self.put(creator.KSM, data)
        item = reuse.record(self.root, creator.KSM)
        self.prior['stages'][2]['outputs'][-1] = item
        self.prior['artifacts'] = [r for r in self.prior['artifacts'] if r['path'] != creator.KSM] + [item]
        self.put(name, b'changed')
        self.refuses('compiled kernel source', allowed=(name,), **options)

    def root_fixture(self):
        options = self.clock_fixture()
        options.pop('recovery_to_clock_snapshot')
        options['recovery_to_root_snapshot'] = True
        self.profile['stages'][-1]['env']['STAGE90_EXTRA_CFLAGS'] += ' ' + creator.ROOT_FLAG
        self.profile['checks'][-1]['argv'][-1] = '--root-snapshot'
        self.put('scripts/build.sh', self.get('out/prior-build.sh').replace(creator.SCRIPT_OLD, creator.SCRIPT_ROOT))
        return options

    def test_root_transition_cli_and_exact_proof(self):
        options = self.root_fixture()
        for name in creator.CLOCK_INPUTS:
            self.put(name, ('root update:' + name).encode())
        self.save()
        argv = ['creator', '--profile', str(self.profile_path), '--prior-result', str(self.prior_path),
                '--output', str(self.output), '--recovery-to-root-snapshot', '--prior-build-script',
                str(options['prior_build_script'])]
        for name in sorted(creator.CLOCK_INPUTS):
            argv.extend(['--allow-payload-input', name])
        with (patch('sys.argv', argv), patch('subprocess.Popen', side_effect=AssertionError('no execution')),
              patch('subprocess.run', side_effect=AssertionError('no execution'))):
            self.assertEqual(creator.main(), 0)
        result = json.loads(self.output.read_bytes())
        self.assertEqual(result['checks'][:-1], self.clock_original['checks'][:-1])
        self.assertEqual(result['checks'][-1]['argv'], creator.IDENT_CHECK + ['--root-snapshot'])
        self.assertEqual(len(result['checks']), 29)
        self.assertEqual([s['name'] for s in result['stages']], ['verified-entry-reuse', 'payload'])
        proof = result['payload_only_reuse']
        self.assertTrue(proof['recovery_to_root_snapshot'])
        self.assertFalse(proof['recovery_to_clock_snapshot'])
        self.assertFalse(proof['recovery_to_identification'])
        self.assertEqual(set(proof['changed_payload_inputs']), creator.CLOCK_INPUTS | {'scripts/build.sh'})
        self.assertEqual(proof['added_payload_inputs'], [])
        for key in ('env', 'symbols', 'embedded'):
            self.assertEqual(result[key], self.clock_original[key])
        for pin in json.loads(self.get(result['input_manifests'][0])):
            reuse.checked(self.root, pin)
        self.assertEqual(self.restore(result), 0)
        for conflict in ('--recovery-to-identification', '--recovery-to-clock-snapshot'):
            with self.subTest(conflict=conflict), patch('sys.argv', argv + [conflict]):
                with self.assertRaises(SystemExit) as caught:
                    creator.main()
                self.assertEqual(caught.exception.code, 2)

    def test_root_transition_eight_rejected_mutations(self):
        mutations = [
            ('root absent', lambda: self.profile['stages'][-1]['env'].update(
                STAGE90_EXTRA_CFLAGS=self.profile['stages'][-1]['env']['STAGE90_EXTRA_CFLAGS'].replace(' ' + creator.ROOT_FLAG, ''))),
            ('root duplicate', lambda: self.profile['stages'][-1]['env'].update(
                STAGE90_EXTRA_CFLAGS=self.profile['stages'][-1]['env']['STAGE90_EXTRA_CFLAGS'] + ' ' + creator.ROOT_FLAG)),
            ('root wrong value', lambda: self.profile['stages'][-1]['env'].update(
                STAGE90_EXTRA_CFLAGS=self.profile['stages'][-1]['env']['STAGE90_EXTRA_CFLAGS'].replace('ROOT_SNAPSHOT=1', 'ROOT_SNAPSHOT=0'))),
            ('append order', lambda: self.profile['stages'][-1]['env'].update(
                STAGE90_EXTRA_CFLAGS=self.profile['stages'][-1]['env']['STAGE90_EXTRA_CFLAGS'].replace(
                    creator.CLOCK_FLAG + ' ' + creator.ROOT_FLAG, creator.ROOT_FLAG + ' ' + creator.CLOCK_FLAG))),
            ('clock script only', lambda: self.put('scripts/build.sh', self.get('out/prior-build.sh').replace(
                creator.SCRIPT_OLD, creator.SCRIPT_NEW))),
            ('extra script bytes', lambda: self.put('scripts/build.sh', self.get('scripts/build.sh') + b'extra')),
            ('clock checker', lambda: self.profile['checks'][-1]['argv'].__setitem__(-1, '--clock-snapshot')),
            ('other check', lambda: self.profile['checks'][0].update(timeout_s=1))]
        for label, mutate in mutations:
            with self.subTest(case=label):
                self.setUp(); options = self.root_fixture(); mutate(); self.refuses(**options)

    def test_root_transition_old_flag_absence_and_cross_modes(self):
        for value in ('0', '1'):
            with self.subTest(old_root=value):
                self.setUp(); options = self.root_fixture(); old = copy.deepcopy(self.clock_original)
                old['stages'][-1]['env']['STAGE90_EXTRA_CFLAGS'] += ' -DSTAGE90_DWC3_ROOT_SNAPSHOT=' + value
                self.put('out/prior/profile.json', reuse.encoded(old))
                self.prior['profile_sha256'] = reuse.sha(reuse.encoded(old))
                self.refuses('old recovery', **options)
        self.setUp(); options = self.root_fixture()
        self.refuses('required only', recovery_to_root_snapshot=True)
        for mode in ('recovery_to_clock_snapshot', 'recovery_to_identification'):
            with self.subTest(mode=mode):
                self.refuses('mutually exclusive', **options, **{mode: True})
        self.refuses('checker argv', recovery_to_clock_snapshot=True,
                     prior_build_script=options['prior_build_script'])
        self.profile['checks'][-1]['argv'][-1] = '--clock-snapshot'
        flags = self.profile['stages'][-1]['env']['STAGE90_EXTRA_CFLAGS']
        self.profile['stages'][-1]['env']['STAGE90_EXTRA_CFLAGS'] = flags.replace(' ' + creator.ROOT_FLAG, '')
        self.refuses('build script differs', recovery_to_clock_snapshot=True,
                     prior_build_script=options['prior_build_script'])

    def test_root_transition_original_count_and_strict_inputs(self):
        options = self.root_fixture()
        self.put('src/stage90.h', b'changed'); self.refuses('non-payload', **options)
        self.setUp(); options = self.root_fixture()
        self.refuses('allowlist', allowed=('scripts/build.sh',), **options)
        self.refuses('allowlist', allowed=('src/stage90.h',), **options)
        old = copy.deepcopy(self.clock_original)
        extra = {'argv': ['python3', 'another-check.py'], 'timeout_s': 9}
        old['checks'].insert(0, copy.deepcopy(extra))
        self.put('out/prior/profile.json', reuse.encoded(old))
        self.prior['profile_sha256'] = reuse.sha(reuse.encoded(old))
        self.prior['checks'].insert(0, {'argv': extra['argv'], 'returncode': 0})
        self.profile['checks'].insert(0, extra)
        self.assertEqual(len(self.create(**options)['checks']), 30)


if __name__ == '__main__':
    unittest.main(verbosity=2)
