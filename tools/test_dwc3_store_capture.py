#!/usr/bin/env python3
"""Synthetic store-console tests only: no device, compiler, or private log."""
import contextlib
import importlib.util
import io
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location('dwc3_store_capture',
    Path(__file__).resolve().with_name('check_dwc3_store_capture.py'))
CAPTURE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CAPTURE)


def value(key, number):
    return key + '=0x%08x' % number


def console():
    read = [('ram_address', 0x780000), ('ram_result', 0),
        ('cpsr_before', 0x60000113), ('cpsr_after', 0x60000193),
        ('fault_address', 0xdeadc000), ('fault_result', 2), ('fault_dfsr', 5),
        ('fault_dfar', 0xdeadc000), ('fault_pc', 0x782000),
        ('fault_spsr', 0x20000193), ('fault_count', 1), ('fault_active', 0),
        ('fault_status', 2), ('fault_output', 0xa55a12ed),
        ('fault_expected_pc', 0x782000), ('fault_cpsr_before', 0x60000113),
        ('fault_cpsr_after', 0x60000193)]
    store = [('ram_address', 0x783000), ('ram_before_result', 0),
        ('ram_before_value', 0xa55a12ed), ('ram_value', 0x53545231),
        ('ram_result', 0), ('ram_active', 0), ('ram_status', 3), ('ram_count', 0),
        ('ram_operation', 1), ('ram_cpsr_before', 0x60000113),
        ('ram_cpsr_after', 0x60000193), ('cpsr_restored', 0x20000113),
        ('ram_readback_result', 0), ('ram_readback_value', 0x53545231),
        ('fault_address', 0xdeadc000), ('fault_value', 0xfeed1234),
        ('fault_result', 8), ('fault_dfsr', 0x805), ('fault_dfar', 0xdeadc000),
        ('fault_pc', 0x782100), ('fault_expected_pc', 0x782100),
        ('fault_spsr', 0x20000193), ('fault_count', 1), ('fault_active', 0),
        ('fault_status', 8), ('fault_operation', 1),
        ('fault_cpsr_before', 0x60000113), ('fault_cpsr_after', 0x60000193),
        ('fault_cpsr_restored', 0x20000113)]
    return '\n'.join([CAPTURE.START] +
        [value('dwc3_ro_guard_' + key, number) for key, number in read] +
        [CAPTURE.SELFTEST] +
        [value('dwc3_store_' + key, number) for key, number in store] + [CAPTURE.FINISH])


class StoreCaptureTests(unittest.TestCase):
    def reject_value(self, key, numbers):
        text = console()
        line = next(line for line in text.splitlines() if line.startswith(key + '='))
        for number in numbers:
            with self.subTest(key=key, number=hex(number)):
                with self.assertRaises(ValueError):
                    CAPTURE.analyze(text.replace(line, value(key, number)))

    def test_positive_indeterminate_is_not_usb_or_mmio_authorization(self):
        report = CAPTURE.analyze(console())
        self.assertTrue(report['store_selftest_passed'])
        self.assertTrue(report['controller_target_reads_inhibited'])
        self.assertTrue(report['write_fault_indeterminate'])
        self.assertEqual(report['write_fault_result'], 8)
        self.assertEqual(report['scope'], 'guarded-ram-store-selftest-only')
        self.assertEqual(report['ram_store_count'], 1)
        self.assertEqual(report['unmapped_store_attempts'], 1)
        self.assertIn('not proof of unchanged target', report['write_fault_semantics'])
        for key in ('identification_passed', 'usb_link_proved', 'mmio_writes_allowed',
                    'clock_write_authorized', 'ownership_or_mapping_proved'):
            self.assertFalse(report[key])

    def test_ram_before_and_readback(self):
        for key, numbers in [('ram_before_result', [2, 6]), ('ram_before_value', [0, 0x53545231]),
            ('ram_readback_result', [2, 6]), ('ram_readback_value', [0, 0xa55a12ed]),
            ('ram_value', [0, 0xfeed1234])]:
            self.reject_value('dwc3_store_' + key, numbers)

    def test_ram_store_state(self):
        for key, numbers in [('ram_result', [2, 6, 8]), ('ram_active', [1]),
            ('ram_status', [0, 2, 8]), ('ram_count', [1]), ('ram_operation', [0, 2])]:
            self.reject_value('dwc3_store_' + key, numbers)

    def test_fault_store_state_and_intent(self):
        for key, numbers in [('fault_result', [0, 2, 6]), ('fault_status', [0, 2, 3]),
            ('fault_count', [0, 2]), ('fault_active', [1]), ('fault_operation', [0, 2]),
            ('fault_value', [0, 0x53545231]), ('fault_address', [0x783000, 0xdeadc004]),
            ('fault_dfar', [0x783000, 0xdeadc004])]:
            self.reject_value('dwc3_store_' + key, numbers)

    def test_write_dfsr_read_external_reserved_and_other_faults(self):
        self.reject_value('dwc3_store_fault_dfsr',
                          [5, 0x807, 0x808, 0x80d, 0xc05, 0xa05, 0x2805, 0x80000805])

    def test_write_dfsr_permitted_domain_and_ext_bits(self):
        for word in (0x805, 0x8f5, 0x1805, 0x18f5):
            text = console().replace(value('dwc3_store_fault_dfsr', 0x805),
                                     value('dwc3_store_fault_dfsr', word))
            self.assertTrue(CAPTURE.analyze(text)['store_selftest_passed'])

    def test_read_guard_must_pass_including_legacy_result_six(self):
        for key, numbers in [('ram_result', [2, 6]), ('fault_result', [0, 6, 8]),
            ('fault_dfsr', [0x805, 0x205, 0x80000005, 7]), ('fault_dfar', [0xdeadc004]),
            ('fault_address', [0x783000]), ('fault_count', [0, 2]), ('fault_active', [1]),
            ('fault_status', [3, 8]), ('fault_output', [0])]:
            self.reject_value('dwc3_ro_guard_' + key, numbers)

    def test_exact_distinct_aligned_fault_pcs(self):
        for prefix in ('dwc3_ro_guard_', 'dwc3_store_'):
            for key in ('fault_pc', 'fault_expected_pc'):
                self.reject_value(prefix + key, [0, 0x782004, 0x782002])
        text = console().replace('0x00782100', '0x00782000')
        with self.assertRaises(ValueError):
            CAPTURE.analyze(text)

    def test_ram_window_alignment_and_not_mmio(self):
        for key in ('dwc3_store_ram_address', 'dwc3_ro_guard_ram_address'):
            self.reject_value(key, [0, 0x7ffc, 0x783001, 0x4000000, 0xdeadc000, 0xf920c120])

    def test_pre_and_post_mode_masks(self):
        for prefix in ('dwc3_ro_guard_', 'dwc3_ro_guard_fault_',
                       'dwc3_store_ram_', 'dwc3_store_fault_'):
            self.reject_value(prefix + 'cpsr_before', [0x60000193, 0x60000133, 0x61000113])
            self.reject_value(prefix + 'cpsr_after', [0x60000113, 0x600001d3, 0x60000093,
                                                    0x60000393, 0x61000193])

    def test_stable_spsr_excludes_abort_auto_a(self):
        for key in ('dwc3_ro_guard_fault_spsr', 'dwc3_store_fault_spsr'):
            self.reject_value(key, [0x200001d3, 0x20000113, 0x21000193, 0x20000393])
            text = console().replace(value(key, 0x20000193), value(key, 0xa0000093))
            self.assertTrue(CAPTURE.analyze(text)['store_selftest_passed'])

    def test_restoration_preserves_a_f_i_mode_not_nzcv(self):
        for key in ('dwc3_store_cpsr_restored', 'dwc3_store_fault_cpsr_restored'):
            self.reject_value(key, [0x20000193, 0x20000153, 0x20000013, 0x21000113, 0x20000133])
        text = console().replace('0x60000113', '0x60000153').replace('0x60000193', '0x600001d3')
        text = text.replace('0x20000113', '0x20000153').replace('0x20000193', '0x200001d3')
        self.assertTrue(CAPTURE.analyze(text)['store_selftest_passed'])

    def test_every_field_required_and_unique(self):
        text = console()
        for line in text.splitlines():
            with self.subTest(line=line):
                for mutated in (text.replace(line, '', 1), text + '\n' + line):
                    with self.assertRaises(ValueError):
                        CAPTURE.analyze(mutated)

    def test_retry_and_reordering(self):
        lines = console().splitlines()
        a = lines.index(value('dwc3_store_ram_result', 0))
        b = lines.index(value('dwc3_store_ram_readback_result', 0))
        for extra in ('\n'.join(lines[a:b]), console()):
            with self.assertRaises(ValueError):
                CAPTURE.analyze(console() + '\n' + extra)
        lines[a], lines[b] = lines[b], lines[a]
        with self.assertRaises(ValueError):
            CAPTURE.analyze('\n'.join(lines))

    def test_other_modes_target_reads_and_encoded_writes(self):
        extras = ['DWC3 read-only identity probe; no USB initialization',
            'DWC3 read-only GCC root snapshot; no DWC3 core reads',
            'dwc3_ro finished; identification is not a USB link',
            'dwc3_ro finished; GCC clock snapshot only; no DWC3 core reads',
            'dwc3_ro recovery verified; controller target reads inhibited']
        extras += [value(key, 0xf920c120) for key in ('dwc3_ro_read_index',
            'dwc3_ro_read_address', 'dwc3_ro_watchdog_read_address', 'dwc3_ro_status',
            'dwc3_ro_root_valid', 'dwc3_ro_completed_reads', 'dwc3_ro_write_address',
            'dwc3_store_core_write_result', 'dwc3_store_retry_result')]
        for extra in extras:
            for text in (extra + '\n' + console(), console() + '\n' + extra):
                with self.subTest(extra=extra), self.assertRaises(ValueError):
                    CAPTURE.analyze(text)

    def test_skips_never_pass_or_echo_private_reason(self):
        for reason in ('guard STORE RAM selftest failed',
            'guard STORE translation-fault selftest failed', 'CPU/MMU/vector precondition',
            'recovery net not confirmed', 'private serial or source path'):
            for text in (CAPTURE.START, console()):
                with self.assertRaises(ValueError) as raised:
                    CAPTURE.analyze(text + '\ndwc3_ro skipped: ' + reason)
                self.assertNotIn(reason, str(raised.exception))

    def test_malformed_records_and_private_prefix_sanitization(self):
        text = console()
        field = value('dwc3_store_fault_value', 0xfeed1234)
        for replacement in ('dwc3_store_fault_value=0xfeed123', field + '0',
                            field + ' private suffix', field + ' ' + field):
            with self.assertRaises(ValueError):
                CAPTURE.analyze(text.replace(field, replacement))
        prefixed = '\r\n'.join('[private serial] ' + line for line in text.splitlines())
        report = json.dumps(CAPTURE.analyze('private path\n' + prefixed))
        self.assertNotIn('private', report)
        self.assertEqual(CAPTURE.analyze(prefixed), CAPTURE.analyze(text))

    def test_cli_emits_only_sanitized_json_and_io_diagnostic(self):
        output = io.StringIO()
        with patch.object(sys, 'argv', ['checker', '/private/capture']), \
             patch.object(Path, 'read_text', return_value=console()), \
             contextlib.redirect_stdout(output):
            CAPTURE.main()
        self.assertTrue(json.loads(output.getvalue())['store_selftest_passed'])
        self.assertNotIn('/private', output.getvalue())
        with patch.object(sys, 'argv', ['checker', '/private/capture']), \
             patch.object(Path, 'read_text', side_effect=OSError('/private/capture')):
            with self.assertRaises(SystemExit) as raised:
                CAPTURE.main()
        self.assertEqual(str(raised.exception), 'FAIL: unable to read capture')


if __name__ == '__main__':
    unittest.main(verbosity=2)
