#!/usr/bin/env python3
"""Synthetic RPM console tests: no private capture, compiler, or device."""
import contextlib
import importlib.util
import io
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location('rpm_rbcpr_capture',
    Path(__file__).resolve().with_name('check_rpm_rbcpr_capture.py'))
CAPTURE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CAPTURE)


def value(key, number):
    return key + '=0x%08x' % number


def console(pointer=0x190100, corner=2, status=0, rails=1, voltage=900000):
    guard = [('ram_address', 0x780000), ('ram_result', 0),
        ('cpsr_before', 0x60000113), ('cpsr_after', 0x60000193),
        ('fault_address', 0xdeadc000), ('fault_result', 2), ('fault_dfsr', 5),
        ('fault_dfar', 0xdeadc000), ('fault_pc', 0x782000),
        ('fault_spsr', 0x20000193), ('fault_count', 1), ('fault_active', 0),
        ('fault_status', 2), ('fault_output', 0xa55a12ed),
        ('fault_expected_pc', 0x782000), ('fault_cpsr_before', 0x60000113),
        ('fault_cpsr_after', 0x60000193)]
    lines = [CAPTURE.START] + [value('dwc3_ro_guard_' + key, word) for key, word in guard]
    lines += [CAPTURE.SELFTEST, value('dwc3_ro_watchdog_read_address', 0xf9017008),
        value('dwc3_ro_watchdog_read_address', 0xf901700c),
        value('dwc3_ro_watchdog_count_first', 50), value('dwc3_ro_watchdog_count_second', 70)]
    block = (0xfc000000 + pointer) & 0xffffffff
    # Literal contract, deliberately not imported offsets or field-name lists.
    addresses = (0xfc190010, block, block + 4, block + 8, block + 12,
                 block + 20, block + 92, block + 164, block + 232, block + 236,
                 block + 4, 0xfc190010)
    words = (pointer, rails, status, 3, 3, 0, 900001, 0xffffffff, corner, voltage, status, pointer)
    for index in range(24):
        for key, number in [('index', index + 1), ('address', addresses[index % 12]),
                            ('result', 0), ('value', words[index % 12])]:
            lines.append(value('rpm_ro_read_' + key, number))
    lines += [value('rpm_ro_' + key, number) for key, number in (
        ('status', 1), ('completed_reads', 24), ('attempted_reads', 24),
        ('failed_slot', 24), ('sample_zero_valid', 0xfff), ('sample_one_valid', 0xfff))]
    return '\n'.join(lines + [CAPTURE.FINISH])


def change_read(text, index, field, number):
    lines = text.splitlines()
    start = lines.index(value('rpm_ro_read_index', index))
    offset = ('index', 'address', 'result', 'value').index(field)
    lines[start + offset] = value('rpm_ro_read_' + field, number)
    return '\n'.join(lines)


class RpmCaptureTests(unittest.TestCase):
    def reject_field(self, key, numbers):
        text = console()
        old = next(line for line in text.splitlines() if line.startswith(key + '='))
        for number in numbers:
            with self.subTest(key=key, number=hex(number)), self.assertRaises(ValueError):
                CAPTURE.analyze(text.replace(old, value(key, number)))

    def test_positive_all_corners_status_and_raw_voltage(self):
        for corner, name in enumerate(('OFF', 'SVS', 'NOMINAL', 'TURBO')):
            for status in (0, 1, 3, 0xffffffff):
                for voltage in (0, 0xffffffff):
                    with self.subTest(corner=corner, status=status, voltage=voltage):
                        report = CAPTURE.analyze(console(corner=corner, status=status, voltage=voltage))
                        self.assertEqual(report['cx_corner'], name)
                        self.assertEqual(report['reported_nominal_or_higher'], corner >= 2)
                        self.assertEqual(report['railway_voltage_raw'], hex(voltage))
                        self.assertEqual(report['status_raw'], hex(status))
                        self.assertEqual(report['programmed_voltage_raw'], ['0x0', hex(900001), '0xffffffff'])

    def test_scope_never_authorizes_power_clock_or_usb(self):
        report = CAPTURE.analyze(console())
        self.assertEqual(report['scope'], 'read-only-rpm-rbcpr-v2-snapshot')
        self.assertEqual(report['result'], 'stable-sampled')
        self.assertEqual(report['completed_reads'], 24)
        self.assertEqual(report['attempted_reads'], 24)
        for key in ('clock_write_authorized', 'supply_write_authorized', 'live_freshness_proved',
            'supply_floor_proved', 'adc_measurement', 'usb_link_proved', 'atomicity_proved',
            'firmware_abi_proved', 'voltage_units_proved', 'watchdog_headroom_independently_proved'):
            self.assertFalse(report[key])

    def test_pointer_boundaries_and_two_rails(self):
        for pointer in (0x190014, 0x19f7fc):
            report = CAPTURE.analyze(console(pointer=pointer, rails=2))
            self.assertEqual(report['stats_block_raw'], hex(0xfc000000 + pointer))
            self.assertEqual(report['num_rails'], 2)

    def test_bad_relative_absolute_unaligned_overflow_pointers(self):
        for pointer in (0, 0x190010, 0x190015, 0x19f800, 0xfc190100, 0xffffffff, 0x4000000):
            with self.subTest(pointer=hex(pointer)), self.assertRaises(ValueError):
                CAPTURE.analyze(console(pointer=pointer))

    def test_layout_rejects_rails_metadata_and_current_corner(self):
        for index, numbers in [(2, [0, 3]), (4, [0, 2, 4]), (5, [0, 2, 4]), (9, [4, 0xffffffff])]:
            for number in numbers:
                text = change_read(console(), index, 'value', number)
                text = change_read(text, index + 12, 'value', number)
                with self.subTest(index=index, number=number), self.assertRaises(ValueError):
                    CAPTURE.analyze(text)

    def test_all_pointer_observations_must_match(self):
        for index in (12, 13, 24):
            with self.subTest(index=index), self.assertRaises(ValueError):
                CAPTURE.analyze(change_read(console(), index, 'value', 0x190104))

    def test_status_drift_within_each_pass(self):
        for index in (3, 11, 15, 23):
            with self.subTest(index=index), self.assertRaises(ValueError):
                CAPTURE.analyze(change_read(console(), index, 'value', 1))

    def test_each_cross_pass_payload_field_must_match(self):
        for index, number in [(14, 2), (15, 3), (16, 2), (17, 2), (18, 1),
                              (19, 900002), (20, 0xfffffffe), (21, 3), (22, 900001)]:
            with self.subTest(index=index), self.assertRaises(ValueError):
                CAPTURE.analyze(change_read(console(), index, 'value', number))
        text = change_read(console(), 15, 'value', 3)
        text = change_read(text, 23, 'value', 3)
        with self.assertRaises(ValueError):
            CAPTURE.analyze(text)

    def test_every_read_index_address_and_result(self):
        for index in range(1, 25):
            for field, number in [('index', 0), ('address', 0xf920c120), ('result', 2)]:
                with self.subTest(index=index, field=field), self.assertRaises(ValueError):
                    CAPTURE.analyze(change_read(console(), index, field, number))
        text = change_read(console(), 6, 'address', 0xfc19015c)
        with self.assertRaises(ValueError):
            CAPTURE.analyze(text)

    def test_summary_ok_is_one_and_failed_slot_is_twenty_four(self):
        for key, numbers in [('status', [0, 2, 5]), ('completed_reads', [0, 23, 25]),
            ('attempted_reads', [23, 25]), ('failed_slot', [0, 23, 0xffffffff]),
            ('sample_zero_valid', [0xffe, 0x1fff]), ('sample_one_valid', [0xffe, 0x1fff])]:
            self.reject_field('rpm_ro_' + key, numbers)

    def test_guard_ram_and_read_fault_evidence(self):
        for key, numbers in [('ram_address', [0, 0xf920c120, 0x780001]),
            ('ram_result', [2, 6]), ('fault_address', [0xdeadc004]), ('fault_result', [0, 6, 8]),
            ('fault_dfsr', [0x805, 0x205, 7, 0x80000005]), ('fault_dfar', [0xdeadc004]),
            ('fault_pc', [0, 0x782004, 0x782002]), ('fault_expected_pc', [0x782004]),
            ('fault_count', [0, 2]), ('fault_active', [1]), ('fault_status', [3, 8]),
            ('fault_output', [0]), ('fault_spsr', [0x200001d3, 0x20000113, 0x21000193])]:
            self.reject_field('dwc3_ro_guard_' + key, numbers)

    def test_guard_context_and_abort_auto_a(self):
        for prefix in ('dwc3_ro_guard_', 'dwc3_ro_guard_fault_'):
            self.reject_field(prefix + 'cpsr_before', [0x60000193, 0x60000133, 0x61000113])
            self.reject_field(prefix + 'cpsr_after', [0x60000113, 0x600001d3, 0x60000093])
        text = console().replace('fault_spsr=0x20000193', 'fault_spsr=0xa0000093')
        self.assertTrue(CAPTURE.analyze(text)['stable_sampled'])

    def test_watchdog_exact_addresses_and_advancing_bounded_counts(self):
        self.reject_field('dwc3_ro_watchdog_count_first', [70, 71, 0x100000])
        self.reject_field('dwc3_ro_watchdog_count_second', [0, 50, 0x100000])
        for address in (0xf9017008, 0xf901700c):
            text = console().replace(value('dwc3_ro_watchdog_read_address', address),
                                     value('dwc3_ro_watchdog_read_address', 0xf920c120))
            with self.assertRaises(ValueError):
                CAPTURE.analyze(text)

    def test_each_record_required_unique_and_ordered(self):
        lines = console().splitlines()
        for index, line in enumerate(lines):
            for mutated in (lines[:index] + lines[index + 1:], lines[:index] + [line] + lines[index:]):
                with self.subTest(index=index), self.assertRaises(ValueError):
                    CAPTURE.analyze('\n'.join(mutated))
        index = lines.index(value('rpm_ro_read_index', 1))
        lines[index + 1], lines[index + 2] = lines[index + 2], lines[index + 1]
        with self.assertRaises(ValueError):
            CAPTURE.analyze('\n'.join(lines))

    def test_retry_mixed_modes_unknown_records_and_target_writes(self):
        extras = [console(), CAPTURE.START, CAPTURE.FINISH,
            'DWC3 guarded RAM store selftest; no MMIO target writes',
            'DWC3 read-only GCC root snapshot; no DWC3 core reads',
            'dwc3_ro recovery verified; controller target reads inhibited',
            'dwc3_ro finished; identification is not a USB link',
            'dwc3_ro skipped: private unknown reason', 'rpm_ro skipped: private unknown reason']
        extras += [value(key, 0xf920c120) for key in ('rpm_ro_retry_result', 'rpm_ro_write_address',
            'rpm_ro_core_write_result', 'dwc3_ro_read_index', 'dwc3_ro_read_address',
            'dwc3_store_ram_result', 'dwc3_ro_status', 'dwc3_ro_root_valid')]
        for extra in extras:
            for text in (extra + '\n' + console(), console() + '\n' + extra):
                with self.subTest(extra=extra[:40]), self.assertRaises(ValueError) as raised:
                    CAPTURE.analyze(text)
                self.assertNotIn('private unknown reason', str(raised.exception))

    def test_malformed_and_private_prefix_sanitization(self):
        field = value('rpm_ro_status', 1)
        for replacement in ('rpm_ro_status=0x0000001', field + '0', field + ' suffix', field + ' ' + field):
            with self.assertRaises(ValueError):
                CAPTURE.analyze(console().replace(field, replacement))
        text = '\r\n'.join('[private serial] ' + line for line in console().splitlines())
        report = json.dumps(CAPTURE.analyze('private source path\n' + text))
        self.assertNotIn('private', report)
        self.assertEqual(CAPTURE.analyze(text), CAPTURE.analyze(console()))

    def test_cli_json_and_sanitized_io_error(self):
        output = io.StringIO()
        with patch.object(sys, 'argv', ['checker', '/private/capture']), \
             patch.object(Path, 'read_text', return_value=console()), contextlib.redirect_stdout(output):
            CAPTURE.main()
        self.assertEqual(json.loads(output.getvalue())['result'], 'stable-sampled')
        self.assertNotIn('/private', output.getvalue())
        with patch.object(sys, 'argv', ['checker', '/private/capture']), \
             patch.object(Path, 'read_text', side_effect=OSError('/private/capture')):
            with self.assertRaises(SystemExit) as raised:
                CAPTURE.main()
        self.assertEqual(str(raised.exception), 'FAIL: unable to read capture')


if __name__ == '__main__':
    unittest.main(verbosity=2)
