#!/usr/bin/env python3
"""Synthetic S2 log tests only: no hardware, network, or private capture."""
import ast
import contextlib
import importlib.util
import io
import json
from pathlib import Path
import sys
import tempfile
import types
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location('spmi_s2_capture_under_test',
    Path(__file__).resolve().with_name('check_spmi_s2_capture.py'))
CAPTURE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CAPTURE)


def value(key, number):
    return key + '=0x%08x' % number


def console(polls=(1, 1), version=0, data_zero=0xb400, data_one=0x80c0,
            pre=(0, 1), diagnostic=0xffffffff):
    # Independent literal fixtures, not implementation-generated field lists.
    guard = [('ram_address', 0x780000), ('ram_result', 0),
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
    lines = ['SPMI PM8841 S2 read transactions; no PMIC voltage writes']
    lines += [value('dwc3_ro_guard_' + key, word) for key, word in guard]
    lines += ['dwc3_ro guard selftest passed: RAM and translation-fault recovery']
    lines += [value('dwc3_store_' + key, word) for key, word in store]
    lines += [value('dwc3_ro_watchdog_read_address', 0xf9017008),
        value('dwc3_ro_watchdog_read_address', 0xf901700c),
        value('dwc3_ro_watchdog_count_first', 50),
        value('dwc3_ro_watchdog_count_second', 70)]
    reads = 0

    def read(address, word):
        nonlocal reads
        reads += 1
        lines.extend(value('spmi_ro_read_' + key, number) for key, number in
                     [('index', reads), ('address', address), ('result', 0), ('value', word)])

    read(0xfc4cf000, version)
    for transaction, command in enumerate((0x08517401, 0x08517451)):
        read(0xfc4cf808, pre[transaction])
        read(0xfc4caf20, diagnostic)
        lines.extend(value('spmi_ro_write_' + key, number) for key, number in
            [('index', transaction + 1), ('address', 0xfc4cf800),
             ('value', command), ('result', 0)])
        for index in range(polls[transaction]):
            read(0xfc4cf808, int(index == polls[transaction] - 1))
        read(0xfc4cf818, (data_zero, data_one)[transaction])
    range_raw, vset = data_zero & 0xff, (data_zero >> 8) & 0xff
    setpoint = vset * (5000 if range_raw == 0 else 10000)
    lines += [value('spmi_ro_' + key, word) for key, word in (
        ('status', 0), ('read_attempts', reads), ('completed_reads', reads),
        ('write_attempts', 2), ('completed_writes', 2), ('indeterminate', 0),
        ('valid_mask', 7), ('data_zero', data_zero), ('data_one', data_one),
        ('range_raw', range_raw), ('vset_raw', vset), ('setpoint_uv', setpoint),
        ('mode_raw', data_one & 0xff), ('enable_raw', (data_one >> 8) & 0xff))]
    lines += ['spmi_ro finished; programmed setpoint only; no clock-write authorization']
    return '\n'.join(lines)


def change_event(text, kind, index, field, number):
    lines = text.splitlines()
    start = lines.index(value('spmi_ro_' + kind + '_index', index))
    fields = ('index', 'address', 'result', 'value') if kind == 'read' else (
        'index', 'address', 'value', 'result')
    lines[start + fields.index(field)] = value('spmi_ro_' + kind + '_' + field, number)
    return '\n'.join(lines)


def change_field(text, key, number):
    old = next(line for line in text.splitlines() if line.startswith(key + '='))
    return text.replace(old, value(key, number), 1)


class S2CaptureTests(unittest.TestCase):
    def reject(self, text):
        with self.assertRaises(ValueError) as raised:
            CAPTURE.analyze(text)
        self.assertNotIn('/private', str(raised.exception))
        self.assertNotIn('secretserial', str(raised.exception))

    def test_minimal_nine_read_golden(self):
        report = CAPTURE.analyze(console())
        self.assertEqual(report['scope'], 'spmi-pm8841-s2-programmed-read')
        self.assertEqual(report['result'], 'two-read-transactions-completed')
        self.assertEqual(report['read_attempts'], 9)
        self.assertEqual(report['completed_reads'], 9)
        self.assertEqual(report['poll_counts'], [1, 1])
        self.assertEqual(report['command_write_count'], 2)
        self.assertEqual(report['physical_pmic_writes'], 0)
        self.assertEqual(report['setpoint_uv'], 900000)

    def test_207_read_golden_198_zero_polls(self):
        text = console(polls=(100, 100))
        report = CAPTURE.analyze(text)
        self.assertEqual(report['completed_reads'], 207)
        self.assertEqual(report['poll_counts'], [100, 100])
        self.assertEqual(report['poll_read_count'], 200)
        self.assertEqual(report['poll_read_count'] - 2, 198)
        self.assertEqual(text.count(value('spmi_ro_read_value', 0)), 200)  # + prestatus + version

    def test_each_100_poll_boundary_allowed_101_rejected(self):
        for polls in ((100, 1), (1, 100)):
            self.assertEqual(CAPTURE.analyze(console(polls=polls))['poll_counts'], list(polls))
        for polls in ((101, 1), (1, 101), (0, 1), (1, 0), (101, 101)):
            self.reject(console(polls=polls))

    def test_version_and_diagnostic_arbitrary_metadata(self):
        for word in (0, 1, 0xffffffff, 0xdeadbeef):
            report = CAPTURE.analyze(console(version=word, diagnostic=word))
            self.assertEqual(report['version_raw'], hex(word))
            self.assertFalse(report['physical_arbiter_valid_proved'])

    def test_prestatus_only_exact_zero_or_done(self):
        for pre in ((0, 0), (1, 1), (1, 0)):
            CAPTURE.analyze(console(pre=pre))
        for word in (2, 3, 4, 5, 8, 9, 0x10, 0xffffffff):
            for pre in ((word, 0), (0, word)):
                self.reject(console(pre=pre))

    def test_every_target_callback_failure_poison_rejected(self):
        for index in range(1, 10):
            for result in (1, 2, 6, 8, 0xffffffff):
                self.reject(change_event(console(), 'read', index, 'result', result))
        for index in (1, 2):
            for result in (1, 2, 6, 8, 0xffffffff):
                self.reject(change_event(console(), 'write', index, 'result', result))

    def test_every_read_address_and_index_checked(self):
        for index in range(1, 10):
            for field, number in (('address', 0xf920c120), ('index', 0),
                                  ('index', index + 1), ('index', 0xffffffff)):
                self.reject(change_event(console(), 'read', index, field, number))

    def test_write_indices_per_kind_not_global(self):
        for index in (1, 2):
            for number in (0, index + 1, index + 3, 0xffffffff):
                self.reject(change_event(console(), 'write', index, 'index', number))

    def test_commands_exact_opcode_sid_length_and_pmic_address(self):
        for index, command in ((1, 0x08517401), (2, 0x08517451)):
            for bit in (0, 1, 4, 8, 16, 20, 24, 27, 28, 31):
                self.reject(change_event(console(), 'write', index, 'value', command ^ (1 << bit)))
            for word in (0, 0x08517400, 0x08517411, 0xffffffff):
                self.reject(change_event(console(), 'write', index, 'value', word))

    def test_channel_offsets_and_rdata1_forbidden(self):
        for index in (1, 2):
            for address in (0xfc4cf000, 0xfc4cf804, 0xfc4cf808, 0xfc4cf880):
                self.reject(change_event(console(), 'write', index, 'address', address))
        for index in (5, 9):
            for address in (0xfc4cf81c, 0xfc4cf898, 0xfc4cf814):
                self.reject(change_event(console(), 'read', index, 'address', address))

    def test_poll_denied_failure_dropped_unknown_any_bits(self):
        for index in (4, 8):
            for word in (2, 3, 4, 5, 6, 7, 8, 9, 15, 16, 0x80000001, 0xffffffff):
                self.reject(change_event(console(), 'read', index, 'value', word))

    def test_no_poll_after_done_or_timeout_retry(self):
        # Valid fixture has two polls per transaction; making first DONE leaves
        # a forbidden second status read where RDATA0 alone must occur.
        text = console(polls=(2, 2))
        for index in (4, 9):
            self.reject(change_event(text, 'read', index, 'value', 1))
        self.reject(change_event(console(), 'read', 4, 'value', 0))
        self.reject(change_event(console(), 'read', 8, 'value', 0))

    def test_payload_upper_16_bits_preserved_without_reserved_rules(self):
        for upper in (0, 1, 0x8000, 0xffff):
            zero, one = (upper << 16) | 0xb400, (upper << 16) | 0x80c0
            report = CAPTURE.analyze(console(data_zero=zero, data_one=one))
            self.assertEqual(report['data_zero_raw'], hex(zero))
            self.assertEqual(report['data_one_raw'], hex(one))
            self.assertEqual(report['setpoint_uv'], 900000)

    def test_range_zero_boundaries_and_invalid_bytes(self):
        for vset in (70, 71, 179, 180, 254, 255):
            report = CAPTURE.analyze(console(data_zero=vset << 8))
            self.assertEqual(report['setpoint_uv'], vset * 5000)
            self.assertEqual(report['nominal_reference_met'], vset >= 180)
        for vset in (0, 1, 69):
            self.reject(console(data_zero=vset << 8))

    def test_range_one_boundaries_and_invalid_bytes(self):
        for vset in (128, 129, 203, 204):
            report = CAPTURE.analyze(console(data_zero=(vset << 8) | 1))
            self.assertEqual(report['setpoint_uv'], vset * 10000)
        for vset in (0, 1, 127, 205, 255):
            self.reject(console(data_zero=(vset << 8) | 1))
        for range_raw in (2, 3, 127, 255):
            self.reject(console(data_zero=0xb400 | range_raw))

    def test_mode_enable_bits_are_requests_not_actual(self):
        for mode in (0, 0x40, 0x80, 0xc0, 0xff):
            for enable in (0, 1, 0x7f, 0x80, 0xff):
                report = CAPTURE.analyze(console(data_one=(enable << 8) | mode))
                self.assertEqual(report['mode_raw'], mode)
                self.assertEqual(report['enable_raw'], enable)
                self.assertEqual(report['enable_requested'], bool(enable & 0x80))
                self.assertEqual(report['hpm_requested'], bool(mode & 0x80))
                self.assertEqual(report['auto_requested'], bool(mode & 0x40))

    def test_no_physical_voltage_clock_usb_or_freshness_claim(self):
        report = CAPTURE.analyze(console())
        for key in ('clock_write_authorized', 'supply_write_authorized', 'supply_floor_proved',
            'adc_measurement', 'usb_link_proved', 'atomicity_proved', 'firmware_abi_proved',
            'watchdog_headroom_independently_proved', 'watchdog_enabled_proved',
            'new_completion_epoch_proved', 'pmic_physical_voltage_proved', 'pwr_good_proved',
            'cx_floor_proved', 'live_freshness_proved', 'ownership_or_mapping_proved'):
            self.assertIs(report[key], False, key)

    def test_every_summary_forgery_rejected_including_ok_one(self):
        text = console()
        for line in text.splitlines():
            if line.split('=')[0] in CAPTURE.SUMMARY_FIELDS:
                number = int(line.split('=0x')[1], 16)
                self.reject(text.replace(line, value(line.split('=')[0], number ^ 1)))
        self.reject(change_field(text, 'spmi_ro_valid_mask', 0xf))

    def test_final_14_key_contract_rejects_old_12_key_draft(self):
        text = console()
        old = '\n'.join(line for line in text.splitlines()
                        if not line.startswith(('spmi_ro_range_raw=', 'spmi_ro_vset_raw=')))
        self.reject(old)
        self.assertEqual(len(CAPTURE.SUMMARY_FIELDS), 14)

    def test_every_record_required_unique_and_ordered(self):
        lines = console().splitlines()
        for index in range(len(lines)):
            self.reject('\n'.join(lines[:index] + lines[index + 1:]))
            self.reject('\n'.join(lines[:index] + [lines[index]] + lines[index:]))
        for index in (1, 17, 19, 47, 49, 53, 58, 65, len(lines) - 3):
            swapped = lines[:]
            swapped[index], swapped[index + 1] = swapped[index + 1], swapped[index]
            self.reject('\n'.join(swapped))

    def test_outside_window_retry_unknown_and_mixed_rpm(self):
        extras = [console(), CAPTURE.START, CAPTURE.FINISH, CAPTURE._STORE.START,
            CAPTURE._STORE.FINISH, 'SPMI other mode', 'RPM read-only snapshot',
            'DWC3 read-only identity probe; no USB initialization',
            'spmi_ro skipped: /private/secretserial', 'rpm_ro skipped: /private/secretserial']
        extras += [value(key, 0) for key in ('spmi_ro_retry_result', 'spmi_ro_unknown',
            'dwc3_ro_status', 'rpm_ro_read_index', 'spmi_ro_write_data', 'dwc3_store_retry')]
        for extra in extras:
            self.reject(extra + '\n' + console())
            self.reject(console() + '\n' + extra)
            self.reject(console().replace(value('spmi_ro_read_index', 1),
                                         extra + '\n' + value('spmi_ro_read_index', 1), 1))

    def test_watchdog_exact_order_addresses_and_bounded_advancing_counts(self):
        text = console()
        for address in (0xf9017008, 0xf901700c):
            self.reject(text.replace(value('dwc3_ro_watchdog_read_address', address),
                                     value('dwc3_ro_watchdog_read_address', address + 4)))
        for key, numbers in (('first', (70, 71, 0x100000)), ('second', (0, 50, 0x100000))):
            for number in numbers:
                self.reject(change_field(text, 'dwc3_ro_watchdog_count_' + key, number))
        CAPTURE.analyze(change_field(change_field(text,
            'dwc3_ro_watchdog_count_first', 0), 'dwc3_ro_watchdog_count_second', 0xfffff))

    def test_read_selftest_fault_data_poison_cpsr_and_pc(self):
        for key, numbers in (('ram_result', (2, 6)), ('fault_result', (0, 6, 8)),
            ('fault_output', (0, 0xffffffff)), ('fault_dfsr', (0x805, 7, 0x205)),
            ('fault_pc', (0, 0x782004, 0x782002)), ('fault_expected_pc', (0x782004,)),
            ('cpsr_before', (0x60000193,)), ('fault_cpsr_after', (0x60000113,)),
            ('fault_spsr', (0x200001d3,)), ('fault_dfar', (0xdeadc004,))):
            for number in numbers:
                self.reject(change_field(console(), 'dwc3_ro_guard_' + key, number))

    def test_store_selftest_ram_data_wnr_cpsr_and_pc(self):
        for key, numbers in (('ram_before_result', (2, 6)), ('ram_result', (2, 8)),
            ('ram_readback_result', (2, 6)), ('ram_before_value', (0,)),
            ('ram_readback_value', (0, 0xa55a12ed)), ('ram_value', (0,)),
            ('fault_dfsr', (5, 0x807, 0xc05)), ('fault_result', (0, 2, 6)),
            ('fault_pc', (0, 0x782000, 0x782104)), ('fault_expected_pc', (0x782104,)),
            ('ram_cpsr_before', (0x60000193,)), ('fault_cpsr_after', (0x60000113,)),
            ('cpsr_restored', (0x20000193,)), ('fault_cpsr_restored', (0x20000193,))):
            for number in numbers:
                self.reject(change_field(console(), 'dwc3_store_' + key, number))

    def test_prefix_validated_before_helper_normalization(self):
        text = console()
        first = value('dwc3_ro_guard_ram_address', 0x780000)
        second = value('dwc3_ro_guard_ram_result', 0)
        self.reject(text.replace(first + '\n' + second, second + '\n' + first))
        self.reject(text.replace(CAPTURE.SELFTEST, CAPTURE._STORE.FINISH))
        self.reject(text.replace(CAPTURE.SELFTEST, ''))
        with patch.object(CAPTURE._STORE, 'analyze', wraps=CAPTURE._STORE.analyze) as helper:
            CAPTURE.analyze(text)
            normalized = helper.call_args.args[0]
            self.assertEqual(normalized.splitlines()[0], CAPTURE._STORE.START)
            self.assertEqual(normalized.splitlines()[-1], CAPTURE._STORE.FINISH)
            self.assertEqual(len(normalized.splitlines()), 49)

    def test_missing_footer_failed_banner_and_no_raw_exception_echo(self):
        self.reject(console().replace(CAPTURE.FINISH, ''))
        self.reject(console().replace(CAPTURE.START, 'SPMI failed /private/secretserial'))
        self.reject(console() + '\nspmi_ro skipped: /private/secretserial')

    def test_malformed_fields_suffixes_and_prefix_sanitization(self):
        text = console()
        line = value('spmi_ro_status', 0)
        for replacement in ('spmi_ro_status=0x0000000', line + '0', line + ' suffix',
                            line + ' ' + line, 'spmi_ro_status=0x-0000001'):
            self.reject(text.replace(line, replacement))
        prefixed = '\r\n'.join('[    0.100] [private secretserial] ' + line
                               for line in text.splitlines())
        report = CAPTURE.analyze('unrelated boot text\n' + prefixed)
        self.assertEqual(report, CAPTURE.analyze(text))
        self.assertNotIn('private', json.dumps(report))
        self.assertNotIn('secretserial', json.dumps(report))

    def test_input_immutable_and_reports_independent(self):
        text = console()
        original = text[:]
        report = CAPTURE.analyze(text)
        report['poll_counts'].append(999)
        self.assertEqual(text, original)
        self.assertEqual(CAPTURE.analyze(text)['poll_counts'], [1, 1])
        for invalid in (None, b'bytes', [], {}):
            self.reject(invalid)

    def test_cli_json_real_temp_fixture_and_sanitized_io_error(self):
        with tempfile.TemporaryDirectory() as directory:
            fixture = Path(directory) / 'synthetic.txt'
            fixture.write_text(console())
            output = io.StringIO()
            with patch.object(sys, 'argv', ['checker', str(fixture)]), \
                 contextlib.redirect_stdout(output):
                CAPTURE.main()
            self.assertEqual(json.loads(output.getvalue())['completed_reads'], 9)
            self.assertNotIn(directory, output.getvalue())
        output = io.StringIO()
        with patch.object(sys, 'argv', ['checker', '/private/capture']), \
             patch.object(Path, 'read_text', return_value=console()), \
             contextlib.redirect_stdout(output):
            CAPTURE.main()
        self.assertNotIn('/private', output.getvalue())
        with patch.object(sys, 'argv', ['checker', '/private/capture']), \
             patch.object(Path, 'read_text', side_effect=OSError('/private/secretserial')):
            with self.assertRaises(SystemExit) as raised:
                CAPTURE.main()
        self.assertEqual(str(raised.exception), 'FAIL: unable to read capture')

    def test_explicit_sibling_import_ignores_module_collision(self):
        fake = types.ModuleType('check_dwc3_store_capture')
        fake.analyze = lambda _: (_ for _ in ()).throw(AssertionError('wrong module'))
        with patch.dict(sys.modules, {'check_dwc3_store_capture': fake,
                                     '_spmi_s2_store_validator': fake}):
            module = importlib.util.module_from_spec(SPEC)
            SPEC.loader.exec_module(module)
            self.assertEqual(module.analyze(console())['completed_reads'], 9)

    def test_tool_imports_are_offline_only(self):
        for module in (CAPTURE, CAPTURE._STORE):
            tree = ast.parse(Path(module.__file__).read_text())
            imports = []
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    imports.extend(alias.name for alias in node.names)
                elif isinstance(node, ast.ImportFrom):
                    imports.append(node.module)
            self.assertLessEqual(set(imports), {'argparse', 'importlib.util', 'json', 'pathlib', 're'})


if __name__ == '__main__':
    unittest.main(verbosity=2)
