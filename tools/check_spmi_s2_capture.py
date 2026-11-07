#!/usr/bin/env python3
"""Validate one success-only PM8841 S2 programmed-register capture offline.

Only the closed, ordered log contract is accepted. The already-ordered 17-field
read guard and 29-field RAM store prefix is normalized with the store helper's
START/FINISH solely to reuse its pure validation, not to fabricate evidence.
That helper's RAM/PC ownership checks are sanity checks, not image/mapping proof.
The two exact EXT_READL commands imply no PMIC register write in this observed
sequence, not a universal control-flow guarantee. Version is metadata, not a
physical-arbiter predicate. Requested mode/enable and a nominal reference are
not ADC, actual voltage, PWRGOOD, a CX floor, freshness, or clock permission.
No device access, raw capture text, private identity, or path is reported.
"""
import argparse
import importlib.util
import json
from pathlib import Path
import re

# Explicit sibling resolution prevents module collisions under direct imports.
_STORE_SPEC = importlib.util.spec_from_file_location(
    '_spmi_s2_store_validator', Path(__file__).resolve().with_name('check_dwc3_store_capture.py'))
_STORE = importlib.util.module_from_spec(_STORE_SPEC)
_STORE_SPEC.loader.exec_module(_STORE)

START = 'SPMI PM8841 S2 read transactions; no PMIC voltage writes'
SELFTEST = _STORE.SELFTEST
FINISH = 'spmi_ro finished; programmed setpoint only; no clock-write authorization'
READ_FIELDS = _STORE.READ_FIELDS
STORE_FIELDS = _STORE.STORE_FIELDS
# Final producer contract includes both decoded range and VSET bytes.
SUMMARY_FIELDS = tuple('spmi_ro_' + key for key in (
    'status', 'read_attempts', 'completed_reads', 'write_attempts',
    'completed_writes', 'indeterminate', 'valid_mask', 'data_zero', 'data_one',
    'range_raw', 'vset_raw', 'setpoint_uv', 'mode_raw', 'enable_raw'))
_TOKEN = re.compile(r'\b(?:SPMI |DWC3 |RPM |spmi_|dwc3_|rpm_)[^\r\n]*')
_FIELD = re.compile(r'((?:spmi_|dwc3_|rpm_)[a-z0-9_]+)=0x([0-9a-fA-F]{8})')


def analyze(text):
    """Return sanitized evidence only; reject every incomplete/failure capture."""
    if not isinstance(text, str):
        raise ValueError('invalid capture input')
    tokens = _TOKEN.findall(text)
    position = 0

    def literal(expected):
        nonlocal position
        if position >= len(tokens) or tokens[position] != expected:
            raise ValueError('incomplete, mixed, or out-of-order S2 capture')
        position += 1

    def field(expected):
        nonlocal position
        if position >= len(tokens):
            raise ValueError('missing S2 evidence')
        match = _FIELD.fullmatch(tokens[position])
        if match is None or match.group(1) != expected:
            raise ValueError('invalid or out-of-order S2 field')
        position += 1
        return int(match.group(2), 16)

    literal(START)
    prefix = []
    for key in READ_FIELDS:
        number = field(key)
        prefix.append(key + '=0x%08x' % number)
    literal(SELFTEST)
    prefix.append(SELFTEST)
    for key in STORE_FIELDS:
        number = field(key)
        prefix.append(key + '=0x%08x' % number)
    try:
        _STORE.analyze('\n'.join([_STORE.START, *prefix, _STORE.FINISH]))
    except ValueError:
        raise ValueError('guard or RAM store selftest evidence failed') from None

    for address in (0xf9017008, 0xf901700c):
        if field('dwc3_ro_watchdog_read_address') != address:
            raise ValueError('invalid watchdog read address')
    first = field('dwc3_ro_watchdog_count_first')
    second = field('dwc3_ro_watchdog_count_second')
    if not 0 <= first < second <= 0xfffff:
        raise ValueError('invalid watchdog counter evidence')

    reads = writes = 0

    def read(address):
        nonlocal reads
        reads += 1
        if reads > 207:
            raise ValueError('S2 read bound exceeded')
        index = field('spmi_ro_read_index')
        observed = field('spmi_ro_read_address')
        result = field('spmi_ro_read_result')
        word = field('spmi_ro_read_value')
        if index != reads or observed != address or result != 0:
            raise ValueError('invalid S2 read transaction evidence')
        return word

    def write(command):
        nonlocal writes
        writes += 1
        index = field('spmi_ro_write_index')
        address = field('spmi_ro_write_address')
        word = field('spmi_ro_write_value')
        result = field('spmi_ro_write_result')
        if index != writes or address != 0xfc4cf800 or word != command or result != 0:
            raise ValueError('invalid S2 command write evidence')

    version = read(0xfc4cf000)
    pre_status, poll_counts, payloads = [], [], []
    for command in (0x08517401, 0x08517451):
        status = read(0xfc4cf808)
        if status not in (0, 1):
            raise ValueError('invalid S2 pre-command status')
        pre_status.append(status)
        read(0xfc4caf20)  # Raw diagnostic metadata is not an authorization gate.
        write(command)
        for count in range(1, 101):
            status = read(0xfc4cf808)
            # Exact DONE only: DENIED/FAILURE/DROPPED, even with DONE, reject.
            if status == 1:
                poll_counts.append(count)
                break
            if status != 0:
                raise ValueError('S2 completion status failed')
        else:
            raise ValueError('S2 completion poll bound exceeded')
        payloads.append(read(0xfc4cf818))

    data_zero, data_one = payloads
    range_raw = data_zero & 0xff
    vset = (data_zero >> 8) & 0xff
    mode = data_one & 0xff
    enable = (data_one >> 8) & 0xff
    if range_raw == 0 and 70 <= vset <= 255:
        setpoint = vset * 5000
    elif range_raw == 1 and 128 <= vset <= 204:
        setpoint = vset * 10000
    else:
        raise ValueError('unsupported S2 programmed setpoint encoding')

    expected_summary = (0, reads, reads, 2, 2, 0, 7, data_zero, data_one,
                        range_raw, vset, setpoint, mode, enable)
    for key, expected in zip(SUMMARY_FIELDS, expected_summary):
        if field(key) != expected:
            raise ValueError('contradictory S2 summary evidence')
    literal(FINISH)
    if position != len(tokens):
        raise ValueError('extra S2 namespace evidence')

    enabled = bool(enable & 0x80)
    return {
        'scope': 'spmi-pm8841-s2-programmed-read',
        'result': 'two-read-transactions-completed',
        'version_raw': hex(version), 'pre_status_raw': [hex(n) for n in pre_status],
        'status_raw': ['0x1', '0x1'],
        'data_zero_raw': hex(data_zero), 'data_one_raw': hex(data_one),
        'setpoint_uv': setpoint, 'range_raw': range_raw, 'vset_raw': vset,
        'mode_raw': mode, 'enable_raw': enable,
        'enable_requested': enabled,
        'hpm_requested': bool(mode & 0x80),
        'auto_requested': bool(mode & 0x40),
        'nominal_reference_met': setpoint >= 900000,
        'read_attempts': reads, 'completed_reads': reads,
        'poll_counts': poll_counts, 'poll_read_count': sum(poll_counts),
        'write_attempts': writes, 'completed_writes': writes,
        'command_write_count': 2, 'physical_pmic_writes': 0,
        'guard_selftest_passed': True, 'store_selftest_passed': True,
        'clock_write_authorized': False, 'supply_write_authorized': False,
        'supply_floor_proved': False, 'adc_measurement': False,
        'usb_link_proved': False, 'atomicity_proved': False,
        'firmware_abi_proved': False,
        'watchdog_headroom_independently_proved': False,
        'watchdog_enabled_proved': False, 'new_completion_epoch_proved': False,
        'pmic_physical_voltage_proved': False, 'pwr_good_proved': False,
        'cx_floor_proved': False, 'live_freshness_proved': False,
        'ownership_or_mapping_proved': False, 'physical_arbiter_valid_proved': False,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('console', type=Path)
    args = parser.parse_args()
    try:
        text = args.console.read_text(errors='replace')
    except OSError:
        raise SystemExit('FAIL: unable to read capture') from None
    print(json.dumps(analyze(text), indent=2, sort_keys=True))


if __name__ == '__main__':
    try:
        main()
    except ValueError:
        raise SystemExit('FAIL: invalid S2 capture evidence') from None
