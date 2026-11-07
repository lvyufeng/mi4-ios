#!/usr/bin/env python3
"""Validate one RPM RBCPR V2-shaped snapshot offline; never authorizes writes.

Repeated telemetry is not proof of freshness, atomicity, firmware ABI, voltage
units, ADC measurement, or a permanent supply floor. No device access is made;
raw console text, identity, and host source paths are never emitted.
"""
import argparse
import json
from pathlib import Path
import re

START = 'RPM RBCPR V2 read-only snapshot; no clock or supply writes'
SELFTEST = 'dwc3_ro guard selftest passed: RAM and translation-fault recovery'
FINISH = 'rpm_ro finished; sampled telemetry only; no clock-write authorization'
GUARD_FIELDS = tuple('dwc3_ro_guard_' + key for key in (
    'ram_address', 'ram_result', 'cpsr_before', 'cpsr_after', 'fault_address',
    'fault_result', 'fault_dfsr', 'fault_dfar', 'fault_pc', 'fault_spsr',
    'fault_count', 'fault_active', 'fault_status', 'fault_output',
    'fault_expected_pc', 'fault_cpsr_before', 'fault_cpsr_after'))
WATCHDOG_FIELDS = ('dwc3_ro_watchdog_read_address', 'dwc3_ro_watchdog_read_address',
                   'dwc3_ro_watchdog_count_first', 'dwc3_ro_watchdog_count_second')
READ_FIELDS = tuple('rpm_ro_read_' + key for key in ('index', 'address', 'result', 'value'))
SUMMARY_FIELDS = tuple('rpm_ro_' + key for key in ('status', 'completed_reads',
    'attempted_reads', 'failed_slot', 'sample_zero_valid', 'sample_one_valid'))
SLOT = 0xfc190010
OFFSETS = (0, 4, 8, 12, 20, 92, 164, 232, 236, 4)
CORNERS = ('OFF', 'SVS', 'NOMINAL', 'TURBO')


def analyze(text):
    expected = (START, *GUARD_FIELDS, SELFTEST, *WATCHDOG_FIELDS,
                *(READ_FIELDS * 24), *SUMMARY_FIELDS, FINISH)
    entries = []
    # Closed namespaces reject unknown writes, mixed modes, retries, malformed
    # fields, and evidence outside the sole run, without echoing private text.
    for token in re.findall(r'\b(?:RPM |DWC3 |rpm_|dwc3_)[^\r\n]*', text):
        match = re.fullmatch(r'((?:rpm|dwc3)_[a-z0-9_]+)=0x([0-9a-fA-F]{8})', token)
        entries.append((match[1], int(match[2], 16)) if match else (token, None))
    if tuple(key for key, _ in entries) != expected:
        raise ValueError('incomplete, contradictory, or out-of-order RPM snapshot')
    guard = dict(entries[1:1 + len(GUARD_FIELDS)])

    def g(key):
        return guard['dwc3_ro_guard_' + key]

    def context(before, after):
        return ((before & 0x010002bf) == 0x13 and
                (after & 0x010002bf) == 0x93 and
                ((before ^ after) & 0x0100037f) == 0)

    if (not 0x8000 <= g('ram_address') <= 0x03fffffc or g('ram_address') & 3 or
        g('ram_result') != 0 or not context(g('cpsr_before'), g('cpsr_after'))):
        raise ValueError('guard RAM/context evidence failed')
    dfsr = g('fault_dfsr')
    if (any(g(key) != number for key, number in (
            ('fault_address', 0xdeadc000), ('fault_result', 2),
            ('fault_dfar', 0xdeadc000), ('fault_count', 1), ('fault_active', 0),
            ('fault_status', 2), ('fault_output', 0xa55a12ed))) or
        dfsr & 0x40f != 5 or dfsr & ~0x14ff or
        not g('fault_pc') or g('fault_pc') & 3 or g('fault_pc') != g('fault_expected_pc') or
        not context(g('fault_cpsr_before'), g('fault_cpsr_after')) or
        (g('fault_spsr') ^ g('fault_cpsr_after')) & 0x010002ff):
        raise ValueError('guard translation-fault recovery evidence failed')
    cursor = len(GUARD_FIELDS) + 2
    enable_address, count_address, first, second = (v for _, v in entries[cursor:cursor + 4])
    if (enable_address != 0xf9017008 or count_address != 0xf901700c or
        not 0 <= first < second <= 0xfffff):
        raise ValueError('watchdog address/count evidence failed')
    # Bark/headroom is probe-gated but not logged: do not invent an independent
    # two-second margin or an enabled-register sample from the two addresses.
    cursor += 4
    reads = [tuple(v for _, v in entries[cursor + i:cursor + i + 4])
             for i in range(0, 96, 4)]
    pointer = reads[0][3]
    block = 0xfc000000 + pointer
    if (pointer & 3 or not 0x190014 <= pointer <= 0x19f7fc or
        block > 0xffffffff or block < 0xfc100000 or block + 0x800 > 0xfc1a0000):
        raise ValueError('RPM relative pointer is outside the approved data window')
    addresses = (SLOT, *(block + offset for offset in OFFSETS), SLOT) * 2
    if any(index != i or address != addresses[i - 1] or result != 0
           for i, (index, address, result, _) in enumerate(reads, 1)):
        raise ValueError('RPM read index/address/result evidence failed')
    samples = [tuple(item[3] for item in reads[start:start + 12]) for start in (0, 12)]
    for sample in samples:
        if (sample[0] != pointer or sample[11] != pointer or sample[1] not in (1, 2) or
            sample[3:5] != (3, 3) or sample[8] > 3 or sample[2] != sample[10]):
            raise ValueError('RPM sample layout or within-pass stability failed')
    if samples[0] != samples[1]:
        raise ValueError('RPM repeated samples changed')
    summary = dict(entries[cursor + 96:cursor + 96 + len(SUMMARY_FIELDS)])
    if any(summary[key] != number for key, number in zip(SUMMARY_FIELDS, (1, 24, 24, 24, 0xfff, 0xfff))):
        raise ValueError('RPM success summary is inconsistent')
    sample = samples[1]
    return {'scope': 'read-only-rpm-rbcpr-v2-snapshot', 'result': 'stable-sampled',
            'stable_sampled': True, 'cx_corner': CORNERS[sample[8]],
            'cx_corner_raw': sample[8], 'reported_nominal_or_higher': sample[8] >= 2,
            'num_rails': sample[1], 'railway_voltage_raw': hex(sample[9]),
            'programmed_voltage_raw': [hex(word) for word in sample[5:8]],
            'status_raw': hex(sample[2]), 'stats_block_raw': hex(block),
            'pointer_relative_raw': hex(pointer), 'completed_reads': 24, 'attempted_reads': 24,
            'clock_write_authorized': False, 'supply_write_authorized': False,
            'live_freshness_proved': False, 'supply_floor_proved': False,
            'adc_measurement': False, 'usb_link_proved': False,
            'atomicity_proved': False, 'firmware_abi_proved': False,
            'voltage_units_proved': False, 'watchdog_headroom_independently_proved': False}


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
    except ValueError as error:
        raise SystemExit('FAIL: ' + str(error)) from None
