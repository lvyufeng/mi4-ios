#!/usr/bin/env python3
"""Check one guarded RAM-store console offline; never authorizes MMIO or USB.

Numeric RAM/PC bounds are sanity checks, not symbol ownership or image/mapping
proof. WRITE_FAULT (8) means an indeterminate write, not an unchanged target.
No raw capture text, device identity, or source path is included in the report.
"""
import argparse
import json
from pathlib import Path
import re

START = 'DWC3 guarded RAM store selftest; no MMIO target writes'
SELFTEST = 'dwc3_ro guard selftest passed: RAM and translation-fault recovery'
FINISH = 'dwc3_ro store selftest passed; RAM writes only; controller target reads inhibited'
READ_FIELDS = tuple('dwc3_ro_guard_' + key for key in (
    'ram_address', 'ram_result', 'cpsr_before', 'cpsr_after',
    'fault_address', 'fault_result', 'fault_dfsr', 'fault_dfar', 'fault_pc',
    'fault_spsr', 'fault_count', 'fault_active', 'fault_status', 'fault_output',
    'fault_expected_pc', 'fault_cpsr_before', 'fault_cpsr_after'))
STORE_FIELDS = tuple('dwc3_store_' + key for key in (
    'ram_address', 'ram_before_result', 'ram_before_value', 'ram_value',
    'ram_result', 'ram_active', 'ram_status', 'ram_count', 'ram_operation',
    'ram_cpsr_before', 'ram_cpsr_after', 'cpsr_restored',
    'ram_readback_result', 'ram_readback_value', 'fault_address', 'fault_value',
    'fault_result', 'fault_dfsr', 'fault_dfar', 'fault_pc', 'fault_expected_pc',
    'fault_spsr', 'fault_count', 'fault_active', 'fault_status',
    'fault_operation', 'fault_cpsr_before', 'fault_cpsr_after', 'fault_cpsr_restored'))


def analyze(text):
    # A closed, ordered namespace rejects retries, other modes, target reads,
    # unknown write records, skips, and evidence before/after the sole run.
    expected = (START, *READ_FIELDS, SELFTEST, *STORE_FIELDS, FINISH)
    tokens = re.findall(r'\b(?:DWC3 |dwc3_)[^\r\n]*', text)
    records, order = {}, []
    for token in tokens:
        match = re.fullmatch(r'(dwc3_[a-z0-9_]+)=0x([0-9a-fA-F]{8})', token)
        if match:
            key, number = match.groups()
            if key in records:
                raise ValueError('duplicate selftest field')
            records[key] = int(number, 16)
            order.append(key)
        else:
            order.append(token)
    if tuple(order) != expected:
        raise ValueError('incomplete, contradictory, or out-of-order store selftest')

    def read(key):
        return records['dwc3_ro_guard_' + key]

    def store(key):
        return records['dwc3_store_' + key]

    def context(before, after, restored=None, spsr=None):
        valid = ((before & 0x010002bf) == 0x13 and
                 (after & 0x010002bf) == 0x93 and
                 ((before ^ after) & 0x0100037f) == 0)
        if restored is not None:
            valid &= ((before ^ restored) & 0x010003ff) == 0
        if spsr is not None:
            valid &= ((spsr ^ after) & 0x010002ff) == 0
        return valid

    def ram(address):
        return 0x8000 <= address <= 0x04000000 - 4 and address % 4 == 0

    if (not ram(read('ram_address')) or read('ram_result') != 0 or
        not context(read('cpsr_before'), read('cpsr_after'))):
        raise ValueError('read guard RAM/context evidence failed')
    dfsr = read('fault_dfsr')
    read_pc = read('fault_pc')
    if (read('fault_address') != 0xdeadc000 or read('fault_result') != 2 or
        read('fault_dfar') != 0xdeadc000 or dfsr & 0x40f != 5 or dfsr & ~0x14ff or
        not read_pc or read_pc % 4 or read_pc != read('fault_expected_pc') or
        any(read(key) != number for key, number in (
            ('fault_count', 1), ('fault_active', 0), ('fault_status', 2),
            ('fault_output', 0xa55a12ed))) or
        not context(read('fault_cpsr_before'), read('fault_cpsr_after'),
                    spsr=read('fault_spsr'))):
        raise ValueError('read translation-fault recovery evidence failed')
    if (not ram(store('ram_address')) or
        any(store(key) != number for key, number in (
            ('ram_before_result', 0), ('ram_before_value', 0xa55a12ed),
            ('ram_value', 0x53545231), ('ram_result', 0), ('ram_active', 0),
            ('ram_status', 3), ('ram_count', 0), ('ram_operation', 1),
            ('ram_readback_result', 0), ('ram_readback_value', 0x53545231))) or
        not context(store('ram_cpsr_before'), store('ram_cpsr_after'),
                    restored=store('cpsr_restored'))):
        raise ValueError('RAM store/readback/context evidence failed')
    dfsr = store('fault_dfsr')
    write_pc = store('fault_pc')
    if (any(store(key) != number for key, number in (
            ('fault_address', 0xdeadc000), ('fault_value', 0xfeed1234),
            ('fault_result', 8), ('fault_dfar', 0xdeadc000), ('fault_count', 1),
            ('fault_active', 0), ('fault_status', 8), ('fault_operation', 1))) or
        dfsr & 0xc0f != 0x805 or dfsr & ~0x1cff or
        not write_pc or write_pc % 4 or write_pc == read_pc or
        write_pc != store('fault_expected_pc') or
        not context(store('fault_cpsr_before'), store('fault_cpsr_after'),
                    restored=store('fault_cpsr_restored'), spsr=store('fault_spsr'))):
        raise ValueError('store translation-fault recovery evidence failed')
    return {'scope': 'guarded-ram-store-selftest-only', 'result': 'store-selftest-passed',
            'store_selftest_passed': True, 'guard_selftest_passed': True,
            'identification_passed': False, 'usb_link_proved': False,
            'controller_target_reads_inhibited': True, 'mmio_writes_allowed': False,
            'clock_write_authorized': False, 'ownership_or_mapping_proved': False,
            'ram_store_count': 1, 'unmapped_store_attempts': 1,
            'ram_address': hex(store('ram_address')),
            'ram_initial_value': hex(store('ram_before_value')),
            'ram_write_value': hex(store('ram_value')),
            'ram_readback_value': hex(store('ram_readback_value')),
            'read_fault_pc': hex(read_pc), 'write_fault_pc': hex(write_pc),
            'write_fault_dfsr': hex(dfsr), 'write_fault_result': 8,
            'write_fault_indeterminate': True,
            'write_fault_semantics': 'indeterminate write; not proof of unchanged target'}


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
