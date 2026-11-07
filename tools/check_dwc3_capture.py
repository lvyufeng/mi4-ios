#!/usr/bin/env python3
"""Analyze one private guarded DWC3 console; never touches a device.

An identification pass is not a functioning USB driver or complete iOS startup.
No raw log contents, device identity or host source paths are emitted in JSON.
"""
import argparse
import json
from pathlib import Path
import re

ADDRESSES = (
    0xfc400108, 0xfc4003c8, 0xfc4003d0, 0xfc4003cc, 0xfc4004ac,
    0xfc4003c0, 0xfc4003d4, 0xf920c120, 0xf920c110, 0xf920c140,
    0xf920c144, 0xf920c200, 0xf920c700, 0xf920c704, 0xf920c70c)
START = 'DWC3 read-only identity probe; no USB initialization'
SELFTEST = 'dwc3_ro guard selftest passed: RAM and translation-fault recovery'
FINISH = 'dwc3_ro finished; identification is not a USB link'


def analyze(text):
    if text.count(START) != 1:
        raise ValueError('expected exactly one probe start marker')
    section = text.split(START, 1)[1]
    records = []
    for line in section.splitlines():
        match = re.search(r'\b(dwc3_ro_[a-z_]+)=0x([0-9a-fA-F]{8})\b', line)
        if match:
            records.append((match[1], int(match[2], 16)))

    def one(key):
        matches = [v for k, v in records if k == key]
        if len(matches) != 1:
            raise ValueError('missing/duplicate probe value: '+key)
        return matches[0]

    skipped = re.findall(r'dwc3_ro skipped: ([^\r\n]+)', section)
    if skipped:
        if len(skipped) != 1 or FINISH in section or any(k == 'dwc3_ro_read_index' for k, _ in records):
            raise ValueError('contradictory skipped-probe evidence')
        # Avoid forwarding arbitrary private log text as a diagnostic.
        reasons = ('CPU/MMU/vector precondition', 'identity MMIO mapping mismatch',
                   'recovery net not confirmed', 'guard selftest address is mapped',
                   'guard RAM selftest failed', 'guard translation-fault selftest failed',
                   'watchdog disabled or unreadable',
                   'watchdog not advancing or insufficient headroom')
        reason = skipped[0]
        if reason not in reasons:
            raise ValueError('unknown probe skip reason')
        report = {'scope': 'read-only-identification-only', 'result': 'skipped',
                  'reason': reason, 'identification_passed': False}
        if reason == 'guard RAM selftest failed' and any(k == 'dwc3_ro_guard_ram_result' for k, _ in records):
            report['guard_ram_result'] = one('dwc3_ro_guard_ram_result')
            report['cpsr_before_mask'] = hex(one('dwc3_ro_guard_cpsr_before'))
            report['cpsr_after_mask'] = hex(one('dwc3_ro_guard_cpsr_after'))
        return report
    if section.count(SELFTEST) != 1 or section.count(FINISH) != 1:
        raise ValueError('incomplete or duplicated probe execution')
    if one('dwc3_ro_guard_ram_result') != 0 or one('dwc3_ro_guard_cpsr_after') & 0x010002ff != 0xd3:
        raise ValueError('guard RAM/mask precondition lacks successful readback evidence')
    one('dwc3_ro_guard_cpsr_before')
    if one('dwc3_ro_guard_fault_address') != 0xdeadc000 or one('dwc3_ro_guard_fault_result') != 2:
        raise ValueError('guard selftest did not report expected fault')
    if one('dwc3_ro_guard_fault_dfar') != 0xdeadc000 or one('dwc3_ro_guard_fault_dfsr') & 0x40f != 5:
        raise ValueError('guard selftest lacks expected translation-fault evidence')
    if not one('dwc3_ro_guard_ram_address') or not one('dwc3_ro_guard_fault_pc'):
        raise ValueError('guard selftest lacks nonzero RAM/PC evidence')
    first, second = one('dwc3_ro_watchdog_count_first'), one('dwc3_ro_watchdog_count_second')
    if not second > first:
        raise ValueError('watchdog did not advance')

    reads = []
    cursor = None
    for key, value in records:
        if key == 'dwc3_ro_read_index':
            if cursor is not None and 'result' not in cursor:
                raise ValueError('read result missing before next read')
            if value != len(reads)+1 or value > len(ADDRESSES):
                raise ValueError('unexpected read index')
            cursor = {'index': value}
            reads.append(cursor)
        elif key in ('dwc3_ro_read_address', 'dwc3_ro_read_result', 'dwc3_ro_read_value'):
            field = key.rsplit('_', 1)[1]
            if cursor is None or field in cursor:
                raise ValueError('orphan/duplicate read field')
            if field == 'address' and value != ADDRESSES[cursor['index']-1]:
                raise ValueError('read address differs from exact ordered whitelist')
            if field != 'address' and 'address' not in cursor:
                raise ValueError('read result precedes address')
            if field == 'value' and cursor.get('result') != 0:
                raise ValueError('value reported before successful read')
            cursor[field] = value
    if any('address' not in r or 'result' not in r or
           (r['result'] == 0) != ('value' in r) for r in reads):
        raise ValueError('incomplete read evidence')
    completed = sum(r['result'] == 0 for r in reads)
    if any(r['result'] != 0 for r in reads[:-1]):
        raise ValueError('probe continued after failed read')
    if completed != one('dwc3_ro_completed_reads'):
        raise ValueError('read count differs from summary')
    status = one('dwc3_ro_status')
    if status not in range(7):
        raise ValueError('unknown identify status')
    report = {'scope': 'read-only-identification-only', 'result': 'stopped',
              'identify_status': status, 'completed_reads': completed,
              'guard_selftest_passed': True, 'watchdog_advancing': True,
              'identification_passed': False}
    if status == 0:
        if completed != 15 or len(reads) != 15 or one('dwc3_ro_valid_clocks') != 31 or one('dwc3_ro_valid_registers') != 255:
            raise ValueError('success summary lacks complete 15-read evidence')
        if one('dwc3_ro_failed_slot') != 0xffffffff:
            raise ValueError('success summary has a failed read slot')
        values = [r['value'] for r in reads]
        for value in values[:5]:
            if value & 1 == 0 or value >> 28 not in (0, 2):
                raise ValueError('success accepted unstable/disabled clock')
        if values[5] & 1 or values[6] & 0x800000f3 != 2 or values[7] & 0xffff0000 != 0x55330000:
            raise ValueError('success lacks reset/root/GSNPSID prerequisites')
        report.update(result='identified', identification_passed=True,
                      gsnpsid=hex(values[7]), revision_hex=hex(values[7] & 0xffff),
                      registers={hex(ADDRESSES[i]):hex(values[i]) for i in range(7,15)})
    if status == 2:
        slot = one('dwc3_ro_failed_slot')
        if slot != completed or completed >= 15 or len(reads) not in (completed, completed+1):
            raise ValueError('read-failure summary has inconsistent slot/count')
        report.update(reason='guarded read failed or pre-read budget expired', failed_slot=slot,
                      next_address=hex(ADDRESSES[slot]))
    elif status == 3:
        if not 1 <= completed <= 5 or len(reads) != completed:
            raise ValueError('clock stop has unexpected read count')
        value = reads[-1]['value']
        if value & 1 and value >> 28 in (0, 2):
            raise ValueError('clock stop reported on an accepted state')
        if one('dwc3_ro_valid_clocks') != (1 << completed)-1 or one('dwc3_ro_valid_registers') != 0:
            raise ValueError('clock stop has inconsistent validity masks')
        report.update(reason='branch clock disabled or not in stable ON state',
                      blocked_address=hex(ADDRESSES[completed-1]), blocked_value=hex(value))
    elif status == 4:
        if completed != 6 or len(reads) != 6 or reads[-1]['value'] & 1 == 0:
            raise ValueError('reset stop lacks asserted reset evidence')
        report.update(reason='USB reset remains asserted')
    elif status == 5:
        if completed != 7 or len(reads) != 7 or reads[-1]['value'] & 0x800000f3 == 2:
            raise ValueError('root-clock stop lacks blocked root evidence')
        report.update(reason='root clock not stable/enabled')
    elif status == 6:
        if completed != 8 or len(reads) != 8 or reads[-1]['value'] & 0xffff0000 == 0x55330000:
            raise ValueError('wrong-ID stop lacks mismatched core evidence')
        report.update(reason='GSNPSID does not identify DWC3')
    elif status == 1:
        raise ValueError('invalid-argument status is not a valid probe result')
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('console', type=Path)
    args = parser.parse_args()
    print(json.dumps(analyze(args.console.read_text(errors='replace')), indent=2, sort_keys=True))


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError) as error:
        raise SystemExit('FAIL: '+str(error))
