#!/usr/bin/env python3
"""Synthetic console acceptance tests; no real logs or device access."""
import importlib.util
from pathlib import Path
import unittest

SPEC = importlib.util.spec_from_file_location('dwc3_capture',
    Path(__file__).resolve().with_name('check_dwc3_capture.py'))
CAPTURE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CAPTURE)
VALUES = [1]*5+[0, 2, 0x5533210a]+[0]*7


def value(key, number):
    return key+'=0x%08x' % number


def console(values=VALUES, status=0, failed=0xffffffff, read_fault=False):
    lines = [CAPTURE.START]
    for key, number in [('dwc3_ro_guard_ram_address', 0x5000),
        ('dwc3_ro_guard_ram_result', 0), ('dwc3_ro_guard_cpsr_before', 0x13),
        ('dwc3_ro_guard_cpsr_after', 0xd3),
        ('dwc3_ro_guard_fault_address', 0xdeadc000),
        ('dwc3_ro_guard_fault_result', 2), ('dwc3_ro_guard_fault_dfsr', 5),
        ('dwc3_ro_guard_fault_dfar', 0xdeadc000), ('dwc3_ro_guard_fault_pc', 0x100c)]:
        lines.append(value(key, number))
    lines += [CAPTURE.SELFTEST, value('dwc3_ro_watchdog_count_first', 50),
              value('dwc3_ro_watchdog_count_second', 70)]
    for i, number in enumerate(values, 1):
        for field, item in [('index', i), ('address', CAPTURE.ADDRESSES[i-1]),
                            ('result', 0), ('value', number)]:
            lines.append(value('dwc3_ro_read_'+field, item))
    count = len(values)
    if read_fault:
        for field, item in [('index', count+1), ('address', CAPTURE.ADDRESSES[count]),
                            ('result', 0xffffffff)]:
            lines.append(value('dwc3_ro_read_'+field, item))
    for field, number in [('status', status), ('completed_reads', count),
        ('valid_clocks', (1 << min(count,5))-1),
        ('valid_registers', (1 << max(0,count-7))-1), ('failed_slot', failed),
        ('elapsed_us', 200)]:
        lines.append(value('dwc3_ro_'+field, number))
    lines.append(CAPTURE.FINISH)
    return '\n'.join(lines)


class CaptureTests(unittest.TestCase):
    def test_complete_identification(self):
        report = CAPTURE.analyze(console())
        self.assertTrue(report['identification_passed'])
        self.assertEqual(report['gsnpsid'], '0x5533210a')
        self.assertEqual(len(report['registers']), 8)

    def test_exact_skip_reasons(self):
        for reason in ('CPU/MMU/vector precondition', 'identity MMIO mapping mismatch',
            'recovery net not confirmed', 'guard selftest address is mapped',
            'guard RAM selftest failed', 'guard translation-fault selftest failed',
            'watchdog disabled or unreadable',
            'watchdog not advancing or insufficient headroom'):
            with self.subTest(reason=reason):
                report = CAPTURE.analyze(CAPTURE.START+'\ndwc3_ro skipped: '+reason)
                self.assertEqual(report['result'], 'skipped')
                self.assertFalse(report['identification_passed'])
        with self.assertRaises(ValueError):
            CAPTURE.analyze(CAPTURE.START+'\ndwc3_ro skipped: private unknown detail')

    def test_mask_readback_stop(self):
        text = '\n'.join([CAPTURE.START,
            value('dwc3_ro_guard_ram_result', 6),
            value('dwc3_ro_guard_cpsr_before', 0x60000193),
            value('dwc3_ro_guard_cpsr_after', 0x60000193),
            'dwc3_ro skipped: guard RAM selftest failed'])
        report = CAPTURE.analyze(text)
        self.assertFalse(report['identification_passed'])
        self.assertEqual(report['guard_ram_result'], 6)
        self.assertEqual(report['cpsr_after_mask'], '0x60000193')
        with self.assertRaises(ValueError):
            CAPTURE.analyze(text+'\n'+value('dwc3_ro_guard_cpsr_after',0xd3))

    def test_recovery_only_exact_fault_evidence(self):
        lines = console().splitlines()
        lines = [line for line in lines if not line.startswith(('dwc3_ro_watchdog_', 'dwc3_ro_read_',
            'dwc3_ro_status=', 'dwc3_ro_completed_reads=', 'dwc3_ro_valid_',
            'dwc3_ro_failed_slot=', 'dwc3_ro_elapsed_us=')) and line != CAPTURE.FINISH]
        lines = [line.replace('dwc3_ro_guard_cpsr_after=0x000000d3',
                               'dwc3_ro_guard_cpsr_after=0x00000093') for line in lines]
        for key, number in [('spsr',0x60000193),('count',1),('active',0),('status',2),
            ('output',0xa55a12ed),('expected_pc',0x100c),('cpsr_before',0x13),('cpsr_after',0x93)]:
            lines.append(value('dwc3_ro_guard_fault_'+key,number))
        lines.append(CAPTURE.RECOVERY)
        text='\n'.join(lines)
        report=CAPTURE.analyze(text, irq_only=True, recovery_only=True)
        self.assertTrue(report['guard_selftest_passed'])
        self.assertFalse(report['identification_passed'])
        self.assertTrue(report['controller_target_reads_inhibited'])
        for old,new in [('fault_spsr=0x60000193','fault_spsr=0x600001d3'),
            ('fault_count=0x00000001','fault_count=0x00000000'),
            ('fault_active=0x00000000','fault_active=0x00000001'),
            ('fault_status=0x00000002','fault_status=0x00000003'),
            ('fault_output=0xa55a12ed','fault_output=0x00000000'),
            ('fault_expected_pc=0x0000100c','fault_expected_pc=0x00001010'),
            ('fault_cpsr_after=0x00000093','fault_cpsr_after=0x00000013'),
            ('fault_cpsr_before=0x00000013','fault_cpsr_before=0x00000053')]:
            with self.subTest(mutation=old):
                self.assertIn(old,text)
                with self.assertRaises(ValueError):
                    CAPTURE.analyze(text.replace(old,new), True, True)
        for extra in ('\n'+value('dwc3_ro_read_index',1),
                       '\n'+value('dwc3_ro_status',0),
                       '\n'+value('dwc3_ro_watchdog_read_address',0xf9017008)):
            with self.assertRaises(ValueError):
                CAPTURE.analyze(text+extra,True,True)
        for word in (0x805, 0x205, 0x80000005):
            with self.assertRaises(ValueError):
                CAPTURE.analyze(text.replace('fault_dfsr=0x00000005',
                    'fault_dfsr=0x%08x' % word),True,True)
        with self.assertRaises(ValueError):
            CAPTURE.analyze(text+'\ndwc3_ro skipped: guard RAM selftest failed',True,True)
        with self.assertRaises(ValueError):
            CAPTURE.analyze(text,False,True)
        with self.assertRaises(ValueError):
            CAPTURE.analyze(text,True,False)

    def test_inconsistent_success_evidence(self):
        original = console()
        mutations = [
            ('dwc3_ro_guard_cpsr_after=0x000000d3', 'dwc3_ro_guard_cpsr_after=0x00000093'),
            ('dwc3_ro_guard_cpsr_after=0x000000d3', 'dwc3_ro_guard_cpsr_after=0x00000053'),
            ('dwc3_ro_read_address=0xfc400108', 'dwc3_ro_read_address=0xf9a55000'),
            ('dwc3_ro_completed_reads=0x0000000f', 'dwc3_ro_completed_reads=0x0000000e'),
            ('dwc3_ro_guard_fault_result=0x00000002', 'dwc3_ro_guard_fault_result=0x00000000'),
            ('dwc3_ro_guard_fault_dfar=0xdeadc000', 'dwc3_ro_guard_fault_dfar=0xdeadc004'),
            ('dwc3_ro_guard_fault_dfsr=0x00000005', 'dwc3_ro_guard_fault_dfsr=0x00000007'),
            ('dwc3_ro_watchdog_count_second=0x00000046', 'dwc3_ro_watchdog_count_second=0x00000032'),
            ('dwc3_ro_read_result=0x00000000', 'dwc3_ro_read_result=0x00000001'),
            ('dwc3_ro_valid_registers=0x000000ff', 'dwc3_ro_valid_registers=0x000000fe'),
            ('dwc3_ro_valid_clocks=0x0000001f', 'dwc3_ro_valid_clocks=0x0000000f'),
            ('dwc3_ro_failed_slot=0xffffffff', 'dwc3_ro_failed_slot=0x00000000'),
            ('dwc3_ro_read_value=0x5533210a', 'dwc3_ro_read_value=0x5532210a'),
            ('dwc3_ro_read_value=0x00000001', 'dwc3_ro_read_value=0x10000001'),
            (CAPTURE.SELFTEST, ''), (CAPTURE.FINISH, '')]
        for old, new in mutations:
            with self.subTest(mutation=old):
                self.assertIn(old, original)
                with self.assertRaises(ValueError):
                    CAPTURE.analyze(original.replace(old,new,1))
        for extra in ('\ndwc3_ro_status=0x00000000', '\n'+CAPTURE.START,
                      '\ndwc3_ro skipped: CPU/MMU/vector precondition'):
            with self.subTest(extra=extra):
                with self.assertRaises(ValueError):
                    CAPTURE.analyze(original+extra)

    def test_exact_stops(self):
        cases = [([0x80000001],3), ([1]*5+[1],4),
                 ([1]*5+[0,0],5), ([1]*5+[0,2,0],6)]
        for words, status in cases:
            with self.subTest(status=status):
                report = CAPTURE.analyze(console(words,status))
                self.assertFalse(report['identification_passed'])
                self.assertIn('reason', report)
        for words, status in [([1],3), ([1]*5+[0],4),
                              ([1]*5+[0,2],5), ([1]*5+[0,2,0x55330000],6)]:
            with self.subTest(contradictory=status):
                with self.assertRaises(ValueError):
                    CAPTURE.analyze(console(words,status))

    def test_guarded_fault_and_pre_read_budget(self):
        for count in range(15):
            for actual_fault in (False,True):
                with self.subTest(count=count,actual_fault=actual_fault):
                    report = CAPTURE.analyze(console(VALUES[:count],2,count,actual_fault))
                    self.assertEqual(report['failed_slot'],count)
                    self.assertFalse(report['identification_passed'])
        with self.assertRaises(ValueError):
            CAPTURE.analyze(console(VALUES[:3],2,4,True))


if __name__ == '__main__':
    unittest.main(verbosity=2)
