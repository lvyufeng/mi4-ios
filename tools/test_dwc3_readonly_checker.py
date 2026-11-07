#!/usr/bin/env python3
"""Offline tests of the real checker, not ARM execution or a hardware proof.

Only command() is mocked: nm/objdump retain the original synthetic text while
raw ELF mutations exercise inspect() and the actual program-header reader.
The first-BNE rule is the checker's exact compiler contract, not universal CFG
validation of every possible handler. No toolchain, device, or build is used.
"""
import contextlib
import copy
import hashlib
import importlib.util
import io
from pathlib import Path
import re
import struct
import sys
import tempfile
import unittest
from unittest import mock

CHECKER_PATH = Path(__file__).resolve().parents[1] / 'tools/check_dwc3_readonly_probe.py'
CHECKER_HASH = hashlib.sha256(CHECKER_PATH.read_bytes()).hexdigest()
SPEC = importlib.util.spec_from_file_location('dwc3_checker_under_test', CHECKER_PATH)
CHECKER = importlib.util.module_from_spec(SPEC)
_bytecode = sys.dont_write_bytecode
try:
    sys.dont_write_bytecode = True
    SPEC.loader.exec_module(CHECKER)
finally:
    sys.dont_write_bytecode = _bytecode
assert hashlib.sha256(CHECKER_PATH.read_bytes()).hexdigest() == CHECKER_HASH

GUARD = (0xf57ff04f, 0xf57ff06f, 0xe3a02000, 0xe5902000, 0xf57ff04f,
         0xf57ff06f, 0xe5812000, 0xe3a00000, 0xe12fff1e, 0xe3a00002, 0xe12fff1e)
MARKERS = (b'dwc3_ro guard selftest passed: RAM and translation-fault recovery',
           b'dwc3_ro skipped: guard translation-fault selftest failed',
           b'mmu legacy CI USB probe skipped; primary port is DWC3',
           b'dwc3_ro finished; identification is not a USB link')
USB = ('entry_usb_probe', 'entry_usb_dev_init', 'entry_usb_enum_poll',
       'entry_usb_stream_poll')


def image(length=0x1800):
    data = bytearray(0x100 + length)
    data[:16] = b'\x7fELF\x01\x01\x01' + bytes(9)
    struct.pack_into('<HHIIIIIHHHHHH', data, 16, 2, 40, 1, 0x1000, 52, 0,
                     0, 52, 32, 1, 0, 0, 0)
    struct.pack_into('<8I', data, 52, 1, 0x100, 0x1000, 0x1000,
                     length, length, 5, 4)
    return data


def branch(source, target, opcode):
    assert (target - source - 8) % 4 == 0
    return opcode | (((target - source - 8) // 4) & 0xffffff)


class Fixture:
    def __init__(self):
        self.payload, self.entry = image(), image(0x100)
        self.config = ''.join('#define STAGE90_' + name + ' ' + value + '\n'
                              for name, value in (('DWC3_READONLY', '1'),
                              ('SKIP_USB_PREBOOT', '1'), ('CACHE_MODE', '0'),
                              ('PMAP_ATTR_MODE', '0'), ('HW_WATCHDOG', '1'),
                              ('DEADMAN_ENABLE', '1')))
        symbols = {
            'stage90_guarded_read32_load_arm': (0x1000, 44),
            'stage90_guarded_read32_fault': (0x100c, 4),
            'stage90_guarded_read32_recovery': (0x1024, 8),
            'stage90_guarded_read32': (0x1040, 4),
            'stage90_guarded_read32_park': (0x1100, 12),
            'stage90_guarded_read32_cpsr_read': (0x1180, 8),
            'stage90_data_abort_c_handler': (0x1200, 0x90),
            'stage90_guarded_read32_abort_policy': (0x1300, 4),
            'stage90_dwc3_readonly_probe': (0x1400, 12),
            'mi4_dwc3_identify': (0x1500, 4), 'kernel_entry': (0x1600, 8),
            'stage90_guarded_read32_state': (0x2000, 4)}
        self.nm = ''.join(f'{addr:08x} {size:08x} T {name}\n'
                          for name, (addr, size) in symbols.items())
        self.entry_nm = ''.join(f'{0x1000+i*16:08x} 00000004 T {name}\n'
                               for i, name in enumerate(USB))
        for i, word in enumerate(GUARD):
            self.word(0x1000 + i*4, word)
        for va, word in ((0x1180, 0xe10f0000), (0x1184, 0xe12fff1e)):
            self.word(va, word)
        for i, word in enumerate((0xf10c00c0, 0xe320f002, 0xeafffffd)):
            self.word(0x1100 + i*4, word)
        for va in range(0x1200, 0x1290, 4):
            self.word(va, 0xe1a00000)  # Harmless legacy-path filler.
        handler = (0xe302c000, 0xe340c000, 0xe59c3000, 0xe3530000,
                   branch(0x1210, 0x1250, 0x1a000000))
        for i, word in enumerate(handler):
            self.word(0x1200 + i*4, word)
        for va, word in ((0x1250, 0xe14f0000), (0x1254, 0xee151f10),
                         (0x1258, branch(0x1258, 0x1300, 0xeb000000)),
                         (0x1260, branch(0x1260, 0x1100, 0xea000000)),
                         (0x1400, branch(0x1400, 0x1040, 0xeb000000)),
                         (0x1404, branch(0x1404, 0x1500, 0xeb000000)),
                         (0x1600, branch(0x1600, 0x1400, 0xeb000000))):
            self.word(va, word)
        for va in (0x1040, 0x1300, 0x1408, 0x1500, 0x1604):
            self.word(va, 0xe12fff1e)
        for i in range(4):
            self.word(0x1000+i*16, 0xe12fff1e, entry=True)
        markers = b'\0'.join(MARKERS) + b'\0'
        self.payload[0x1200:0x1200+len(markers)] = markers  # VMA 0x2100.
        bodies = {name: ['  %x: e12fff1e bx lr' % addr]
                  for name, (addr, _) in symbols.items()}
        bodies['stage90_guarded_read32'] = [
            '  1040: eb00004e bl 1180 <stage90_guarded_read32_cpsr_read>',
            '  1044: ebffffed bl 1000 <stage90_guarded_read32_load_arm>']
        bodies['stage90_guarded_read32_load_arm'] = [
            '  1000: f57ff04f dsb sy', '  1004: f57ff06f isb sy',
            '  1008: e3a02000 mov r2, #0']
        bodies['stage90_guarded_read32_fault'] = [
            '  100c: e5902000 ldr r2, [r0]', '  1010: f57ff04f dsb sy',
            '  1014: f57ff06f isb sy', '  1018: e5812000 str r2, [r1]',
            '  101c: e3a00000 mov r0, #0', '  1020: e12fff1e bx lr']
        bodies['stage90_guarded_read32_recovery'] = [
            '  1024: e3a00002 mov r0, #2', '  1028: e12fff1e bx lr']
        bodies['stage90_guarded_read32_park'] = [
            '  1100: f10c00c0 cpsid if', '  1104: e320f002 wfe',
            '  1108: eafffffd b 1104 <stage90_guarded_read32_park+0x4>']
        bodies['stage90_data_abort_c_handler'] = [
            '  1200: e302c000 movw ip, #8192', '  1204: e340c000 movt ip, #0',
            '  1208: e59c3000 ldr r3, [ip]', '  120c: e3530000 cmp r3, #0',
            '  1210: 1a00000e bne 1250 <stage90_data_abort_c_handler+0x50>',
            '  1250: e14f0000 mrs r0, SPSR', '  1254: ee151f10 mrc 15, 0, r1, cr5, cr0',
            '  1258: eb000028 bl 1300 <stage90_guarded_read32_abort_policy>',
            '  1260: eaffffa6 b 1100 <stage90_guarded_read32_park>']
        bodies['kernel_entry'] = ['  1600: ebffff7e bl 1400 <stage90_dwc3_readonly_probe>']
        bodies['stage90_dwc3_readonly_probe'] = [
            '  1400: ebffff0e bl 1040 <stage90_guarded_read32>',
            '  1404: eb00003d bl 1500 <mi4_dwc3_identify>']
        self.dis = ''.join(f'{symbols[name][0]:08x} <{name}>:\n' + '\n'.join(lines) + '\n'
                           for name, lines in bodies.items())

    def word(self, va, value, entry=False):
        struct.pack_into('<I', self.entry if entry else self.payload, va-0x1000+0x100, value)

    def symbol(self, name, size=None, address=None, remove=False, entry=False):
        attr = 'entry_nm' if entry else 'nm'
        text = getattr(self, attr)
        pattern = r'^([0-9a-f]+) ([0-9a-f]+) T ' + re.escape(name) + r'\n'
        def replace(match):
            return '' if remove else (f'{address if address is not None else int(match[1],16):08x} '
                                      f'{size if size is not None else int(match[2],16):08x} T {name}\n')
        text, count = re.subn(pattern, replace, text, flags=re.M)
        assert count == 1
        setattr(self, attr, text)

    def define(self, name, value):
        self.config = re.sub(r'(#define STAGE90_' + name + r') \S+',
                             lambda m: m[1] + ' ' + value, self.config)


def negatives():
    cases = []
    for name, wrong in (('DWC3_READONLY', '0'), ('SKIP_USB_PREBOOT', '0'),
                        ('CACHE_MODE', '1'), ('PMAP_ATTR_MODE', '1'),
                        ('HW_WATCHDOG', '0'), ('DEADMAN_ENABLE', '0'),
                        ('HW_WATCHDOG', 'WATCHDOG_ALIAS')):
        cases.append((name+'='+wrong, name, lambda f, n=name, v=wrong: f.define(n, v)))
    cases += [
        ('CPSR reader absent', 'CPSR reader differs', lambda f: f.symbol('stage90_guarded_read32_cpsr_read', remove=True)),
        ('CPSR reader wrong instruction', 'CPSR reader differs', lambda f: f.word(0x1180, 0xe3a000d3)),
        ('CPSR reader wrong size', 'CPSR reader differs', lambda f: f.symbol('stage90_guarded_read32_cpsr_read', size=4)),
        ('CPSR read call absent', 'before the target load', lambda f: setattr(f, 'dis', f.dis.replace('<stage90_guarded_read32_cpsr_read>', '<other_reader>'))),
        ('missing symbol', 'missing linked symbol', lambda f: f.symbol('mi4_dwc3_identify', remove=True)),
        ('zero symbol', 'missing linked symbol', lambda f: f.symbol('stage90_guarded_read32', size=0)),
        ('fault size', 'label layout', lambda f: f.symbol('stage90_guarded_read32_fault', size=8)),
        ('fault offset', 'label layout', lambda f: f.symbol('stage90_guarded_read32_fault', address=0x1010)),
        ('fixup size', 'label layout', lambda f: f.symbol('stage90_guarded_read32_recovery', size=4)),
        ('fixup offset', 'label layout', lambda f: f.symbol('stage90_guarded_read32_recovery', address=0x1020)),
        ('raw LDR', 'load opcodes', lambda f: f.word(0x100c, 0xe5902004)),
        ('fixup store', 'load opcodes', lambda f: f.word(0x1024, 0xe5812000)),
        ('park word', 'store-free loop', lambda f: f.word(0x1104, 0xe5812000)),
        ('park size', 'store-free loop', lambda f: f.symbol('stage90_guarded_read32_park', size=8)),
        ('unconditional first branch', 'lacks active-state', lambda f: f.word(0x1210, branch(0x1210, 0x1250, 0xea000000))),
        ('wrong condition', 'branch on nonzero', lambda f: f.word(0x1210, branch(0x1210, 0x1250, 0x0a000000))),
        ('nonzero comparison', 'branch on nonzero', lambda f: f.word(0x120c, 0xe3530001)),
        ('wrong state pointer', 'actual guard', lambda f: f.word(0x1200, 0xe302c004)),
        ('wrong state high bits', 'actual guard', lambda f: f.word(0x1204, 0xe340c001)),
        ('wrong state load', 'actual guard', lambda f: f.word(0x1208, 0xe59c3004)),
        ('prefix BL', 'before any call', lambda f: (f.word(0x120c, 0xeb000000),
            f.word(0x1210, 0xe3530000), f.word(0x1214, branch(0x1214, 0x1250, 0x1a000000)))),
        ('branch outside handler', 'leaves handler', lambda f: f.word(0x1210, branch(0x1210, 0x1300, 0x1a000000))),
        ('wrong policy target', 'must call policy', lambda f: f.word(0x1258, branch(0x1258, 0x1040, 0xeb000000))),
        ('conditional policy BL', 'must call policy', lambda f: f.word(0x1258, branch(0x1258, 0x1300, 0x1b000000))),
        ('no policy call', 'control transfer', lambda f: f.word(0x1258, 0xe1a00000)),
        ('pre-policy branch', 'control transfer', lambda f: f.word(0x1250, 0xea000000)),
        ('pre-policy BX', 'control transfer', lambda f: f.word(0x1250, 0xe12fff1e)),
        ('policy text absent', 'lacks policy', lambda f: setattr(f, 'dis', f.dis.replace('<stage90_guarded_read32_abort_policy>', '<other_policy>'))),
        ('guard text absent', 'missing disassembly body stage90_guarded_read32', lambda f: setattr(f, 'dis', f.dis.replace('<stage90_guarded_read32>', '<other_reader>'))),
        ('kernel call absent', 'exactly once', lambda f: setattr(f, 'dis', f.dis.replace('bl 1400', 'b 1400'))),
        ('legacy USB call', 'legacy CI', lambda f: setattr(f, 'dis', f.dis.replace('bl 1400 <stage90_dwc3_readonly_probe>', 'bl 1400 <stage90_dwc3_readonly_probe>\n bl 1700 <usb_preboot_run>'))),
        ('USB size', 'bare return', lambda f: f.symbol(USB[0], size=8, entry=True)),
        ('USB raw instruction', 'bare return', lambda f: f.word(0x1000, 0xe1a00000, entry=True)),
        ('USB symbol absent', 'missing disabled', lambda f: f.symbol(USB[1], remove=True, entry=True)),
        ('markers absent', 'diagnostic', lambda f: setattr(f, 'payload', f.payload.replace(MARKERS[0], b'X'*len(MARKERS[0])))),
        ('ELF machine', 'ARM ELF', lambda f: struct.pack_into('<H', f.payload, 18, 3)),
        ('ELF endian', 'little-endian', lambda f: f.payload.__setitem__(5, 2)),
        ('program headers out of range', 'program-header bounds', lambda f: struct.pack_into('<I', f.payload, 28, len(f.payload))),
        ('load out of file', 'load bounds', lambda f: struct.pack_into('<I', f.payload, 56, len(f.payload))),
        ('unbacked instructions', 'unbacked', lambda f: struct.pack_into('<I', f.payload, 68, 12)),
    ]
    return cases


class CheckerTests(unittest.TestCase):
    @classmethod
    def tearDownClass(cls):
        if hashlib.sha256(CHECKER_PATH.read_bytes()).hexdigest() != CHECKER_HASH:
            raise AssertionError('checker changed during tests')

    def inspect_fixture(self, fixture):
        with tempfile.TemporaryDirectory(prefix='dwc3-checker-test-') as directory:
            root = Path(directory)
            payload, entry, config = (root / n for n in ('payload.elf', 'entry.elf', 'config.h'))
            payload.write_bytes(fixture.payload)
            entry.write_bytes(fixture.entry)
            config.write_text(fixture.config)
            outputs = {('arm-none-eabi-nm', 'payload.elf'): fixture.nm,
                       ('arm-none-eabi-nm', 'entry.elf'): fixture.entry_nm,
                       ('arm-none-eabi-objdump', 'payload.elf'): fixture.dis}
            def command(argv):
                self.assertEqual(argv[1:-1], ['-d'] if argv[0].endswith('objdump')
                                 else ['-S', '--defined-only'])
                return outputs[(argv[0], Path(argv[-1]).name)]
            output = io.StringIO()
            with mock.patch.object(CHECKER, 'command', side_effect=command) as calls:
                with contextlib.redirect_stdout(output):
                    CHECKER.inspect(payload, entry, config)
            return output.getvalue(), calls.call_count

    def test_complete_positive_fixture(self):
        output, calls = self.inspect_fixture(Fixture())
        self.assertIn('PASS:', output)
        self.assertIn('LIMIT: static acceptance only', output)
        self.assertEqual(calls, 3)

    def test_valid_integer_suffixes(self):
        for suffix in ('u', 'U', 'ul', 'ULL', 'l', 'LLu'):
            with self.subTest(suffix=suffix):
                fixture = Fixture()
                for name, value in re.findall(r'#define STAGE90_(\w+) (\d+)', fixture.config):
                    fixture.define(name, ('0x1' if value == '1' else '0') + suffix)
                self.assertIn('PASS:', self.inspect_fixture(fixture)[0])

    def test_reject_mutated_inputs_with_original_command_text(self):
        cases = negatives()
        self.assertGreaterEqual(len(cases), 20)
        original = Fixture()
        for name, error, mutate in cases:
            with self.subTest(case=name):
                fixture = copy.deepcopy(original)
                mutate(fixture)
                with self.assertRaisesRegex(ValueError, error):
                    self.inspect_fixture(fixture)

    def test_raw_opcode_negative_control(self):
        fixture = Fixture()
        original_nm, original_dis = fixture.nm, fixture.dis
        fixture.word(0x100c, 0xe5802000)  # Store, despite unchanged textual LDR.
        self.assertEqual((fixture.nm, fixture.dis), (original_nm, original_dis))
        with self.assertRaisesRegex(ValueError, 'actual guarded-load opcodes differ'):
            self.inspect_fixture(fixture)


class ElfReaderTests(unittest.TestCase):
    def test_file_backed_boundaries(self):
        data = image(0x40)
        data[0x100:] = bytes(range(0x40))
        at = CHECKER.elf_reader(data)
        for address, size in ((0x1000, 1), (0x103f, 1), (0x1000, 0x40), (0x1040, 0)):
            with self.subTest(address=address, size=size):
                self.assertEqual(at(address, size, True), data[address-0xf00:address-0xf00+size])
        for address, size in ((0xfff, 1), (0x1040, 1), (0x103f, 2), (0x1000, 0x41)):
            with self.subTest(address=address, size=size):
                with self.assertRaisesRegex(ValueError, 'unbacked'):
                    at(address, size)

    def test_header_validation(self):
        mutations = [('short', lambda d: d.__delitem__(slice(51, None))),
                     ('magic', lambda d: d.__setitem__(0, 0)),
                     ('ELF64', lambda d: d.__setitem__(4, 2)),
                     ('big endian', lambda d: d.__setitem__(5, 2)),
                     ('machine', lambda d: struct.pack_into('<H', d, 18, 3)),
                     ('small phsize', lambda d: struct.pack_into('<H', d, 42, 31)),
                     ('phoff', lambda d: struct.pack_into('<I', d, 28, len(d))),
                     ('phnum', lambda d: struct.pack_into('<H', d, 44, 100)),
                     ('filesz', lambda d: struct.pack_into('<I', d, 68, len(d)))]
        for name, mutate in mutations:
            with self.subTest(case=name):
                data = image(0x40)
                mutate(data)
                with self.assertRaises(ValueError):
                    CHECKER.elf_reader(data)

    def test_flags_nonload_and_memsz_do_not_back_bytes(self):
        for field, value in ((76, 4), (52, 0), (68, 0x20)):
            with self.subTest(field=field):
                data = image(0x40)
                struct.pack_into('<I', data, field, value)
                at = CHECKER.elf_reader(data)
                if field == 76:
                    self.assertEqual(at(0x1000, 4), bytes(4))
                with self.assertRaisesRegex(ValueError, 'unbacked'):
                    at(0x1030, 4, executable=True)

    def test_overlaps_ambiguous_and_adjacent_not_stitched(self):
        for base, length, address, size in ((0x1000, 0x40, 0x1000, 4),
                                            (0x1010, 0x10, 0x1010, 4),
                                            (0x1040, 0x40, 0x103f, 2)):
            with self.subTest(base=base):
                data = image(0x80)
                struct.pack_into('<H', data, 44, 2)
                struct.pack_into('<I', data, 68, 0x40)
                struct.pack_into('<8I', data, 84, 1, 0x140, base, base, length, length, 4, 4)
                at = CHECKER.elf_reader(data)
                with self.assertRaisesRegex(ValueError, 'ambiguous/unbacked'):
                    at(address, size, True)
                if base != 0x1000:
                    self.assertEqual(at(0x1000, 4, True), bytes(4))


if __name__ == '__main__':
    print('Checker SHA256:', CHECKER_HASH, flush=True)
    unittest.main(verbosity=2)
