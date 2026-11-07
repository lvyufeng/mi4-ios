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
STORE = (0xf57ff04f, 0xf57ff06f, 0xe5801000, 0xf57ff04f, 0xf57ff06f,
         0xe3a00000, 0xe12fff1e, 0xe3a00008, 0xe12fff1e)
STORE_START = b'DWC3 guarded RAM store selftest; no MMIO target writes'
STORE_FINISH = b'dwc3_ro store selftest passed; RAM writes only; controller target reads inhibited'
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
    def __init__(self, irq_only=False, recovery_only=False, clock_snapshot=False,
                 root_snapshot=False, store_selftest=False):
        self.irq_only, self.recovery_only = irq_only, recovery_only
        self.clock_snapshot, self.root_snapshot = clock_snapshot, root_snapshot
        self.store_selftest = store_selftest
        self.payload, self.entry = image(), image(0x100)
        self.config = ''.join('#define STAGE90_' + name + ' ' + value + '\n'
                              for name, value in (('DWC3_READONLY', '1'),
                              ('SKIP_USB_PREBOOT', '1'), ('CACHE_MODE', '0'),
                              ('PMAP_ATTR_MODE', '0'), ('HW_WATCHDOG', '1'),
                              ('DEADMAN_ENABLE', '1'),
                               ('DWC3_TARGET_READS', '0' if recovery_only or store_selftest else '1')))
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
            'stage90_guarded_read32_state': (0x2000, 56 if store_selftest else 52)}
        self.nm = ''.join(f'{addr:08x} {size:08x} '
                          f'{"B" if name == "stage90_guarded_read32_state" else "T"} {name}\n'
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
        if clock_snapshot:
            self.config += '#define STAGE90_DWC3_CLOCK_SNAPSHOT 1\n'
            self.nm += ('00001b00 00000004 T mi4_dwc3_clock_snapshot\n'
                        '00002400 0000001c R clock_snapshot_addresses\n')
            self.dis = self.dis.replace('bl 1500 <mi4_dwc3_identify>',
                                        'bl 1b00 <mi4_dwc3_clock_snapshot>')
            self.word(0x1404, branch(0x1404, 0x1b00, 0xeb000000))
            self.word(0x1b00, 0xe12fff1e)
            for i, address in enumerate((0xfc400108, 0xfc4003c8, 0xfc4003d0,
                                         0xfc4003cc, 0xfc4004ac, 0xfc4003c0, 0xfc4003d4)):
                self.word(0x2400+i*4, address)
            self.payload = self.payload.replace(MARKERS[-1], b'X'*len(MARKERS[-1]))
            marker = b'dwc3_ro finished; GCC clock snapshot only; no DWC3 core reads\0'
            self.payload[0x1600:0x1600+len(marker)] = marker
        if root_snapshot:
            self.config += ('#define STAGE90_DWC3_ROOT_SNAPSHOT 1\n'
                            '#define STAGE90_DWC3_CLOCK_SNAPSHOT 1\n')
            self.nm += ('00001c00 00000004 T mi4_dwc3_root_snapshot\n'
                        '00002600 00000034 R root_snapshot_addresses\n')
            self.dis = self.dis.replace('bl 1500 <mi4_dwc3_identify>',
                                        'bl 1c00 <mi4_dwc3_root_snapshot>')
            self.word(0x1404, branch(0x1404, 0x1c00, 0xeb000000))
            self.word(0x1c00, 0xe12fff1e)
            for i, address in enumerate((0xfc400108, 0xfc4003c8, 0xfc4003d0,
                                         0xfc4003cc, 0xfc4004ac, 0xfc4003c0, 0xfc4003d4,
                                         0xfc4003d8, 0xfc4003dc, 0xfc4003e0, 0xfc4003e4,
                                         0xfc40001c, 0xfc401480)):
                self.word(0x2600+i*4, address)
            self.payload = self.payload.replace(MARKERS[-1], b'X'*len(MARKERS[-1]))
            marker = b'dwc3_ro finished; GCC root snapshot only; no DWC3 core reads\0'
            self.payload[0x1600:0x1600+len(marker)] = marker
        if recovery_only:
            self.dis = self.dis.replace('bl 1500 <mi4_dwc3_identify>',
                                        'bl 1040 <stage90_guarded_read32>')
            self.word(0x1404, branch(0x1404, 0x1040, 0xeb000000))
            self.payload = self.payload.replace(MARKERS[-1], b'X'*len(MARKERS[-1]))
            marker = b'dwc3_ro recovery verified; controller target reads inhibited\0'
            self.payload[0x1600:0x1600+len(marker)] = marker
        if store_selftest:
            self.config += ('#define STAGE90_GUARDED_STORE32 1\n'
                            '#define STAGE90_GUARDED_STORE_SELFTEST 1\n')
            extra = {'stage90_guarded_write32': (0x2280, 12),
                     'stage90_guarded_write32_store_arm': (0x2300, 36),
                     'stage90_guarded_write32_fault': (0x2308, 4),
                     'stage90_guarded_write32_recovery': (0x231c, 8)}
            self.nm += ''.join(f'{addr:08x} {size:08x} T {name}\n'
                               for name, (addr, size) in extra.items())
            for index, instruction in enumerate(STORE):
                self.word(0x2300+index*4, instruction)
            for address, instruction in (
                    (0x2280, branch(0x2280, 0x1180, 0xeb000000)),
                    (0x2284, branch(0x2284, 0x2300, 0xeb000000)),
                    (0x2288, 0xe12fff1e)):
                self.word(address, instruction)
            self.dis = self.dis.replace('bl 1500 <mi4_dwc3_identify>',
                'bl 1040 <stage90_guarded_read32>\n'
                '  1408: eb000000 bl 1040 <stage90_guarded_read32>\n'
                '  140c: eb000000 bl 2280 <stage90_guarded_write32>\n'
                '  1410: eb000000 bl 1040 <stage90_guarded_read32>\n'
                '  1414: eb000000 bl 2280 <stage90_guarded_write32>')
            self.dis += ('00002280 <stage90_guarded_write32>:\n'
                         '  2280: eb000000 bl 1180 <stage90_guarded_read32_cpsr_read>\n'
                         '  2284: eb000000 bl 2300 <stage90_guarded_write32_store_arm>\n'
                         '  2288: e12fff1e bx lr\n')
            self.payload = self.payload.replace(MARKERS[-1], b'X'*len(MARKERS[-1]))
            marker = STORE_START+b'\0'+STORE_FINISH+b'\0'
            self.payload[0x1600:0x1600+len(marker)] = marker
        if irq_only:
            self.config += '#define STAGE90_GUARDED_IRQ_ONLY 1\n'
            extra = {'stage90_vectors': (0x1700, 32),
                     'stage90_guarded_fiq_park': (0x1840, 28),
                     'stage90_exception_common': (0x1900, 24),
                     'platform_reboot': (0x1980, 4),
                     'stage90_guarded_read32_irq_save': (0x1a00, 52),
                     'stage90_guarded_read32_irq_restore': (0x1a40, 28)}
            self.nm += ''.join(f'{addr:08x} {size:08x} T {name}\n'
                               for name, (addr, size) in extra.items())
            self.nm += '00001800 T stage90_guarded_fiq_hook_contract\n'
            # Deliberately no vector_fiq label/disassembly: aliases need not be printed.
            words = {
                0x171c: (branch(0x171c, 0x1800, 0xea000000),),
                0x1800: (0xe59f8018, 0xe5989000, 0xe3590000,
                         branch(0x180c, 0x1840, 0x1a000000), 0xe59f000c,
                         branch(0x1814, 0x1900, 0xea000000)),
                0x1820: (0x2000, 0x2080),
                0x1840: (0xe3a09007, 0xe5889018, 0xe3049651, 0xe3449752,
                         0xe5889028, 0xe320f002, 0xeafffffd),
                0x1900: (0xf10c00c0, 0xe1a04000, 0xe59f0000,
                         branch(0x190c, 0x1980, 0xeb000000), 0xe320f002, 0xeafffffd),
                0x1a00: (0xe10f0000, 0xe200101f, 0xe3510013, 0x112fff1e,
                         0xe3100020, 0x112fff1e, 0xe3100c02, 0x112fff1e,
                         0xe3100401, 0x112fff1e, 0xf10c0080, 0xf57ff06f, 0xe12fff1e),
                0x1a40: (0xe10f1000, 0xe3c11080, 0xe2000080, 0xe1811000,
                         0xe121f001, 0xf57ff06f, 0xe12fff1e),
                0x2080: (0x00716966,)}
            for address, values in words.items():
                for i, value in enumerate(values):
                    self.word(address+i*4, value)

    def word(self, va, value, entry=False):
        struct.pack_into('<I', self.entry if entry else self.payload, va-0x1000+0x100, value)

    def symbol(self, name, size=None, address=None, remove=False, entry=False):
        attr = 'entry_nm' if entry else 'nm'
        text = getattr(self, attr)
        pattern = r'^([0-9a-f]+) ([0-9a-f]+) ([TBb]) ' + re.escape(name) + r'\n'
        def replace(match):
            return '' if remove else (f'{address if address is not None else int(match[1],16):08x} '
                                      f'{size if size is not None else int(match[2],16):08x} {match[3]} {name}\n')
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
                    CHECKER.inspect(payload, entry, config, irq_only=fixture.irq_only,
                                    recovery_only=fixture.recovery_only,
                                    clock_snapshot=fixture.clock_snapshot,
                                    root_snapshot=fixture.root_snapshot,
                                    store_selftest=fixture.store_selftest)
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


    def test_irq_only_positive_unsized_hook_and_negative_literals(self):
        fixture = Fixture(irq_only=True)
        self.assertNotIn('vector_fiq', fixture.nm)
        self.assertIn('PASS:', self.inspect_fixture(fixture)[0])
        # GNU as may put either literal behind the instruction (U=0).
        fixture.word(0x1800, 0xe51f8018)
        fixture.word(0x17f0, 0x2000)
        fixture.word(0x1810, 0xe51f002c)
        fixture.word(0x17ec, 0x2080)
        self.assertIn('PASS:', self.inspect_fixture(fixture)[0])
        # A file-backed data LOAD can hold literals without executable permission.
        struct.pack_into('<H', fixture.payload, 44, 2)
        struct.pack_into('<8I', fixture.payload, 84, 1, 0x180, 0x2800, 0x2800, 8, 8, 4, 4)
        struct.pack_into('<2I', fixture.payload, 0x180, 0x2000, 0x2080)
        fixture.word(0x1800, 0xe59f8ff8)  # 0x1808 + 0xff8 = 0x2800.
        fixture.word(0x1810, 0xe59f0fec)
        self.assertIn('PASS:', self.inspect_fixture(fixture)[0])

    def test_irq_only_raw_mutations_ignore_original_command_text(self):
        cases = [
            (0x171c, branch(0x171c, 0x1804, 0xea000000), 'exact guarded hook'),
            (0x171c, branch(0x171c, 0x1800, 0xeb000000), 'unconditional B'),
            (0x171c, branch(0x171c, 0x1800, 0x1a000000), 'unconditional B'),
            (0x1800, 0xe59f7018, 'PC-relative word LDR'),
            (0x1800, 0xe5bf8018, 'PC-relative word LDR'),
            (0x1820, 0x2004, 'actual guard state'),
            (0x1804, 0xe5989004, 'banked r9'),
            (0x1804, 0xe5980000, 'banked r9'),
            (0x1808, 0xe3590001, 'compare zero'),
            (0x1808, 0x13590000, 'compare zero'),
            (0x180c, branch(0x180c, 0x1840, 0x0a000000), 'must be BNE'),
            (0x180c, branch(0x180c, 0x1840, 0x1b000000), 'must be BNE'),
            (0x180c, branch(0x180c, 0x1844, 0x1a000000), 'exact fail-stop'),
            (0x1810, 0xe59f100c, 'PC-relative word LDR'),
            (0x1824, 0x2084, 'message differs'),
            (0x1814, branch(0x1814, 0x1904, 0xea000000), 'misses fatal common'),
            (0x1814, branch(0x1814, 0x1900, 0xeb000000), 'unconditionally'),
            (0x1840, 0xe3a09000, 'park opcodes'),
            (0x1844, 0xe5880018, 'park opcodes'),
            (0x1844, 0xe588901c, 'park opcodes'),
            (0x1848, 0xe3049650, 'park opcodes'),
            (0x184c, 0xe3449753, 'park opcodes'),
            (0x1850, 0xe588902c, 'park opcodes'),
            (0x1854, 0xe12fff1e, 'park opcodes'),
            (0x1858, 0xe12fff1e, 'park opcodes'),
            (0x1a28, 0xf10c00c0, 'irq_save opcodes'),
            (0x1a00, 0xe3a00013, 'irq_save opcodes'),
            (0x1a44, 0xe3c110c0, 'irq_restore opcodes'),
            (0x1a48, 0xe20000c0, 'irq_restore opcodes'),
            (0x1904, 0xe12fff1e, 'unexpected instruction'),
            (0x190c, branch(0x190c, 0x1984, 0xeb000000), 'reboot/park'),
            (0x1914, 0xe12fff1e, 'reboot/park'),
        ]
        self.assertGreaterEqual(len(cases), 20)
        original = Fixture(irq_only=True)
        for address, value, error in cases:
            with self.subTest(address=hex(address), value=hex(value)):
                fixture = copy.deepcopy(original)
                fixture.word(address, value)
                self.assertEqual((fixture.nm, fixture.dis), (original.nm, original.dis))
                with self.assertRaisesRegex(ValueError, error):
                    self.inspect_fixture(fixture)

    def test_irq_only_configuration_and_symbol_contracts(self):
        for value in ('1u', '0x1ULL', '1LLu'):
            fixture = Fixture(irq_only=True)
            fixture.define('GUARDED_IRQ_ONLY', value)
            fixture.define('DWC3_TARGET_READS', value)
            self.assertIn('PASS:', self.inspect_fixture(fixture)[0])
        fixture = Fixture(irq_only=True)
        fixture.config = fixture.config.replace('#define STAGE90_DWC3_TARGET_READS 1\n', '')
        with self.assertRaisesRegex(ValueError, 'DWC3_TARGET_READS'):
            self.inspect_fixture(fixture)
        fixture = Fixture()
        fixture.nm = fixture.nm.replace('00001040 00000004 T stage90_guarded_read32',
                                        '00001040 T stage90_guarded_read32')
        with self.assertRaisesRegex(ValueError, 'missing linked symbol'):
            self.inspect_fixture(fixture)
        for value in ('0', '2', '-1', 'IRQ_ALIAS'):
            with self.subTest(value=value):
                fixture = Fixture(irq_only=True)
                fixture.define('GUARDED_IRQ_ONLY', value)
                with self.assertRaisesRegex(ValueError, 'GUARDED_IRQ_ONLY'):
                    self.inspect_fixture(fixture)
        fixture = Fixture(irq_only=True)
        fixture.config = fixture.config.replace('#define STAGE90_GUARDED_IRQ_ONLY 1\n', '')
        with self.assertRaisesRegex(ValueError, 'GUARDED_IRQ_ONLY'):
            self.inspect_fixture(fixture)
        fixture = Fixture(irq_only=True)
        fixture.nm = fixture.nm.replace('00001800 T stage90_guarded_fiq_hook_contract\n', '')
        with self.assertRaisesRegex(ValueError, 'missing IRQ-only linked symbol'):
            self.inspect_fixture(fixture)
        for name, size in (('stage90_vectors', 28), ('stage90_guarded_fiq_park', 24),
                           ('stage90_guarded_read32_irq_save', 48),
                           ('stage90_guarded_read32_irq_restore', 24)):
            with self.subTest(symbol=name):
                fixture = Fixture(irq_only=True)
                fixture.symbol(name, size=size)
                with self.assertRaises(ValueError):
                    self.inspect_fixture(fixture)

    def test_strict_default_stays_strict_and_legacy_config_compatible(self):
        fixture = Fixture()
        fixture.config = fixture.config.replace('#define STAGE90_DWC3_TARGET_READS 1\n', '')
        self.assertIn('PASS:', self.inspect_fixture(fixture)[0])
        fixture.config += '#define STAGE90_GUARDED_IRQ_ONLY 0\n'
        self.assertIn('PASS:', self.inspect_fixture(fixture)[0])
        for value in ('1', '2', 'IRQ_ALIAS'):
            fixture.define('GUARDED_IRQ_ONLY', value)
            with self.assertRaisesRegex(ValueError, 'GUARDED_IRQ_ONLY'):
                self.inspect_fixture(fixture)
        fixture = Fixture(irq_only=True)
        fixture.irq_only = False
        with self.assertRaisesRegex(ValueError, 'GUARDED_IRQ_ONLY'):
            self.inspect_fixture(fixture)

    def test_recovery_only_positive_and_controller_gate_negatives(self):
        original = Fixture(irq_only=True, recovery_only=True)
        self.assertIn('PASS:', self.inspect_fixture(original)[0])
        cases = [
            ('wrong config', 'DWC3_TARGET_READS', lambda f: f.define('DWC3_TARGET_READS', '1')),
            ('nonbool config', 'DWC3_TARGET_READS', lambda f: f.define('DWC3_TARGET_READS', '2')),
            ('missing config', 'DWC3_TARGET_READS', lambda f: setattr(f, 'config', f.config.replace('#define STAGE90_DWC3_TARGET_READS 0\n', ''))),
            ('identity call', 'controller/core', lambda f: setattr(f, 'dis', f.dis.replace('bl 1040 <stage90_guarded_read32>', 'bl 1500 <mi4_dwc3_identify>', 1))),
            ('controller callback', 'controller/core', lambda f: setattr(f, 'dis', f.dis.replace('bl 1040 <stage90_guarded_read32>', 'bl 1040 <stage90_guarded_read32>\n  1408: eb000000 bl 1500 <dwc3_probe_read>', 1))),
            ('third guarded call', 'exactly twice', lambda f: setattr(f, 'dis', f.dis.replace('bl 1040 <stage90_guarded_read32>', 'bl 1040 <stage90_guarded_read32>\n  1408: eb000000 bl 1040 <stage90_guarded_read32>', 1))),
            ('inhibit marker absent', 'diagnostic', lambda f: setattr(f, 'payload', f.payload.replace(b'controller target reads inhibited', b'X'*len(b'controller target reads inhibited')))),
        ]
        for name, error, mutate in cases:
            with self.subTest(case=name):
                fixture = copy.deepcopy(original)
                mutate(fixture)
                with self.assertRaisesRegex(ValueError, error):
                    self.inspect_fixture(fixture)

    def test_clock_snapshot_positive_and_config_contracts(self):
        for irq_only in (False, True):
            fixture = Fixture(irq_only=irq_only, clock_snapshot=True)
            self.assertIn('PASS:', self.inspect_fixture(fixture)[0])
        original = Fixture(irq_only=True, clock_snapshot=True)
        for value in ('0', '2', '-1', 'SNAPSHOT_ALIAS'):
            with self.subTest(value=value):
                fixture = copy.deepcopy(original)
                fixture.define('DWC3_CLOCK_SNAPSHOT', value)
                with self.assertRaisesRegex(ValueError, 'DWC3_CLOCK_SNAPSHOT'):
                    self.inspect_fixture(fixture)
        for name in ('DWC3_CLOCK_SNAPSHOT', 'DWC3_TARGET_READS'):
            fixture = copy.deepcopy(original)
            fixture.config = re.sub(r'#define STAGE90_'+name+r' \S+\n', '', fixture.config)
            with self.assertRaisesRegex(ValueError, name):
                self.inspect_fixture(fixture)
        fixture = copy.deepcopy(original)
        fixture.define('DWC3_TARGET_READS', '0')
        with self.assertRaisesRegex(ValueError, 'DWC3_TARGET_READS'):
            self.inspect_fixture(fixture)
        fixture = copy.deepcopy(original)
        fixture.clock_snapshot = False
        with self.assertRaisesRegex(ValueError, 'DWC3_CLOCK_SNAPSHOT'):
            self.inspect_fixture(fixture)
        for fixture in (Fixture(), Fixture(recovery_only=True)):
            fixture.config += '#define STAGE90_DWC3_CLOCK_SNAPSHOT 0\n'
            self.assertIn('PASS:', self.inspect_fixture(fixture)[0])
        fixture = copy.deepcopy(original)
        fixture.recovery_only = True
        with self.assertRaisesRegex(ValueError, 'mutually exclusive'):
            self.inspect_fixture(fixture)

    def test_clock_snapshot_linked_call_and_marker_negatives(self):
        original = Fixture(irq_only=True, clock_snapshot=True)
        cases = [
            ('no snapshot call', 'exactly once', lambda f: setattr(f, 'dis', f.dis.replace('bl 1b00 <mi4_dwc3_clock_snapshot>', 'b 1b00 <mi4_dwc3_clock_snapshot>'))),
            ('duplicate snapshot call', 'exactly once', lambda f: setattr(f, 'dis', f.dis.replace('bl 1b00 <mi4_dwc3_clock_snapshot>', 'bl 1b00 <mi4_dwc3_clock_snapshot>\n bl 1b00 <mi4_dwc3_clock_snapshot>'))),
            ('identity retained', 'retains identity', lambda f: setattr(f, 'dis', f.dis.replace('bl 1b00 <mi4_dwc3_clock_snapshot>', 'bl 1b00 <mi4_dwc3_clock_snapshot>\n bl 1500 <mi4_dwc3_identify>'))),
            ('wrong core', 'exactly once', lambda f: setattr(f, 'dis', f.dis.replace('<mi4_dwc3_clock_snapshot>', '<other_core>'))),
            ('no guard', 'exactly once', lambda f: setattr(f, 'dis', f.dis.replace('bl 1040 <stage90_guarded_read32>', 'bl 1040 <other_guard>'))),
            ('core before guard', 'precedes guarded', lambda f: setattr(f, 'dis', f.dis.replace('bl 1040 <stage90_guarded_read32>\n  1404: eb00003d bl 1b00 <mi4_dwc3_clock_snapshot>', 'bl 1b00 <mi4_dwc3_clock_snapshot>\n bl 1040 <stage90_guarded_read32>'))),
            ('finish marker absent', 'diagnostic', lambda f: setattr(f, 'payload', f.payload.replace(b'GCC clock snapshot only', b'X'*len(b'GCC clock snapshot only')))),
            ('missing core symbol', 'missing linked symbol mi4_dwc3_clock_snapshot', lambda f: f.symbol('mi4_dwc3_clock_snapshot', remove=True)),
            ('zero core symbol', 'missing linked symbol mi4_dwc3_clock_snapshot', lambda f: f.symbol('mi4_dwc3_clock_snapshot', size=0)),
        ]
        for name, error, mutate in cases:
            with self.subTest(case=name):
                fixture = copy.deepcopy(original)
                mutate(fixture)
                with self.assertRaisesRegex(ValueError, error):
                    self.inspect_fixture(fixture)
        for index in range(7):
            fixture = copy.deepcopy(original)
            fixture.word(0x2400+index*4, 0xf920c120)  # Core address despite unchanged nm/dis.
            self.assertEqual((fixture.nm, fixture.dis), (original.nm, original.dis))
            with self.assertRaisesRegex(ValueError, 'GCC address array'):
                self.inspect_fixture(fixture)
        for old, new in (('00002400 0000001c R clock_snapshot_addresses\n', ''),
                         ('0000001c R clock_snapshot_addresses', '00000018 R clock_snapshot_addresses'),
                         ('00002400 0000001c R clock_snapshot_addresses', '000027f0 0000001c R clock_snapshot_addresses')):
            fixture = copy.deepcopy(original)
            fixture.nm = fixture.nm.replace(old, new)
            with self.assertRaisesRegex(ValueError, 'GCC address array|unbacked'):
                self.inspect_fixture(fixture)

    def test_clock_snapshot_cli_rejects_recovery_combination(self):
        argv = ['checker', '--payload', 'p', '--entry', 'e', '--config', 'c',
                '--clock-snapshot', '--recovery-only']
        with mock.patch.object(sys, 'argv', argv), contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit) as error:
                CHECKER.main()
        self.assertEqual(error.exception.code, 2)

    def test_root_snapshot_positive_configuration_and_cross_modes(self):
        for irq_only in (False, True):
            fixture = Fixture(irq_only=irq_only, root_snapshot=True)
            self.assertIn('PASS:', self.inspect_fixture(fixture)[0])
        original = Fixture(irq_only=True, root_snapshot=True)
        for value in ('0', '2', '-1', 'ROOT_ALIAS'):
            fixture = copy.deepcopy(original)
            fixture.define('DWC3_ROOT_SNAPSHOT', value)
            with self.subTest(value=value), self.assertRaisesRegex(ValueError, 'DWC3_ROOT_SNAPSHOT'):
                self.inspect_fixture(fixture)
        for name in ('DWC3_ROOT_SNAPSHOT', 'DWC3_CLOCK_SNAPSHOT', 'DWC3_TARGET_READS'):
            for absent in (False, True):
                fixture = copy.deepcopy(original)
                if absent:
                    fixture.config = re.sub(r'#define STAGE90_'+name+r' \S+\n', '', fixture.config)
                else:
                    fixture.define(name, '0')
                with self.subTest(define=name, absent=absent), self.assertRaisesRegex(ValueError, name):
                    self.inspect_fixture(fixture)
        fixture = copy.deepcopy(original)
        for name in ('DWC3_ROOT_SNAPSHOT', 'DWC3_CLOCK_SNAPSHOT', 'DWC3_TARGET_READS'):
            fixture.define(name, '0x1ULL')
        self.assertIn('PASS:', self.inspect_fixture(fixture)[0])
        for other in ('clock_snapshot', 'recovery_only'):
            fixture = copy.deepcopy(original)
            setattr(fixture, other, True)
            with self.assertRaisesRegex(ValueError, 'mutually exclusive'):
                self.inspect_fixture(fixture)
        fixture = copy.deepcopy(original)
        fixture.root_snapshot, fixture.clock_snapshot = False, True
        with self.assertRaisesRegex(ValueError, 'DWC3_ROOT_SNAPSHOT'):
            self.inspect_fixture(fixture)
        for fixture in (Fixture(), Fixture(recovery_only=True), Fixture(clock_snapshot=True)):
            fixture.config += '#define STAGE90_DWC3_ROOT_SNAPSHOT 0\n'
            self.assertIn('PASS:', self.inspect_fixture(fixture)[0])
            fixture.dis = fixture.dis.replace('  1400:',
                '  13fc: eb000000 bl 1c00 <mi4_dwc3_root_snapshot>\n  1400:')
            with self.assertRaisesRegex(ValueError, 'non-root probe retains root'):
                self.inspect_fixture(fixture)

    def test_root_snapshot_raw_table_and_linked_call_negatives(self):
        original = Fixture(irq_only=True, root_snapshot=True)
        for index in range(13):
            fixture = copy.deepcopy(original)
            fixture.word(0x2600+index*4, 0xf920c120)
            self.assertEqual((fixture.nm, fixture.dis), (original.nm, original.dis))
            with self.subTest(table_index=index), self.assertRaisesRegex(ValueError, 'root snapshot GCC address array'):
                self.inspect_fixture(fixture)
        for old, new in (('00002600 00000034 R root_snapshot_addresses\n', ''),
                         ('00000034 R root_snapshot_addresses', '00000030 R root_snapshot_addresses'),
                         ('00002600 00000034 R root_snapshot_addresses', '000027f0 00000034 R root_snapshot_addresses')):
            fixture = copy.deepcopy(original)
            fixture.nm = fixture.nm.replace(old, new)
            with self.assertRaisesRegex(ValueError, 'root snapshot GCC address array|unbacked'):
                self.inspect_fixture(fixture)
        cases = [
            ('missing core', 'missing linked symbol mi4_dwc3_root_snapshot', lambda f: f.symbol('mi4_dwc3_root_snapshot', remove=True)),
            ('zero core', 'missing linked symbol mi4_dwc3_root_snapshot', lambda f: f.symbol('mi4_dwc3_root_snapshot', size=0)),
            ('no root call', 'exactly once', lambda f: setattr(f, 'dis', f.dis.replace('bl 1c00 <mi4_dwc3_root_snapshot>', 'b 1c00 <mi4_dwc3_root_snapshot>'))),
            ('wrong root call', 'exactly once', lambda f: setattr(f, 'dis', f.dis.replace('<mi4_dwc3_root_snapshot>', '<other_core>'))),
            ('duplicate root call', 'exactly once', lambda f: setattr(f, 'dis', f.dis.replace('bl 1c00 <mi4_dwc3_root_snapshot>', 'bl 1c00 <mi4_dwc3_root_snapshot>\n bl 1c00 <mi4_dwc3_root_snapshot>'))),
            ('identity retained', 'retains identity or clock', lambda f: setattr(f, 'dis', f.dis.replace('bl 1c00 <mi4_dwc3_root_snapshot>', 'bl 1c00 <mi4_dwc3_root_snapshot>\n bl 1500 <mi4_dwc3_identify>'))),
            ('clock retained', 'retains identity or clock', lambda f: setattr(f, 'dis', f.dis.replace('bl 1c00 <mi4_dwc3_root_snapshot>', 'bl 1c00 <mi4_dwc3_root_snapshot>\n bl 1b00 <mi4_dwc3_clock_snapshot>'))),
            ('no guard', 'exactly once', lambda f: setattr(f, 'dis', f.dis.replace('bl 1040 <stage90_guarded_read32>', 'bl 1040 <other_guard>'))),
            ('root before guard', 'precedes guarded', lambda f: setattr(f, 'dis', f.dis.replace('bl 1040 <stage90_guarded_read32>\n  1404: eb00003d bl 1c00 <mi4_dwc3_root_snapshot>', 'bl 1c00 <mi4_dwc3_root_snapshot>\n bl 1040 <stage90_guarded_read32>'))),
            ('finish marker absent', 'diagnostic', lambda f: setattr(f, 'payload', f.payload.replace(b'GCC root snapshot only', b'X'*len(b'GCC root snapshot only')))),
        ]
        for name, error, mutate in cases:
            fixture = copy.deepcopy(original)
            mutate(fixture)
            with self.subTest(case=name), self.assertRaisesRegex(ValueError, error):
                self.inspect_fixture(fixture)

    def test_root_snapshot_cli_rejects_other_modes(self):
        for mode in ('--clock-snapshot', '--recovery-only'):
            argv = ['checker', '--payload', 'p', '--entry', 'e', '--config', 'c',
                    '--root-snapshot', mode]
            with mock.patch.object(sys, 'argv', argv), contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit) as error:
                    CHECKER.main()
            self.assertEqual(error.exception.code, 2)

    def test_store_selftest_inline_and_outlined_positive(self):
        for guard_outlined, store_outlined in ((False, False), (False, True),
                                                (True, False), (True, True)):
            fixture = Fixture(irq_only=True, store_selftest=True)
            self.outline_selftests(fixture, guard_outlined, store_outlined)
            with self.subTest(guard=guard_outlined, store=store_outlined):
                output, calls = self.inspect_fixture(fixture)
                self.assertIn('PASS:', output)
                self.assertIn('LIMIT: static acceptance only', output)
                self.assertEqual(calls, 3)

    @staticmethod
    def outline_selftests(fixture, guard=True, store=True):
        # Disassembly text models only direct named helpers, not arbitrary CFG.
        guard_lines = ('  1400: ebffff0e bl 1040 <stage90_guarded_read32>\n'
                       '  1404: eb00003d bl 1040 <stage90_guarded_read32>')
        store_lines = ('  1408: eb000000 bl 1040 <stage90_guarded_read32>\n'
                       '  140c: eb000000 bl 2280 <stage90_guarded_write32>\n'
                       '  1410: eb000000 bl 1040 <stage90_guarded_read32>\n'
                       '  1414: eb000000 bl 2280 <stage90_guarded_write32>')
        for enabled, name, address, lines in (
                (guard, 'dwc3_probe_guard_selftest', 0x1d00, guard_lines),
                (store, 'dwc3_probe_store_selftest', 0x1e00, store_lines)):
            if enabled:
                assert lines in fixture.dis
                fixture.dis = fixture.dis.replace(lines,
                    f'  1400: eb000000 bl {address:x} <{name}>')
                fixture.nm += f'{address:08x} 00000020 t {name}\n'
                fixture.dis += f'{address:08x} <{name}>:\n'+lines+'\n'

    def test_store_selftest_configuration_and_cross_modes(self):
        original = Fixture(irq_only=True, store_selftest=True)
        for name in ('GUARDED_STORE32', 'GUARDED_STORE_SELFTEST', 'GUARDED_IRQ_ONLY',
                     'DWC3_READONLY', 'DWC3_TARGET_READS'):
            expected = '0' if name == 'DWC3_TARGET_READS' else '1'
            for value in ('1' if expected == '0' else '0', '2', '-1', 'STORE_ALIAS', None):
                fixture = copy.deepcopy(original)
                if value is None:
                    fixture.config = re.sub(r'#define STAGE90_'+name+r' \S+\n', '', fixture.config)
                else:
                    fixture.define(name, value)
                with self.subTest(name=name, value=value), self.assertRaisesRegex(ValueError, name):
                    self.inspect_fixture(fixture)
        fixture = copy.deepcopy(original)
        for name in ('GUARDED_STORE32', 'GUARDED_STORE_SELFTEST', 'GUARDED_IRQ_ONLY'):
            fixture.define(name, '0x1ULL')
        fixture.define('DWC3_TARGET_READS', '0UL')
        fixture.config += '#define STAGE90_DWC3_ROOT_SNAPSHOT 0\n#define STAGE90_DWC3_CLOCK_SNAPSHOT 0\n'
        self.assertIn('PASS:', self.inspect_fixture(fixture)[0])
        for name in ('DWC3_ROOT_SNAPSHOT', 'DWC3_CLOCK_SNAPSHOT'):
            fixture = copy.deepcopy(original)
            fixture.config += '#define STAGE90_'+name+' 1\n'
            with self.assertRaisesRegex(ValueError, name):
                self.inspect_fixture(fixture)
        for name in ('root_snapshot', 'clock_snapshot', 'recovery_only'):
            fixture = copy.deepcopy(original)
            setattr(fixture, name, True)
            with self.assertRaisesRegex(ValueError, 'mutually exclusive'):
                self.inspect_fixture(fixture)
        fixture = copy.deepcopy(original)
        fixture.irq_only = False
        with self.assertRaisesRegex(ValueError, 'requires --irq-only'):
            self.inspect_fixture(fixture)
        for mode in ({}, {'irq_only': True}, {'recovery_only': True},
                     {'clock_snapshot': True}, {'root_snapshot': True}):
            for name in ('GUARDED_STORE32', 'GUARDED_STORE_SELFTEST'):
                fixture = Fixture(**mode)
                fixture.config += '#define STAGE90_'+name+' 0\n'
                self.assertIn('PASS:', self.inspect_fixture(fixture)[0])
                fixture.define(name, '1')
                with self.subTest(mode=mode, name=name), self.assertRaisesRegex(ValueError, name):
                    self.inspect_fixture(fixture)

    def test_store_selftest_raw_mutations_ignore_original_text(self):
        original = Fixture(irq_only=True, store_selftest=True)
        cases = [(0x2308, 0xe5801004),  # Wrong target offset.
                 (0x2308, 0xe5811000),  # Wrong target register.
                 (0x2308, 0xe5802000),  # Wrong value register.
                 (0x2308, 0xe5901000),  # LDR instead of STR.
                 (0x2300, 0xe5801000),  # Extra STR in leading barriers.
                 (0x230c, 0xe5801000),  # Extra STR in trailing barriers.
                 (0x231c, 0xe3a00000),  # Recovery must return 8, never success.
                 (0x231c, 0xe5801000),  # Recovery store forbidden.
                 (0x2320, 0xe5801000)]
        for address, value in cases:
            fixture = copy.deepcopy(original)
            fixture.word(address, value)
            self.assertEqual((fixture.nm, fixture.dis), (original.nm, original.dis))
            with self.subTest(address=hex(address), value=hex(value)), self.assertRaisesRegex(ValueError, 'guarded-store opcodes'):
                self.inspect_fixture(fixture)
        for address, value, error in (
                (0x2280, 0xe1a00000, 'store wrapper'),
                (0x2284, branch(0x2284, 0x1000, 0xeb000000), 'store wrapper'),
                (0x1104, 0xe5801000, 'store-free loop'),
                (0x1844, 0xe588901c, 'park opcodes'),
                (0x100c, 0xe5802000, 'guarded-load opcodes')):
            fixture = copy.deepcopy(original)
            fixture.word(address, value)
            self.assertEqual((fixture.nm, fixture.dis), (original.nm, original.dis))
            with self.subTest(address=hex(address)), self.assertRaisesRegex(ValueError, error):
                self.inspect_fixture(fixture)
        fixture = copy.deepcopy(original)
        fixture.word(0x2280, branch(0x2280, 0x2300, 0xeb000000))
        fixture.word(0x2284, branch(0x2284, 0x1180, 0xeb000000))
        with self.assertRaisesRegex(ValueError, 'store wrapper'):
            self.inspect_fixture(fixture)

    def test_store_selftest_symbol_and_state_contracts(self):
        original = Fixture(irq_only=True, store_selftest=True)
        for name, changes, error in (
                ('stage90_guarded_read32_state', {'size': 52}, 'state B-symbol size'),
                ('stage90_guarded_read32_state', {'remove': True}, 'state B-symbol size'),
                ('stage90_guarded_write32', {'size': 0}, 'missing linked symbol'),
                ('stage90_guarded_write32', {'size': 10}, 'wrapper size'),
                ('stage90_guarded_write32', {'remove': True}, 'missing linked symbol'),
                ('stage90_guarded_write32_store_arm', {'size': 32}, 'label layout'),
                ('stage90_guarded_write32_fault', {'address': 0x230c}, 'label layout'),
                ('stage90_guarded_write32_fault', {'size': 8}, 'label layout'),
                ('stage90_guarded_write32_recovery', {'address': 0x2318}, 'label layout'),
                ('stage90_guarded_write32_recovery', {'size': 4}, 'label layout')):
            fixture = copy.deepcopy(original)
            fixture.symbol(name, **changes)
            with self.subTest(name=name, changes=changes), self.assertRaisesRegex(ValueError, error):
                self.inspect_fixture(fixture)
        fixture = copy.deepcopy(original)
        fixture.nm = fixture.nm.replace('00000038 B stage90_guarded_read32_state',
                                         '00000038 T stage90_guarded_read32_state')
        with self.assertRaisesRegex(ValueError, 'state B-symbol size'):
            self.inspect_fixture(fixture)
        fixture = Fixture()
        fixture.symbol('stage90_guarded_read32_state', size=0)
        self.assertIn('PASS:', self.inspect_fixture(fixture)[0])

    def test_store_selftest_call_and_diagnostic_negatives(self):
        original = Fixture(irq_only=True, store_selftest=True)
        cases = [
            ('missing write', 'exactly twice', lambda f: setattr(f, 'dis', f.dis.replace('bl 2280 <stage90_guarded_write32>', 'b 2280 <stage90_guarded_write32>', 1))),
            ('extra write', 'exactly twice', lambda f: setattr(f, 'dis', f.dis.replace('bl 2280 <stage90_guarded_write32>', 'bl 2280 <stage90_guarded_write32>\n bl 2280 <stage90_guarded_write32>', 1))),
            ('missing read', 'exactly four', lambda f: setattr(f, 'dis', f.dis.replace('bl 1040 <stage90_guarded_read32>', 'b 1040 <stage90_guarded_read32>', 1))),
            ('reordered', 'must follow', lambda f: setattr(f, 'dis', f.dis.replace('bl 1040 <stage90_guarded_read32>', 'bl 2280 <stage90_guarded_write32>', 1).replace('  1414: eb000000 bl 2280 <stage90_guarded_write32>', '  1414: eb000000 bl 1040 <stage90_guarded_read32>'))),
        ]
        for name in ('mi4_dwc3_identify', 'mi4_dwc3_clock_snapshot', 'mi4_dwc3_root_snapshot',
                     'dwc3_probe_read', 'usb_preboot_run', 'entry_usb_stream_poll'):
            cases.append((name, 'controller/core/stream', lambda f, n=name:
                setattr(f, 'dis', f.dis.replace('  1400:', '  13fc: eb000000 bl 1500 <'+n+'>\n  1400:', 1))))
        for marker in (STORE_START, STORE_FINISH):
            cases.append((repr(marker), 'diagnostic', lambda f, m=marker:
                setattr(f, 'payload', f.payload.replace(m, b'X'*len(m)))))
        for name, error, mutate in cases:
            fixture = copy.deepcopy(original)
            mutate(fixture)
            with self.subTest(case=name), self.assertRaisesRegex(ValueError, error):
                self.inspect_fixture(fixture)
        fixture = copy.deepcopy(original)
        fixture.payload = fixture.payload.replace(STORE_FINISH,
            b'dwc3_ro recovery verified; controller target reads inhibited'.ljust(len(STORE_FINISH), b'\0'))
        with self.assertRaisesRegex(ValueError, 'diagnostic'):
            self.inspect_fixture(fixture)
        for outlined in ('dwc3_probe_guard_selftest', 'dwc3_probe_store_selftest'):
            fixture = copy.deepcopy(original)
            self.outline_selftests(fixture)
            fixture.dis = fixture.dis.replace('bl 1d00 <'+outlined+'>', 'b 1d00 <'+outlined+'>') if outlined.endswith('guard_selftest') else fixture.dis.replace('bl 1e00 <'+outlined+'>', 'b 1e00 <'+outlined+'>')
            with self.assertRaisesRegex(ValueError, 'directly called exactly once'):
                self.inspect_fixture(fixture)
        fixture = copy.deepcopy(original)
        self.outline_selftests(fixture)
        fixture.dis += ' bl 1500 <mi4_dwc3_identify>\n'
        with self.assertRaisesRegex(ValueError, 'controller/core/stream'):
            self.inspect_fixture(fixture)
        for mode in ({}, {'recovery_only': True}, {'clock_snapshot': True}, {'root_snapshot': True}):
            fixture = Fixture(**mode)
            fixture.dis = fixture.dis.replace('  1400:', ' bl 2280 <stage90_guarded_write32>\n  1400:', 1)
            with self.assertRaisesRegex(ValueError, 'non-store probe'):
                self.inspect_fixture(fixture)

    def test_store_selftest_cli_rejects_other_modes_and_requires_irq(self):
        required = ['checker', '--payload', 'p', '--entry', 'e', '--config', 'c']
        for flags in (['--store-selftest'],
                      ['--irq-only', '--store-selftest', '--recovery-only'],
                      ['--irq-only', '--store-selftest', '--clock-snapshot'],
                      ['--irq-only', '--store-selftest', '--root-snapshot']):
            with mock.patch.object(sys, 'argv', required+flags), contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit) as error:
                    CHECKER.main()
            self.assertEqual(error.exception.code, 2)

    def test_cli_modes_are_explicit(self):
        required = ['--payload', 'p', '--entry', 'e', '--config', 'c']
        for flags in ([], ['--irq-only'], ['--irq-only', '--recovery-only'],
                      ['--clock-snapshot'], ['--irq-only', '--clock-snapshot'],
                      ['--root-snapshot'], ['--irq-only', '--root-snapshot'],
                      ['--irq-only', '--store-selftest']):
            with self.subTest(flags=flags), mock.patch.object(sys, 'argv', ['checker']+required+flags):
                with mock.patch.object(CHECKER, 'inspect') as inspect:
                    CHECKER.main()
                    inspect.assert_called_once_with(Path('p'), Path('e'), Path('c'),
                        irq_only='--irq-only' in flags, recovery_only='--recovery-only' in flags,
                        clock_snapshot='--clock-snapshot' in flags,
                        root_snapshot='--root-snapshot' in flags,
                         store_selftest='--store-selftest' in flags)


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
