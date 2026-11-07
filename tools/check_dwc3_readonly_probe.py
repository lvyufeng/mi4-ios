#!/usr/bin/env python3
"""Inspect the actual linked opt-in probe; no device access or image execution.

This is static acceptance, not proof of exception delivery, MMIO completion or USB.
"""
import argparse
from pathlib import Path
import re
import struct
import subprocess


def command(argv):
    return subprocess.run(argv, check=True, text=True, capture_output=True,
                          timeout=30).stdout


def elf_reader(data):
    if len(data) < 52 or data[:7] != b'\x7fELF\x01\x01\x01':
        raise ValueError('expected ELF32 little-endian')
    if struct.unpack_from('<H', data, 18)[0] != 40:
        raise ValueError('expected ARM ELF')
    phoff = struct.unpack_from('<I', data, 28)[0]
    phsize, phnum = struct.unpack_from('<HH', data, 42)
    if phsize < 32 or phoff + phsize * phnum > len(data):
        raise ValueError('invalid ELF program-header bounds')
    segments = []
    for index in range(phnum):
        kind, off, va, _, filesz, _, flags, _ = struct.unpack_from(
            '<8I', data, phoff + index * phsize)
        if kind == 1:
            if off + filesz > len(data):
                raise ValueError('invalid ELF load bounds')
            segments.append((va, off, filesz, flags))

    def at(va, size, executable=False):
        matches = [(off + va - base, flags) for base, off, length, flags in segments
                   if base <= va and size <= length and va - base <= length - size]
        if len(matches) != 1 or executable and not matches[0][1] & 1:
            raise ValueError('ambiguous/unbacked ELF address: '+hex(va))
        off = matches[0][0]
        return data[off:off+size]
    return at


def inspect(payload, entry, config):
    checks = 0

    def require(test, message):
        nonlocal checks
        checks += 1
        if not test:
            raise ValueError(message)

    defines = {}
    for line in config.read_text().splitlines():
        m = re.fullmatch(r'#define (STAGE90_\w+) (\S+)', line)
        if m:
            require(m[1] not in defines, 'duplicate build define '+m[1])
            defines[m[1]] = m[2]
    for name, expected in {'DWC3_READONLY': '1', 'SKIP_USB_PREBOOT': '1',
                           'CACHE_MODE': '0', 'PMAP_ATTR_MODE': '0',
                           'HW_WATCHDOG': '1', 'DEADMAN_ENABLE': '1'}.items():
        raw = defines.get('STAGE90_'+name, '')
        literal = re.fullmatch(r'(0[xX][0-9a-fA-F]+|0|[1-9][0-9]*)(?:[uU](?:[lL]{1,2})?|[lL]{1,2}[uU]?)?', raw)
        require(literal is not None and int(literal[1], 0) == int(expected),
                'actual payload configuration differs or is unexpanded: '+name)

    data = payload.read_bytes()
    at = elf_reader(data)
    nm = command(['arm-none-eabi-nm', '-S', '--defined-only', str(payload)])
    symbols = {}
    for line in nm.splitlines():
        m = re.fullmatch(r'([0-9a-fA-F]+) ([0-9a-fA-F]+) (\w) (\S+)', line)
        if m:
            symbols[m[4]] = (int(m[1], 16), int(m[2], 16))
    for name in ('stage90_guarded_read32', 'stage90_guarded_read32_abort_policy',
                 'stage90_guarded_read32_load_arm', 'stage90_guarded_read32_fault',
                 'stage90_guarded_read32_recovery', 'stage90_guarded_read32_park',
                 'stage90_data_abort_c_handler', 'stage90_dwc3_readonly_probe',
                 'mi4_dwc3_identify', 'kernel_entry'):
        require(name in symbols and symbols[name][1] > 0, 'missing linked symbol '+name)
    read_cpsr = symbols.get('stage90_guarded_read32_cpsr_read')
    require(read_cpsr is not None and read_cpsr[1] == 8 and
            at(read_cpsr[0], 8, True) == struct.pack('<2I', 0xe10f0000, 0xe12fff1e),
            'actual post-mask CPSR reader differs')
    start = symbols['stage90_guarded_read32_load_arm'][0]
    fault, fault_size = symbols['stage90_guarded_read32_fault']
    fixup, fixup_size = symbols['stage90_guarded_read32_recovery']
    require(fault == start+12 and fault_size == 4 and fixup == start+36 and fixup_size == 8,
            'guarded instruction/fixup label layout differs')
    expected = (0xf57ff04f, 0xf57ff06f, 0xe3a02000, 0xe5902000,
                0xf57ff04f, 0xf57ff06f, 0xe5812000, 0xe3a00000,
                0xe12fff1e, 0xe3a00002, 0xe12fff1e)
    require(at(start, 44, True) == struct.pack('<11I', *expected),
            'actual guarded-load opcodes differ')
    park = symbols['stage90_guarded_read32_park']
    require(park[1] == 12 and at(park[0], 12, True) ==
            struct.pack('<3I', 0xf10c00c0, 0xe320f002, 0xeafffffd),
            'unsupported-fault park is not the expected store-free loop')

    dis = command(['arm-none-eabi-objdump', '-d', str(payload)])
    bodies = {}
    name = None
    for line in dis.splitlines():
        label = re.match(r'^([0-9a-f]+) <([^>]+)>:$', line)
        if label:
            name = label[2]
            bodies[name] = []
        elif name:
            bodies[name].append(line)

    def body(name):
        require(name in bodies, 'missing disassembly body '+name)
        return '\n'.join(bodies[name])

    wrapper = body('stage90_guarded_read32')
    require('<stage90_guarded_read32_cpsr_read>' in wrapper and
            '<stage90_guarded_read32_load_arm>' in wrapper and
            wrapper.index('<stage90_guarded_read32_cpsr_read>') <
            wrapper.index('<stage90_guarded_read32_load_arm>'),
            'post-mask CPSR must be read before the target load')
    handler = body('stage90_data_abort_c_handler')
    require('<stage90_guarded_read32_abort_policy>' in handler and
            '<stage90_guarded_read32_park>' in handler,
            'actual abort handler lacks policy or fail-stop path')
    handler_start, handler_size = symbols['stage90_data_abort_c_handler']
    words = struct.unpack('<'+'I'*(handler_size//4), at(handler_start, handler_size, True))
    branches = [(i, word) for i, word in enumerate(words)
                if word >> 28 != 14 and (word & 0x0e000000) == 0x0a000000]
    require(bool(branches), 'abort handler lacks active-state conditional branch')
    branch_index, branch_word = branches[0]
    require(branch_word >> 28 == 1 and words[branch_index-1] == 0xe3530000,
            'abort guard must branch on nonzero active-state r3 before legacy code')
    state_address = symbols['stage90_guarded_read32_state'][0]
    def mov_imm(base, value):
        return base | ((value & 0xf000) << 4) | (value & 0xfff)
    prefix = words[:branch_index]
    require(mov_imm(0xe300c000, state_address & 0xffff) in prefix and
            mov_imm(0xe340c000, state_address >> 16) in prefix and
            0xe59c3000 in prefix and not any((w & 0x0f000000) == 0x0b000000 for w in prefix),
            'active-state branch does not read the actual guard before any call')
    offset = branch_word & 0xffffff
    if offset & 0x800000:
        offset -= 1 << 24
    target = handler_start + branch_index*4 + 8 + offset*4
    require(handler_start <= target < handler_start+handler_size,
            'active guard branch leaves handler unexpectedly')
    cursor = target
    reached_policy = False
    for _ in range(16):
        word = struct.unpack('<I', at(cursor, 4, True))[0]
        if (word & 0x0f000000) == 0x0b000000:
            displacement = word & 0xffffff
            if displacement & 0x800000:
                displacement -= 1 << 24
            callee = cursor + 8 + displacement*4
            reached_policy = word >> 28 == 14 and callee == symbols['stage90_guarded_read32_abort_policy'][0]
            break
        require((word & 0x0e000000) != 0x0a000000 and
                (word & 0x0ffffff0) != 0x012fff10,
                'unexpected control transfer before guarded abort policy')
        cursor += 4
    require(reached_policy, 'active guard path must call policy before any legacy call')
    kernel = body('kernel_entry')
    require(len(re.findall(r'\bbl\b[^\n]*<stage90_dwc3_readonly_probe>', kernel)) == 1,
            'kernel_entry must directly call probe exactly once')
    require('<usb_preboot_run>' not in kernel and '<usb_preboot_readonly_probe>' not in kernel,
            'legacy CI preboot call remains in actual kernel entry')
    probe = body('stage90_dwc3_readonly_probe')
    require('<stage90_guarded_read32>' in probe and '<mi4_dwc3_identify>' in probe,
            'probe lacks guarded reader or actual identity core')
    require(probe.index('<stage90_guarded_read32>') < probe.index('<mi4_dwc3_identify>'),
            'identity core precedes guarded-load selftest')
    for marker in (b'dwc3_ro guard selftest passed: RAM and translation-fault recovery',
                   b'dwc3_ro skipped: guard translation-fault selftest failed',
                   b'mmu legacy CI USB probe skipped; primary port is DWC3',
                   b'dwc3_ro finished; identification is not a USB link'):
        require(marker in data, 'missing linked diagnostic '+repr(marker))

    entry_data = entry.read_bytes()
    entry_at = elf_reader(entry_data)
    entry_nm = command(['arm-none-eabi-nm', '-S', '--defined-only', str(entry)])
    for name in ('entry_usb_probe', 'entry_usb_dev_init',
                 'entry_usb_enum_poll', 'entry_usb_stream_poll'):
        match = re.search(r'^([0-9a-f]+) ([0-9a-f]+) \w '+name+r'$', entry_nm, re.M)
        require(match is not None, 'missing disabled entry USB function '+name)
        require(int(match[2], 16) == 4 and
                entry_at(int(match[1], 16), 4, True) == struct.pack('<I', 0xe12fff1e),
                'entry USB function is not a bare return: '+name)
    print('PASS:', checks, 'actual linked probe/config/opcode/CI-disabled checks')
    print('LIMIT: static acceptance only; no ARM exception, MMIO completion, or USB proof')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--payload', type=Path, required=True)
    parser.add_argument('--entry', type=Path, required=True)
    parser.add_argument('--config', type=Path, required=True)
    args = parser.parse_args()
    inspect(args.payload, args.entry, args.config)


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        raise SystemExit('FAIL: '+str(error))
