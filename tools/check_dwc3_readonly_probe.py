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


def inspect_irq_only(at, symbols, require):
    """Source-shaped linked-byte contract, not runtime VBAR/delivery or general CFG proof."""
    def word(address, executable=True):
        return struct.unpack('<I', at(address, 4, executable))[0]

    def branch_target(address, instruction, opcode, message):
        require(instruction & 0xff000000 == opcode, message)
        offset = instruction & 0xffffff
        if offset & 0x800000:
            offset -= 1 << 24
        return address + 8 + offset*4

    def literal(address, instruction, register):
        require(instruction & 0xff7ff000 == (0xe51f0000 | register << 12),
                'FIQ prefix must use an unconditional PC-relative word LDR')
        offset = instruction & 0xfff
        pointer = address + 8 + (offset if instruction & 0x800000 else -offset)
        require(pointer % 4 == 0, 'unaligned FIQ literal')
        return word(pointer, False)  # Literal may be in a non-executable LOAD.

    for name in ('stage90_vectors', 'stage90_guarded_fiq_hook_contract',
                 'stage90_guarded_fiq_park', 'stage90_guarded_read32_state',
                 'stage90_guarded_read32_irq_save', 'stage90_guarded_read32_irq_restore',
                 'stage90_exception_common', 'platform_reboot'):
        require(name in symbols, 'missing IRQ-only linked symbol '+name)
    vectors, vector_size = symbols['stage90_vectors']
    hook = symbols['stage90_guarded_fiq_hook_contract'][0]  # May have no nm size.
    park, park_size = symbols['stage90_guarded_fiq_park']
    require(vector_size == 32 and vectors % 32 == 0, 'IRQ-only vector table layout differs')
    require(branch_target(vectors+28, word(vectors+28), 0xea000000,
                          'FIQ vector must be unconditional B, not BL') == hook,
            'FIQ vector does not target the exact guarded hook entry')
    prefix = struct.unpack('<6I', at(hook, 24, True))
    require(literal(hook, prefix[0], 8) == symbols['stage90_guarded_read32_state'][0],
            'FIQ literal does not address the actual guard state')
    require(prefix[1:3] == (0xe5989000, 0xe3590000),
            'FIQ prefix must load active into banked r9 and compare zero')
    require(branch_target(hook+12, prefix[3], 0x1a000000,
                          'FIQ active branch must be BNE, not a call') == park,
            'FIQ active branch does not target the exact fail-stop park')
    common, common_size = symbols['stage90_exception_common']
    require(at(literal(hook+16, prefix[4], 0), 4) == b'fiq\0',
            'inactive FIQ message differs')
    require(branch_target(hook+20, prefix[5], 0xea000000,
                          'inactive FIQ must branch unconditionally to fatal common') == common,
            'inactive FIQ branch misses fatal common')
    expected_park = (0xe3a09007, 0xe5889018, 0xe3049651, 0xe3449752,
                     0xe5889028, 0xe320f002, 0xeafffffd)
    require(park_size == 28 and at(park, 28, True) == struct.pack('<7I', *expected_park),
            'FIQ fail-stop park opcodes/size differ')
    save = (0xe10f0000, 0xe200101f, 0xe3510013, 0x112fff1e,
            0xe3100020, 0x112fff1e, 0xe3100c02, 0x112fff1e,
            0xe3100401, 0x112fff1e, 0xf10c0080, 0xf57ff06f, 0xe12fff1e)
    restore = (0xe10f1000, 0xe3c11080, 0xe2000080, 0xe1811000,
               0xe121f001, 0xf57ff06f, 0xe12fff1e)
    for name, expected in (('irq_save', save), ('irq_restore', restore)):
        address, size = symbols['stage90_guarded_read32_'+name]
        require(size == len(expected)*4 and at(address, size, True) ==
                struct.pack('<'+'I'*len(expected), *expected),
                'IRQ-only '+name+' opcodes/size differ')
    # The unchanged fatal assembly is straight-line moves/literals/direct calls,
    # ending in reboot plus a park. Do not infer arbitrary C callee behavior.
    require(common_size >= 16 and common_size % 4 == 0, 'fatal common size differs')
    fatal = struct.unpack('<'+'I'*(common_size//4), at(common, common_size, True))
    require(fatal[0] == 0xf10c00c0 and fatal[-2:] == (0xe320f002, 0xeafffffd) and
            branch_target(common+common_size-12, fatal[-3], 0xeb000000,
                          'fatal common must directly call reboot before park') ==
            symbols['platform_reboot'][0], 'fatal common reboot/park tail differs')
    require(all(w in (0xe1a04000, 0xe1a0500e, 0xe14f6000,
                      0xe1a00004, 0xe1a00005, 0xe1a00006) or
                w & 0xff7ff000 == 0xe51f0000 or w & 0xff000000 == 0xeb000000
                for w in fatal[1:-3]),
            'fatal common contains an unexpected instruction/control transfer')


def inspect(payload, entry, config, irq_only=False, recovery_only=False):
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

    raw_irq = defines.get('STAGE90_GUARDED_IRQ_ONLY', '' if irq_only else '0')
    irq_literal = re.fullmatch(r'(0[xX][0-9a-fA-F]+|0|[1-9][0-9]*)(?:[uU](?:[lL]{1,2})?|[lL]{1,2}[uU]?)?', raw_irq)
    require(irq_literal is not None and int(irq_literal[1], 0) == int(irq_only),
            'actual payload configuration differs or is unexpanded: GUARDED_IRQ_ONLY')

    raw_target = defines.get('STAGE90_DWC3_TARGET_READS',
                             '' if irq_only or recovery_only else '1')
    target_literal = re.fullmatch(r'(0[xX][0-9a-fA-F]+|0|[1-9][0-9]*)(?:[uU](?:[lL]{1,2})?|[lL]{1,2}[uU]?)?', raw_target)
    require(target_literal is not None and int(target_literal[1], 0) == int(not recovery_only),
            'actual payload configuration differs or is unexpanded: DWC3_TARGET_READS')

    data = payload.read_bytes()
    at = elf_reader(data)
    nm = command(['arm-none-eabi-nm', '-S', '--defined-only', str(payload)])
    symbols = {}
    for line in nm.splitlines():
        m = re.fullmatch(r'([0-9a-fA-F]+) ([0-9a-fA-F]+) (\w) (\S+)', line)
        if m:
            symbols[m[4]] = (int(m[1], 16), int(m[2], 16))
        else:
            m = re.fullmatch(r'([0-9a-fA-F]+) (\w) (\S+)', line)
            if m:
                symbols[m[3]] = (int(m[1], 16), 0)
    if irq_only:
        inspect_irq_only(at, symbols, require)
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
    inhibited = b'dwc3_ro recovery verified; controller target reads inhibited'
    if recovery_only:
        require('<mi4_dwc3_identify>' not in probe and '<dwc3_probe_read>' not in probe,
                'recovery-only probe retains controller/core calls')
        require(len(re.findall(r'\bbl\b[^\n]*<stage90_guarded_read32>', probe)) == 2,
                'recovery-only probe must directly call guarded reader exactly twice')
    else:
        require('<stage90_guarded_read32>' in probe and '<mi4_dwc3_identify>' in probe,
                'probe lacks guarded reader or actual identity core')
        require(probe.index('<stage90_guarded_read32>') < probe.index('<mi4_dwc3_identify>'),
                'identity core precedes guarded-load selftest')
    for marker in (b'dwc3_ro guard selftest passed: RAM and translation-fault recovery',
                   b'dwc3_ro skipped: guard translation-fault selftest failed',
                   b'mmu legacy CI USB probe skipped; primary port is DWC3',
                   inhibited if recovery_only else
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
    parser.add_argument('--irq-only', action='store_true',
                        help='require IRQ-only helpers and linked FIQ fail-stop vector contract')
    parser.add_argument('--recovery-only', action='store_true',
                        help='require controller target reads inhibited after guard selftests')
    args = parser.parse_args()
    inspect(args.payload, args.entry, args.config, irq_only=args.irq_only,
            recovery_only=args.recovery_only)


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        raise SystemExit('FAIL: '+str(error))
