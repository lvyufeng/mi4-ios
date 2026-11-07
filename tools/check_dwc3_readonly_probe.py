#!/usr/bin/env python3
"""Inspect the actual linked opt-in probe; no device access or image execution.

This is static acceptance, not proof of exception delivery, MMIO completion or USB.
Store call counts cover only the probe and directly called source-known helpers;
per-call RAM/unmapped address intent and state/policy predicates need source review
and host tests. This is not universal CFG/dataflow or a no-hardware-writes proof.
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


def inspect(payload, entry, config, irq_only=False, recovery_only=False,
            clock_snapshot=False, root_snapshot=False, store_selftest=False):
    checks = 0

    def require(test, message):
        nonlocal checks
        checks += 1
        if not test:
            raise ValueError(message)

    require(sum((recovery_only, clock_snapshot, root_snapshot, store_selftest)) <= 1,
            'snapshot, recovery-only and store-selftest modes are mutually exclusive')
    require(not store_selftest or irq_only, 'store-selftest requires --irq-only')
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

    for name in ('GUARDED_STORE32', 'GUARDED_STORE_SELFTEST'):
        raw = defines.get('STAGE90_'+name, '' if store_selftest else '0')
        literal = re.fullmatch(r'(0[xX][0-9a-fA-F]+|0|[1-9][0-9]*)(?:[uU](?:[lL]{1,2})?|[lL]{1,2}[uU]?)?', raw)
        require(literal is not None and int(literal[1], 0) == int(store_selftest),
                'actual payload configuration differs or is unexpanded: '+name)

    raw_root = defines.get('STAGE90_DWC3_ROOT_SNAPSHOT', '' if root_snapshot else '0')
    root_literal = re.fullmatch(r'(0[xX][0-9a-fA-F]+|0|[1-9][0-9]*)(?:[uU](?:[lL]{1,2})?|[lL]{1,2}[uU]?)?', raw_root)
    require(root_literal is not None and int(root_literal[1], 0) == int(root_snapshot),
            'actual payload configuration differs or is unexpanded: DWC3_ROOT_SNAPSHOT')

    want_clock = clock_snapshot or root_snapshot
    raw_snapshot = defines.get('STAGE90_DWC3_CLOCK_SNAPSHOT', '' if want_clock else '0')
    snapshot_literal = re.fullmatch(r'(0[xX][0-9a-fA-F]+|0|[1-9][0-9]*)(?:[uU](?:[lL]{1,2})?|[lL]{1,2}[uU]?)?', raw_snapshot)
    require(snapshot_literal is not None and int(snapshot_literal[1], 0) == int(want_clock),
            'actual payload configuration differs or is unexpanded: DWC3_CLOCK_SNAPSHOT')

    raw_target = defines.get('STAGE90_DWC3_TARGET_READS',
                             '' if irq_only or recovery_only or want_clock or store_selftest else '1')
    target_literal = re.fullmatch(r'(0[xX][0-9a-fA-F]+|0|[1-9][0-9]*)(?:[uU](?:[lL]{1,2})?|[lL]{1,2}[uU]?)?', raw_target)
    require(target_literal is not None and int(target_literal[1], 0) == int(not (recovery_only or store_selftest)),
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
    symbol_types = {}
    for line in nm.splitlines():
        m = re.fullmatch(r'([0-9a-fA-F]+) ([0-9a-fA-F]+) (\w) (\S+)', line)
        if m:
            symbol_types[m[4]] = m[3]
    if store_selftest:
        state = symbols.get('stage90_guarded_read32_state')
        require(state is not None and state[1] == 56 and
                symbol_types.get('stage90_guarded_read32_state') in ('b', 'B'),
                'actual guard state B-symbol size differs')
    if irq_only:
        inspect_irq_only(at, symbols, require)
    for name in ('stage90_guarded_read32', 'stage90_guarded_read32_abort_policy',
                 'stage90_guarded_read32_load_arm', 'stage90_guarded_read32_fault',
                 'stage90_guarded_read32_recovery', 'stage90_guarded_read32_park',
                 'stage90_data_abort_c_handler', 'stage90_dwc3_readonly_probe',
                 'mi4_dwc3_identify', 'kernel_entry'):
        require(name in symbols and symbols[name][1] > 0, 'missing linked symbol '+name)
    if want_clock:
        snapshot_kind = 'root' if root_snapshot else 'clock'
        snapshot_name = 'mi4_dwc3_'+snapshot_kind+'_snapshot'
        snapshot = symbols.get(snapshot_name)
        require(snapshot is not None and snapshot[1] > 0,
                'missing linked symbol '+snapshot_name)
        at(snapshot[0], snapshot[1], True)
        addresses = symbols.get(snapshot_kind+'_snapshot_addresses')
        expected_clocks = (0xfc400108, 0xfc4003c8, 0xfc4003d0, 0xfc4003cc,
                           0xfc4004ac, 0xfc4003c0, 0xfc4003d4)
        if root_snapshot:
            expected_clocks += (0xfc4003d8, 0xfc4003dc, 0xfc4003e0,
                                0xfc4003e4, 0xfc40001c, 0xfc401480)
        size = len(expected_clocks)*4
        # Linked data contract only; module/callback tests establish read semantics.
        require(addresses is not None and addresses[1] == size and
                at(addresses[0], size) == struct.pack('<'+'I'*len(expected_clocks), *expected_clocks),
                snapshot_kind+' snapshot GCC address array opcodes/data/size differ')
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

    if store_selftest:
        for name in ('stage90_guarded_write32', 'stage90_guarded_write32_store_arm',
                     'stage90_guarded_write32_fault', 'stage90_guarded_write32_recovery'):
            require(name in symbols and symbols[name][1] > 0, 'missing linked symbol '+name)
        store, store_size = symbols['stage90_guarded_write32_store_arm']
        require(store_size == 36 and
                symbols['stage90_guarded_write32_fault'] == (store+8, 4) and
                symbols['stage90_guarded_write32_recovery'] == (store+28, 8),
                'guarded store instruction/fixup label layout differs')
        expected_store = (0xf57ff04f, 0xf57ff06f, 0xe5801000, 0xf57ff04f,
                          0xf57ff06f, 0xe3a00000, 0xe12fff1e, 0xe3a00008, 0xe12fff1e)
        require(at(store, 36, True) == struct.pack('<9I', *expected_store),
                'actual guarded-store opcodes differ')
        # Exact source-shaped leaf: the sole target STR is r1 -> [r0].
        # Wrapper state/operation predicates and WnR/FS policy need host C tests;
        # these bytes and direct calls are not a general dataflow/CFG proof.
        address, size = symbols['stage90_guarded_write32']
        require(size % 4 == 0, 'guarded store wrapper size is not ARM aligned')
        wrapper_words = struct.unpack('<'+'I'*(size//4), at(address, size, True))
        calls = []
        for index, instruction in enumerate(wrapper_words):
            if instruction & 0xff000000 == 0xeb000000:
                offset = instruction & 0xffffff
                if offset & 0x800000:
                    offset -= 1 << 24
                calls.append(address+index*4+8+offset*4)
        cpsr = symbols['stage90_guarded_read32_cpsr_read'][0]
        require(calls.count(cpsr) == 1 and calls.count(store) == 1 and
                calls.index(cpsr) < calls.index(store),
                'actual store wrapper must read post-mask CPSR before its sole STR leaf call')

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
    if not store_selftest:
        require('<stage90_guarded_write32>' not in probe and
                '<dwc3_probe_store_selftest>' not in probe,
                'non-store probe retains guarded store calls')
    if store_selftest:
        # Only these two source-known helpers may be outlined. Expand exactly
        # one direct probe BL each, never arbitrary transitive reachability.
        selected = probe
        for helper in ('dwc3_probe_guard_selftest', 'dwc3_probe_store_selftest'):
            if helper in bodies:
                reference = r'\bbl\b[^\n]*<'+helper+r'>'
                require(len(re.findall(reference, probe)) == 1 and
                        helper in symbols and symbols[helper][1] > 0,
                        'outlined selftest helper must be sized and directly called exactly once: '+helper)
                helper_body = body(helper)
                require(not any('<'+name+'>' in helper_body for name in
                                ('dwc3_probe_guard_selftest', 'dwc3_probe_store_selftest')),
                        'selftest helpers may not call each other or recurse')
                selected = re.sub(reference, lambda _: helper_body, selected)
        require(not any('<'+name in selected for name in
                        ('mi4_dwc3_identify', 'mi4_dwc3_clock_snapshot',
                         'mi4_dwc3_root_snapshot', 'dwc3_probe_read',
                         'usb_preboot_', 'entry_usb_')),
                'store-selftest probe/helpers retain controller/core/stream callback references')
        guard_calls = re.findall(r'\bbl\b[^\n]*<(stage90_guarded_(?:read|write)32)>', selected)
        require(guard_calls.count('stage90_guarded_read32') == 4 and
                guard_calls.count('stage90_guarded_write32') == 2,
                'store-selftest must directly call guarded reader exactly four times and writer exactly twice')
        require(guard_calls == ['stage90_guarded_read32']*3 +
                ['stage90_guarded_write32', 'stage90_guarded_read32', 'stage90_guarded_write32'],
                'store-selftest calls must follow read/fault selftest, RAM read/write/read, unmapped write order')
    if not root_snapshot:
        require('<mi4_dwc3_root_snapshot>' not in probe,
                'non-root probe retains root-snapshot core call')
    if store_selftest:
        pass  # The bounded combined probe/helper call contract was checked above.
    elif recovery_only:
        require('<mi4_dwc3_identify>' not in probe and '<mi4_dwc3_clock_snapshot>' not in probe and
                '<dwc3_probe_read>' not in probe,
                'recovery-only probe retains controller/core calls')
        require(len(re.findall(r'\bbl\b[^\n]*<stage90_guarded_read32>', probe)) == 2,
                'recovery-only probe must directly call guarded reader exactly twice')
    elif root_snapshot:
        require('<mi4_dwc3_identify>' not in probe and '<mi4_dwc3_clock_snapshot>' not in probe,
                'root-snapshot probe retains identity or clock core call')
        require(len(re.findall(r'\bbl\b[^\n]*<mi4_dwc3_root_snapshot>', probe)) == 1 and
                '<stage90_guarded_read32>' in probe,
                'root-snapshot probe must call root core exactly once after guard selftest')
        require(probe.index('<stage90_guarded_read32>') < probe.index('<mi4_dwc3_root_snapshot>'),
                'root snapshot core precedes guarded-load selftest')
    elif clock_snapshot:
        require('<mi4_dwc3_identify>' not in probe,
                'clock-snapshot probe retains identity core call')
        require(len(re.findall(r'\bbl\b[^\n]*<mi4_dwc3_clock_snapshot>', probe)) == 1 and
                '<stage90_guarded_read32>' in probe,
                'clock-snapshot probe must call snapshot core exactly once after guard selftest')
        require(probe.index('<stage90_guarded_read32>') < probe.index('<mi4_dwc3_clock_snapshot>'),
                'clock snapshot core precedes guarded-load selftest')
    else:
        require('<mi4_dwc3_clock_snapshot>' not in probe,
                'identity probe retains clock-snapshot core call')
        require('<stage90_guarded_read32>' in probe and '<mi4_dwc3_identify>' in probe,
                'probe lacks guarded reader or actual identity core')
        require(probe.index('<stage90_guarded_read32>') < probe.index('<mi4_dwc3_identify>'),
                'identity core precedes guarded-load selftest')
    finish = (b'dwc3_ro store selftest passed; RAM writes only; controller target reads inhibited' if store_selftest else
              inhibited if recovery_only else
              b'dwc3_ro finished; GCC root snapshot only; no DWC3 core reads' if root_snapshot else
              b'dwc3_ro finished; GCC clock snapshot only; no DWC3 core reads' if clock_snapshot else
              b'dwc3_ro finished; identification is not a USB link')
    if store_selftest:
        require(b'DWC3 guarded RAM store selftest; no MMIO target writes' in data,
                'missing linked diagnostic for guarded RAM store selftest start')
    for marker in (b'dwc3_ro guard selftest passed: RAM and translation-fault recovery',
                   b'dwc3_ro skipped: guard translation-fault selftest failed',
                   b'mmu legacy CI USB probe skipped; primary port is DWC3', finish):
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
    if store_selftest:
        print('LIMIT: source-known direct-call contract only; per-call address/state policy needs source review and host tests; no universal CFG or no-hardware-writes proof')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--payload', type=Path, required=True)
    parser.add_argument('--entry', type=Path, required=True)
    parser.add_argument('--config', type=Path, required=True)
    parser.add_argument('--irq-only', action='store_true',
                        help='require IRQ-only helpers and linked FIQ fail-stop vector contract')
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument('--recovery-only', action='store_true',
                      help='require controller target reads inhibited after guard selftests')
    mode.add_argument('--clock-snapshot', action='store_true',
                      help='require seven-GCC-clock snapshot mode, not DWC3 core identification')
    mode.add_argument('--root-snapshot', action='store_true',
                      help='require thirteen-GCC-root snapshot mode, not DWC3 core identification')
    mode.add_argument('--store-selftest', action='store_true',
                      help='require IRQ-only RAM/unmapped guarded-store selftests; target reads inhibited')
    args = parser.parse_args()
    if args.store_selftest and not args.irq_only:
        parser.error('--store-selftest requires --irq-only')
    inspect(args.payload, args.entry, args.config, irq_only=args.irq_only,
            recovery_only=args.recovery_only, clock_snapshot=args.clock_snapshot,
            root_snapshot=args.root_snapshot, store_selftest=args.store_selftest)


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        raise SystemExit('FAIL: '+str(error))
