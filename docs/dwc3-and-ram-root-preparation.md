# DWC3 preparation and private RAM-root staging

These modules support the ongoing genuine iOS 7 port. **They do not implement a
working phone USB gadget or resolve the real launchd library dependency.** The
current hardware-proven blocker is `/usr/lib/libbsm.0.dylib: image not found`.
No Apple executable, private device log, assigned hardware identity or vendor
function implementation is included in these original modules.

## Event decoding: `src/dwc3_events.{c,h}`

Portable little-endian event decoding and bounded four-byte ring consumption.
Validates cursor, size and byte count before reading entries or calling the
consumer. Returns proposed consumed **bytes**, not event counts; performs no
allocation, MMIO, DMA, cache maintenance or hardware acknowledgement. Unknown
entries are diagnostic. Device event 11 reports overflow without claiming
recovery. The special test-LMP record stops consumption before its header because
its extra eight payload bytes are not implemented.

The callback owns side effects; a paused entry remains pending. A real adapter
must separately serialize ownership, establish DMA coherency, acknowledge the
returned byte count and implement reset/recovery. Tests compare 22 numerical
supplier definitions and four field layouts, compile the actual implementation,
and exercise wrap, budgets, invalid input and framing. GCC and Clang native tests
and sanitizer runs passed; this is not USB connection evidence.

```sh
# Tests create a fresh test-run-* directory beneath the supplied source snapshot.
python3 tools/test_dwc3_events.py --repo-root /ABS/PRIVATE/source-snapshot \
  --vendor-core /ABS/vendor/drivers/usb/dwc3/core.h --sanitize
```

On macOS, `gcc` may be an alias for Clang; the test refuses to call that GNU GCC.
A real cross-GCC can be used with `--gcc-compile-only`; that result explicitly
reports compilation only, not native execution.

## EP0 planning: `src/dwc3_ep0.{c,h}`

Pure C11 request validation, bounded descriptor responses, data/status direction
and transaction state. It requires a bus reset before requests, cancels old work
on new SETUP/reset, rejects stale completions, and only publishes address/config
intent after a successful matching status completion. DATA queuing is not
completion. The no-data direction and terminating-ZLP rules are explicit.

This is a narrow one-configuration/interface-0/alt-0/bulk-IN profile. Unsupported
requests and bulk-halt operations STALL. The optional synthetic `1234:0001`
fixture is **not an assigned or proposed hardware identity** and must not be used
on hardware as-is. Caller descriptor storage must remain accessible and immutable.

**No actual DWC3 event/TRB/endpoint adapter exists here.** For non-address changes,
a future adapter must prepare reversible hardware resources before offering
STATUS, then publish software intent after completion and roll back on failure.
It must also implement real setup-pending/transfer-not-ready events, endpoint
commands, ownership, halts and timing. The planner alone is not enumeration.

```sh
# Linux native execution; on macOS use an explicitly selected Linux build host.
python3 tools/test_dwc3_ep0.py
python3 tools/test_dwc3_ep0.py --ssh YOUR_LINUX_HOST
```

The test compiles the actual C with strict GCC/Clang and sanitizers, uses synthetic
fixtures, and checks three deliberately broken source variants. Its Linux runner
uses anonymous memory files. No phone or controller is accessed.

## Private directory staging: `tools/stage_ram_root.py`

A stdlib-only host-directory validator/stager, **not an HFS formatter or image
builder**. A private JSON manifest pins each input's size and SHA-256 and declares
canonical guest paths, safe modes, explicit directories and confined symlinks.
Only new output directories are accepted. Input paths are opened without following
symlinks; copied bytes and destination readback are hashed. Failed partial outputs
are diagnosed and retained, never deleted or silently reused.

The minimum requires ARM32 little-endian launchd/dyld headers, a launchd dylinker
path of `/usr/lib/dyld`, and an empty `/dev` directory. These checks do **not** prove
Apple authenticity, library closure, runnable code, valid code signatures, HFS
allocation or a fit within the owned 64 MiB window. The optional volume budget has
a 32 MiB ceiling; that ceiling is not evidence that a 32 MiB root can boot.
Guest ownership, ACLs, xattrs and HFS case folding are not modeled. Sources are
never executed; ordinary host reads may update filesystem access times.

```sh
python3 tools/stage_ram_root.py /ABS/PRIVATE/root.json \
  --output-staging /ABS/EXISTING/PRIVATE/PARENT/NEW-root \
  --require-files /usr/lib/libbsm.0.dylib
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover \
  -s tools -p test_stage_ram_root.py -v
```

Only launchd/dyld plus directories is not a complete runnable root. Explicitly
requiring missing libbsm rejects that incomplete tree; the tool never invents a
replacement library. Actual manifests, inputs and reports with private labels
must remain private. Success reports contain guest content metadata, not host
input paths, and are not placed inside the guest.

## Guarded identity preparation

`src/dwc3_identify.{c,h}` reads through a supplied error-return callback. It
requires all five branch clocks explicitly enabled and CBCR[31:28] exactly 0 or 2,
reset deasserted, and a running/stable root clock before checking GSNPSID. Failed
reads never gain valid bits. A callback is a trust boundary, not a raw volatile
load that can claim success after an exception.

`src/stage90_guarded_read32.{c,h}` and `_arm.S` provide a narrowly scoped pre-XNU
ARM/SVC/little-endian guarded load. The original vector's exact fault PC and DFAR
must match the dedicated single 32-bit LDR; only documented synchronous read
fault classes are recoverable. Before arming any target load, the wrapper reads
back actual CPSR after requesting IRQ/FIQ masking; if the required state did not
take effect, it restores the original masks and returns a nonzero status without
reading the target or changing the output. The failure label returns nonzero
without storing an output. Unsupported active faults retain a RAM breadcrumb and park rather than
fall through to the existing generic instruction-skip handler. This is not an
SMP, Thumb, XNU, arbitrary-pointer or universal crash-recovery API.

`STAGE90_GUARDED_IRQ_ONLY=1` is a separately reviewed, default-OFF profile for the
measured environment where F cannot be set. It requests/restores only I, requires
actual post-I=1 and unchanged per-call F/A and ARM/SVC/LE context, and compares
fault SPSR M/T/E/J/I/F with the immutable post-mask snapshot. Exact PC/DFAR and
supported read-fault requirements remain. It also requires a linked FIQ hook:
ANY nonzero active branches using banked r8/r9 to a RAM-only, nonreturning park
before the old logger. Output may already be written if FIQ arrives after commit;
no API success returns from that park. Neither secure routing nor bus completion
is proved. Default-OFF instruction sections were checked against the strict baseline.

`STAGE90_DWC3_TARGET_READS` now defaults to **0**. A recovery-only profile completes
normal RAM and intentional translation-fault selftests, logs exact fault context,
then returns before live watchdog/controller target reads. The real-image checker
requires exactly those two guarded call sites and no identity-core call. Its
explicit `--irq-only --recovery-only` contract is distinct from identification.
Hardware recovery evidence is required before a separate TARGET_READS=1 profile;
there is no automatic fallback or enablement.

The opt-in `src/dwc3_probe.c` checks the original vectors, actual identity table,
MMU/cache/TEX-remapping state, strongly-ordered mappings and existing recovery
nets. It first checks a real RAM read and a confirmed unmapped-section translation
fault, then guarded live watchdog reads and exactly 15 whitelisted clock/reset/
core reads. A failed prerequisite stops the probe; it does not turn on clocks or
reset/configure the controller. Host tests exercise the actual C with explicitly
mocked CPU/guarded-load seams, not hardware exceptions.

```sh
python3 tools/test_guarded_read32.py --cc gcc
python3 tools/test_guarded_read32.py --cc clang --sanitize
python3 tools/test_dwc3_identify.py --cc gcc
python3 tools/test_dwc3_probe.py --cc clang --sanitize
python3 tools/test_dwc3_readonly_checker.py
python3 tools/test_dwc3_capture.py
```

The separate verified-build profile keeps old CI USB and all medium-write gates
OFF, pins inputs/outputs and requires actual linked opcode/configuration checks.
The checker tests use synthetic ELF bytes; the capture tests use synthetic logs.
They are not evidence that an unbuilt profile is usable. Real logs remain private.

## Offline TRB preparation

`src/dwc3_trb.{c,h}` is an original DMA32-profile byte codec, not a queue or DMA
adapter. It validates widened length/type/flags, checked caller-declared bus spans,
SETUP=8 and STATUS=0, and permits legitimate zero packets and address zero. Its
16-byte LE prepared image always has HWO=0; unsupported CHN/PCM1/iso/link fields
are rejected. The caller still proves ownership, translation, TRB alignment,
coherency and lifetime. Decoding preserves all 16 status nibbles and does not
interpret HWO-clear or OK as USB completion.

Strict Clang and GNU GCC plus ASan/UBSan each passed 1,505,925 checks with 100,000
randomized TRBs. Six independently compiled unsafe mutants were rejected; 20
supplier numerical contracts, the four-word layout and 11 local assertions were
checked. The parent also compiled the codec with ARM GCC. Frozen inputs are used
for compilation and mutants and rechecked afterward, including failure paths.
None of this publishes DMA or proves a hardware transfer.

```sh
python3 tools/test_dwc3_trb.py --cc clang --sanitize
python3 tools/test_dwc3_trb.py --cc gcc --sanitize
```

## Root-clock snapshots and RAM-store prerequisite

The seven-word GCC snapshot and distinct thirteen-word root snapshot have each
completed one bounded RAM boot and recovered Android. Five USB branches were OFF;
BCR/CMD were zero. The extra CFG/M/N/D were all zero, GPLL0 status was `0x00036005`
and APPS vote `0x11`. This establishes missing master-root configuration, not
frequency, voltage, ownership, DWC3 identity or USB transport. The thirteen-word
mode adds exactly six unique GCC reads and never calls vendor clock functions.

`STAGE90_GUARDED_STORE32` defaults OFF. When explicitly enabled with the IRQ-only
profile, it shares the read guard's active/FIQ fail-stop state and adds a single
aligned ARM STR with exact operation-specific fault/recovery labels. Accepted
write faults return **8, indeterminate**: no retry, rollback or unchanged-target
claim. Only eight nonexternal precise fault classes are accepted for writes;
external classes remain unsupported even with raw WnR set. Read policy is unchanged.

The separate `STAGE90_GUARDED_STORE_SELFTEST=1` profile requires target reads and
both snapshots OFF. It first verifies the existing read/fault guard and cached
watchdog headroom, then writes one exclusively owned ordinary-RAM word, reads it
back, and attempts one store to a confirmed-unmapped section. No target MMIO write,
controller read, word restoration or automatic retry is included. Native host,
sanitizer and linked-byte checks are prerequisites, not real exception evidence.

```sh
python3 tools/test_guarded_store32.py --cc clang --sanitize
python3 tools/test_dwc3_readonly_checker.py
python3 tools/test_dwc3_store_capture.py
# Private recovered console only; emits a sanitized RAM-only report:
python3 tools/check_dwc3_store_capture.py /ABS/PRIVATE/recovered-console
```

The canonical full-build profile is
`tools/build_profile_d13_guard_store_selftest.json` (five stages, 31 acceptance
commands). A passing real RAM-store test is still not permission or proof for
clock writes; root configuration, supplies, quiescence and the hardware adapter
remain separate obligations. See the milestone record for actual build/boot state.

## Hardware boundary

The EP0 planner commits **software** address/configuration after matching STATUS
completion. This is not a hardware DCFG.DEVADDR timing rule. The existing platform
source handles the DCFG address field during SET_ADDRESS, before status scheduling
(`external/android_kernel_xiaomi_cancro/drivers/usb/dwc3/ep0.c:501–527`). A future
original adapter must distinguish controller-address staging from software commit
and reconcile cancelled requests/reset; the source alone does not prove silicon
internal latch timing. Non-address hardware preparation must be reversible and
complete before offering STATUS.

The actual recovered phone gadget is DWC3, not the separately implemented legacy
CI controller. Changing a CI base address cannot port its QH/dTD driver to DWC3.
The guarded identity probe is separate from the offline event/EP0 modules and
still does not initialize a USB link. Neither volatile loads, software deadlines,
clock flags nor exception fixups can guarantee completion of a stalled MMIO bus.
The watchdog recovery path also depends on the SoC/secure world surviving the
fault. Identification, when proven on hardware, is not a transport or iOS startup.
