# Mi 4 / Darwin 13 milestone — 2026-11-07

## Final objective and current scope

The final target remains genuine, complete and stable iOS 7 operation on the Xiaomi
Mi 4 LTE (`cancro`, MSM8974). Core services, interactive SpringBoard/apps, hardware
support and power management require repeatable hardware evidence. Entering XNU
or dyld is not completion, and neither a theme nor emulation meets this target.

The near-term priorities are evidence-driven:

1. Unblock the genuine dyld/launchd startup path.
2. Establish reliable host-visible USB data and then kernel debugging.
3. Progress to core services, graphics, interaction and hardware/power validation.

Safety remains **`fastboot boot` only**: no flashing, no experimental data written
to `misc` or other physical partitions, and all experimental medium-write gates
remain OFF. Ordinary Android shutdown synchronization is not an experimental log
or partition-writing workaround.

## Completed hardware observation

A full kernel build produced a hash-locked RAM-boot image:

`d301887d62d1f520cb99bd27cf89e03f5933cf2e0734b7328ea4f9e13cf97fba`

The Fastboot command accepted this image. A prearmed exact-port observer ran for
120 seconds; a separate bounded EP1-IN reader ran for 45 seconds. **The USB data
acceptance failed:** no eligible experiment identity was selected, no interface
was claimed, and zero `MI4U` records were received. Android recovered automatically.
There was no automatic retry of the boot command.

Fastboot's `OKAY` is command acceptance, not USB data delivery or successful iOS
startup. Cached descriptors, device-presence observations, and reader exit status
alone do not establish a working stream. The intended narrow USB threshold is two
adjacent valid records in one claimed-identity segment, sequence increment one
modulo 32 bits, and no backwards counters.

The recovered console shows real XNU running and pid1 entering the genuine dyld.
The high commpage alias was installed using the same physical page with user
read-only/XN permissions. Current tests use a **small RAM-backed root volume with
genuine executable components**, not a demonstrated full iOS root and service
installation. SpringBoard and interactive applications are not demonstrated.

## Identified startup defect

Two independent dyld anchors establish the runtime slide. The failing instruction
resolves to `_dyld_fatal_error`, ARM `UDF #0xdefe`, called by `dyld::halt`. The halt
argument is the image's literal `throwf, out of memory error`; this does not prove
physical RAM exhaustion or reveal the earlier error that dyld was trying to format.
The exact dyld bytes were matched to the booted entry image, rather than assuming
an unrelated local root filesystem was its source.

Actual linked kernel instructions confirm a VM trap wire-width mismatch: trap10
reads flags at saved-frame byte12, while the iOS 7 stub supplies flags at byte16.
The corresponding VM traps use five/five/seven 32-bit wire words. The historical
broad compatibility option also enables unrelated port/map experiments, so it was
not used as a shortcut.

The corrective implementation uses separate narrow VM-wire and SWI-timebase
selectors, preserving the broad selector OFF, the syscall dispatch table, and
port/map exclusions. Offline validation passed 91 scope checks and 114 actual-C
runtime cases with Clang and Linux GCC under strict warnings. Linked checks in a
subsequent full-build attempt confirmed the correct VM-word reads, real 64-bit
clock return and the excluded extra trap rows. That build was later stopped by an
independent source-staging checker; no image from that attempt was booted.

## Identified USB configuration defect

The supplier clock table specifies `GPLL0 / 8` for the USB HS core. Its formula
requires controlled CFG bits `0x10f` under mask `0x71f`; the previous write of zero
selects a different source, not the claimed 75 MHz configuration.

The candidate now preserves unrelated CFG bits, fails closed when UPDATE does not
complete, and logs the actual CFG. Two diagnostics were corrected to read the real
AHB branch register rather than the RCGR M slot. These changes passed 299 actual-C
clock-model checks and four deliberately broken variants, plus the existing 128
DMA and 12 service-window checks. They do **not** demonstrate PLL lock, actual
clock rate, physical attachment or USB enumeration.

## Build and safety tooling

The independent verified-build harness locks the repository, pins declared inputs
and outputs, rejects stale artifacts and failure diagnostics even after exit0,
checks exact payload embedding, rehashes after checks, and publishes only a checked
image. Its 27 offline tests pass. A successful build is still not phone approval:
separate compiled-backend review previously found legacy medium-write paths that
were then gated out and fully rebuilt.

A read-only ARM32 Mach-O inspection tool attributes PCs and return addresses using
real `LC_UNIXTHREAD`, slide anchors, instruction mode, sections and function starts.
It refuses inconsistent anchors and does not confuse `LC_MAIN` with the kernel's
initial dyld entry. Its tests use synthetic fixtures; no proprietary executable
bytes are published with these tools.

## Remaining work

The corrective full build completed assembly, preparation, kernel, entry and payload
stages and **18 final checks**. Its image SHA256 is:

`a06cbdcc0499d83250ba3aac0dd094a1afcfc19dce0abe71581a80692a236c50`

It has now received **one bounded RAM-boot experiment**. VM allocation with the
correct wire flags returned success, followed by successful deallocation: the
specific VM-wire fix has hardware evidence. Dyld subsequently reached its fatal
halt again, now with a dynamically formatted message that has not yet been read.
This is not successful launchd service execution or proof of any particular next
error. The clock CFG read back `0x10f`; USB acceptance still failed with zero data
records. Android recovered automatically, with no second boot attempt.

### USB controller-selection correction

A read-only UDC binding from the recovered phone identifies **DWC3 at
`0xf9200000`**, while the experimental code programs the separate CI13xxx at
`0xf9a55000`. Supplier device-tree configuration disables the CI node; the DWC3
platform driver explicitly routes the primary USB port to its controller. This
explains why CI register readbacks and CI-only model tests do not establish a
working physical phone link. It does not measure the bootloader's exact mux/power
state or prove a DWC3 implementation already works.

The independent witness build completed all five stages and **20 final checks**.
Its image SHA256 is:

`1b4582dfc292f9e7c9887d122c3a97b72059a3a1b226b453dcf9400eb9bede19`

A subsequent single bounded RAM boot printed both obsolete-CI skip markers.
All four linked XNU USB entry functions were independently checked as bare
returns. All medium-write gates and broad compatibility remained OFF. Android
recovered within the observation deadline; no USB reader or second boot was used.

The bounded witness recovered the **actual next error**, twice, with matching
successful reads through dyld's errorMessage field and saved r5:

```text
Library not loaded: /usr/lib/libbsm.0.dylib
  Referenced from: /sbin/launchd
  Reason: image not found
```

The logger replaces newline characters with `?`; the displayed lines above restore
that formatting. This is now a hardware-proven missing-library blocker, not merely
an inventory inference. It is not proof that satisfying one library completes
launchd or its dependency closure.

One legacy diagnostic must not be overinterpreted: in this dyld's version-0x0e
all-image-info structure, offset `+0x64` is **reserved[0]**, not a cache base. The
old `cacheBase=0` label therefore does not measure cache mapping. The error text
comes from separate successful bounded reads and remains valid. The witness does
not skip the fatal instruction or claim universal undefined-instruction handling.

DWC3 needs its own event ring, endpoint commands and TRBs; changing the CI base
address is not a port. An original offline event decoder/consumer now checks the
actual supplier event formats, wrap-safe byte counts, budgets and framing refusal.
Clang/GCC native tests and sanitizer tests passed; no event-ring or EP0 hardware
adapter has been integrated. These tests are not USB connectivity evidence.

### Guarded-read hardware prerequisite

A separate opt-in build completed all five stages, 27 final acceptance commands
and 68 linked probe/configuration/opcode checks. Its image SHA256 was:

`446eaf8408247baf33bbfd1fe74d1677a72fd5582443d835a1255693a9eca3dd`

The XNU entry ELF remained identical to the prior witness entry; the new guarded
identity probe was payload-only. One bounded RAM boot recovered to Android. The
normal guarded RAM read passed, but execution stopped at the intentional unmapped
translation-fault selftest before its result was logged. **No new-probe watchdog,
clock or DWC3 register read occurred.** This is a guarded-recovery prerequisite
failure, not evidence that DWC3 itself failed to answer. The log did not capture
DFSR/DFAR/SPSR for that fault, so the exact reject condition remains unmeasured.

Review found a coverage gap: host tests assumed `CPSID if` sets both mask bits,
whereas historical same-device records show F remaining clear. That is the leading
hypothesis, not the captured SPSR of this boot. The subsequent correction retains
the strict exception policy and adds actual post-mask CPSR readback **before any
target load or guard activation**. If masking did not take effect, it restores the
original state, returns a nonzero status and leaves output unchanged. Dedicated
cases cover missing I, missing F and neither effective, all with zero target-load
calls. A separate diagnostic build/boot must measure that state before any further
policy or controller changes. No automatic retry or gate relaxation is used.

That strict diagnostic subsequently completed all five stages, 27 acceptance
commands and 71 linked checks. Its image SHA256 was:

`cf2c63501e2ed9c69125be300cc263f3ecc7cbef6d499723ae1d4b1d2987ca98`

One RAM boot measured **CPSR `0x60000113` → `0x60000193`**: I became 1, F remained
0, and A was preserved. The guard returned status 6 before activation or any target
load, safely skipped the probe, and Android recovered. No intentional fault or
new watchdog/clock/DWC3 target read occurred. This confirms the current masking
limitation; it still does not reconstruct the original fault's uncaptured SPSR.

A separately reviewed default-OFF IRQ-only profile preserves per-call F/A and
requires actual I=1 plus stable ARM/SVC/LE state. It retains exact fault PC/DFAR/
read-DFSR checks and matching saved-SPSR context, and adds a banked-register active
FIQ path to a two-known-RAM-store, nonreturning park before logging. Host GCC/Clang,
sanitizer, lifecycle and opcode tests are not proof of asynchronous FIQ delivery.
The successor first verifies **RAM and intentional-fault recovery only**, with
controller target reads explicitly inhibited. No controller initialization,
security-routing change, or experimental medium write is authorized by this work.

The recovery-only successor completed all five build stages, 29 acceptance
commands and 104 actual linked checks. Its image SHA256 was:

`6e4365522002e9018b5cb5f0290fcae8ae7fce0f64bcb200f7b5b14798686799`

A single bounded RAM boot then passed both normal RAM and exact intentional-fault
recovery. Actual evidence: result 2; DFSR `0x00000005`; DFAR `0xdeadc000`; observed
and expected fault PC both `0x0000c734`; SPSR `0x60000193`; count 1; active 0;
status 2; output still `0xa55a12ed`. The explicit final marker inhibited all new
live-watchdog/controller target reads, and Android recovered. This proves the
narrow synchronous ARM recovery contract, **not asynchronous FIQ delivery or USB**.

Only after that hardware gate was a separately validated identification payload
prepared. The exact-transition tool pins 705 recorded compiled sources, every
prior declared input/kernel output and four byte-identical OLD entry artifacts;
only TARGET_READS=0→1 and the matching final checker mode may change. It performs
a payload rebuild, not a fresh kernel/entry compilation. All other 28 acceptance
commands remain identical. Its synthetic safeguards passed 42 tests independently
on macOS and Linux; historical source manifests still do not prove a transitive
header dependency closure. Controller identity remains a separate real-boot gate.

The subsequent identification payload passed 29 checks and 104 linked checks;
its image SHA256 was:

`64c9ede5ab8784a96c758abffdc214b6e989bcc0e05bbae8e62237ef4e924db7`

One bounded RAM boot passed normal/fault guard selftests again and confirmed the
live watchdog advancing. The first clock read succeeded at `0xfc400108` with
`0x80000000`. The strict core stopped with CLOCK_BLOCKED, one completed read and
zero valid DWC3 registers; Android recovered. The supplier contract identifies
this as the SYS_NOC_USB3_AXI branch. **No other clock/reset/root/core register was
read and no clock/controller register was written.** This is a measured clock
prerequisite blocker, not DWC3 identification, enumeration or transport. A separate
GCC-only snapshot and dependency review must precede any clock enablement; the
existing identification early-stop is not bypassed.

### Root-system provenance and capacity

The current 512 KiB RAM root contains only launchd and dyld, with no dependency
libraries, shared cache or `/dev` mountpoint. The larger host-side root image is a
historical laboratory derivative containing injected observers and modified
service configuration, not evidence of untouched stock iOS. Those jobs will not
be copied wholesale or used as proof of genuine service behavior.

The launchd dependency closure includes 33 cached libraries. The complete cache
is about 301 MiB and cannot be embedded in the actually owned 64 MiB window.
Simple cache slicing is not runnable library restoration: optimized pointers,
relocations, bindings and shared LINKEDIT require correct handling. A smaller RAM
root is only a feasibility target until its executable dependencies, layout and
real startup are validated. Neither these inventory findings nor a build pass
establish complete iOS operation.

Raw recovered logs, device identifiers, proprietary images, and license-uncertain
external port snapshots remain private. This milestone publishes only reviewable
original tooling and sanitized findings; it does not assert full iOS usability.
