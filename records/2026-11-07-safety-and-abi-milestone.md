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

The next independent build disables both preboot and XNU-side CI initialization
and diagnostics, retains all medium-write gates and broad compatibility OFF,
and enables a bounded, copyin/copyinstr-only dyld error witness. Its actual C
functions passed Clang and GCC regression tests in 32/64-bit address-size models
(41 cases per model) plus three negative controls. It preserves the saved PC and
exception delivery; it does not skip dyld's fatal instruction. Runtime error
recovery and actual linked configuration remain separate acceptance gates.

DWC3 needs its own event ring, endpoint commands and TRBs; changing the CI base
address is not a port. Offline, revision-aware event/EP0 work precedes any new
bounded hardware identification or initialization.

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
