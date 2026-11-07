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

The corrective sources are not yet hardware-proven. The fresh full build completed
all assembly, preparation, kernel, entry and payload stages and **18 final checks**.
The published image SHA256 is:

`a06cbdcc0499d83250ba3aac0dd094a1afcfc19dce0abe71581a80692a236c50`

Downloaded artifacts matched the recorded hashes. The actual configuration keeps
all medium-write gates and broad compatibility OFF; narrow VM-wire/timebase paths
are ON. Actual linked-code checks retain the read backend and exclude the extra
medium-write and port/map laboratory entry points. The geometry-tool correction
also passed eight regression groups and source round-trip checks.

**This corrective image has not been booted.** The next hardware milestone is one
bounded, preobserved RAM boot: verify the new CFG readback, determine whether the
host receives adjacent valid records, recover the actual dyld/launchd progress,
and retain explicit recovery deadlines. A build pass is not USB or iOS success.
The RAM-root dependency set must also be completed before a full service-system
claim is possible.

Raw recovered logs, device identifiers, proprietary images, and license-uncertain
external port snapshots remain private. This milestone publishes only reviewable
original tooling and sanitized findings; it does not assert full iOS usability.
