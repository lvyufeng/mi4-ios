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

## Hardware boundary

The actual recovered phone gadget is DWC3, not the separately implemented legacy
CI controller. Changing a CI base address cannot port its QH/dTD driver to DWC3.
A separate identification probe is being developed with strict clock gating,
read-only address allowlists, guarded ARM loads and verified recovery prerequisites.
It is not integrated by these modules. Neither volatile loads, software deadlines,
clock flags nor exception fixups can guarantee completion of a stalled MMIO bus.
