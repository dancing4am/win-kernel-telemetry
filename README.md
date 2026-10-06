# win-kernel-telemetry

Hands-on Windows kernel driver lab: KMDF/WDM drivers exploring the primitives
behind endpoint detection (EDR) and anti-cheat — process and image-load
monitoring, process protection, off-thread event handling, and load-time
anomaly detection.

Each driver is small, commented, and built to be understood rather than
shipped. Everything runs in an isolated VM with test signing enabled; nothing
here is meant to run on a production machine.

## Drivers

| # | Driver | What it does | Technique |
|---|--------|--------------|-----------|
| 01 | `01-hello-world` | Minimal KMDF driver that logs `DriverEntry` and `EvtDeviceAdd` | KMDF skeleton, PnP load via a root-enumerated device |
| 02 | `02-process-monitor` | Logs every process create/exit, with PID, parent PID, and image path | WDM, `PsSetCreateProcessNotifyRoutineEx` |
| 03 | `03-image-load-monitor` | Logs DLL/driver image loads, filtered to images from outside trusted install roots | WDM, `PsSetLoadImageNotifyRoutine` |
| 04 | `04-process-protect` | Blocks other processes from reading/writing a protected process's memory (anti-cheat style), with a fakegame/reader test harness | WDM, `ObRegisterCallbacks` |
| 05 | `05-image-monitor-async` | Same events as 03, but the callback only queues; a worker thread does the logging off the callback path | WDM, producer/consumer (spin lock + linked list + system thread) |
| 06 | `06-late-driver-monitor` | Flags kernel-mode drivers that load long after boot — the BYOVD timing signal | WDM, `PsSetLoadImageNotifyRoutine` + `KeQueryInterruptTime`, auto-start |

## What each driver teaches

### 01 — hello world
The KMDF skeleton: `DriverEntry`, an `EvtDeviceAdd` callback, and a
root-enumerated fake device so Plug-and-Play loads the driver. Installed with
`devcon`.

### 02 — process monitor
A software-only driver (no device), so it is pure WDM and loaded as a service
with `sc create` / `sc start` rather than through PnP. Registers a
process-create callback and logs each start/exit with its PID, parent PID, and
image path — the parent/child relationship is a core EDR signal (e.g. Word
spawning PowerShell).

Key gotcha: `PsSetCreateProcessNotifyRoutineEx` requires the driver to be
linked with `/INTEGRITYCHECK`. Without it, registration fails at load with
`STATUS_ACCESS_DENIED` (0xC0000022), which surfaces as "Access is denied" from
`sc start`.

### 03 — image-load monitor
Same WDM service pattern, registering an image-load callback instead. Every DLL,
driver, or EXE mapped into any process fires the callback — a firehose, since
one app loads dozens of DLLs. It filters to images loaded from outside the
normal install roots (`\Windows\`, `\Program Files\`, `\Program Files (x86)\`,
`\ProgramData\`): *normal is quiet, suspicious is loud*. A path heuristic, not a
trust decision — production EDR checks the image's digital signature instead.

### 04 — process protect
Where 01–03 observe, this one intervenes. Using `ObRegisterCallbacks`, a
pre-operation callback runs before any handle to a process is created, and for
the protected "game" process it strips `PROCESS_VM_READ` / `PROCESS_VM_WRITE`
from the requested access. The opener still gets a handle, but the later
`ReadProcessMemory` fails with access denied — the anti-cheat defense against
external memory-reading cheats. A fakegame/reader test harness shows the
before/after (value read without the driver, access denied with it).

### 05 — async image monitor
The same image-load events as 03, restructured the way production EDR actually
handles them: the callback does the minimum and hands the real work to a worker
thread. This fixes the stutter that logging inside the callback caused in 03.

Producer/consumer design:
- The callback (producer) copies a small fixed-size record (PID, kernel/user
  flag, truncated path) into a `NonPagedPool` allocation, pushes it onto a
  shared linked list under a spin lock, signals a `KEVENT`, and returns.
- A system thread (consumer) sleeps on that event, wakes when work arrives,
  drains the queue, and does the slow logging — off the callback path entirely.

Kernel concepts this forces you to get right:
- **Paged vs non-paged pool.** Holding a spin lock raises IRQL to
  `DISPATCH_LEVEL`, where touching pageable memory can fault to disk and
  bugcheck (`IRQL_NOT_LESS_OR_EQUAL`). Everything reachable under the lock is
  non-paged.
- **Startup/teardown ordering.** `DriverEntry` initializes the queue/lock/event
  and starts the worker *before* registering the callback. Unload removes the
  callback first (stop new events), then signals the worker and waits for it to
  exit (`KeWaitForSingleObject` on the referenced thread object) before freeing
  anything — tearing the driver down while the worker still runs would execute
  freed code.

### 06 — late-loaded kernel driver monitor
The same image-load callback as 03, narrowed to a single question: did a
*kernel-mode* driver load long after boot? The callback keeps only kernel
images (`SystemModeImage != 0`) and drops every user-mode DLL/EXE. That is a
handful of events, not 03's firehose, so it stays synchronous — no worker
thread needed (that was 05's problem, not this one). Knowing *when* to add the
async machinery, and when not to, is the point.

For each kernel image it reads the uptime with `KeQueryInterruptTime` (100ns
units counted from boot, so no wall-clock subtraction and no sensitivity to a
clock change) and tags it `[boot]` or `[LATE]` against a boot-window threshold.
A driver appearing long after boot is the core signal of a BYOVD ("bring your
own vulnerable driver") attack — loading a signed-but-vulnerable driver at
runtime to reach the kernel. Boot-time drivers are expected; a late one earns a
flag (not a verdict).

The big lesson here is that *when a driver runs* matters as much as its code. A
demand-start driver loaded by hand well after boot sees every later load as
`[LATE]` and never witnesses the quiet boot window — it clocked in too late, so
its own baseline is blind. Run it **auto-start** and it arms a few seconds into
boot (`armed at uptime=13s`): early drivers then log `[boot]` and a driver
loaded minutes later logs `[LATE]`, the real contrast. Production AV/EDR goes
earlier still, via **ELAM** (Early Launch Anti-Malware) — a specially
Microsoft-signed driver Windows loads *first* so it can vouch for everything
after it. ELAM is out of reach for a test-signed lab driver; auto-start (and,
more riskily, boot-start) is as close as this lab gets.

## Cross-cutting lessons

- Callbacks must be cleaned up and lightweight. A notify/Ob callback left
  registered after unload calls freed memory on the next event — instant BSOD.
  Heavy work (logging, I/O) belongs off the callback path (see 05).
- Match the machinery to the volume. 05 needs a worker thread because image
  loads are a firehose; 06 filters to rare kernel-only events and stays
  synchronous. Unneeded complexity is a cost, not a feature.
- When a driver runs is part of the design. A detector that must see the boot
  window has to be present at boot — auto-start, or in production ELAM. Load it
  late and it is blind to everything before it (see 06).
- Protection is a balancing act. Too strict and the protected app or the OS
  breaks; too loose and a cheat gets through (see 04).
- Primitive drivers. A driver with no device doesn't install "on a device".
  Either remove the INF, or declare it primitive with a `[DefaultInstall]`
  section and `PnpLockdown=1`.

## Roadmap

- 07 — signature-based trust: verify the image's digital signer instead of
  03's path heuristic or 06's load-timing. Closer to how production EDR decides
  what to trust.
- Stretch: run 06 as a boot-start driver for a true from-zero baseline —
  carefully, since a bug in a boot-start driver can block the machine from
  booting.

## Building

- Visual Studio 2026 with the Desktop development with C++ workload and the
  Windows Driver Kit (WDK) component, plus the Spectre-mitigated libraries.
- A matching Windows SDK and WDK (build numbers must match).
- For the callback drivers (02–06), add `/INTEGRITYCHECK` under
  Linker > Command Line > Additional Options.
- Open the solution in each driver folder, select `Debug | x64`, and Build.
- Test exes (fakegame/reader) are plain console apps; build them `Release | x64`
  with Runtime Library set to `/MT` so they need no runtime DLLs on the VM.

## Testing (isolated VM only)

Drivers are test-signed, so they load only on a machine with test signing on:

    bcdedit /set testsigning on

Load a service driver (02–06):

    sc create <Name> type= kernel binPath= C:\Windows\System32\drivers\<file>.sys
    sc start <Name>

(Note the required space after `type=` and `binPath=`.)

To make a driver run from early boot — which 06 needs so it can see the quiet
boot window rather than tagging everything `[LATE]` — set it auto-start and
reboot:

    sc config <Name> start= auto
    shutdown /r /t 0

Log output is viewed with DebugView (Capture Kernel) or over a WinDbg
kernel-debug connection (KDNET). A kernel debugger is the way to see early-boot
logs, since DebugView only starts after login. For `KdPrintEx` INFO-level
messages to appear, open the debug print filter:

    reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Debug Print Filter" /v IHVDRIVER /t REG_DWORD /d 0xF /f

## Credits

`01-hello-world` is based on Microsoft's official KMDF "Hello World" sample and
tutorial, adapted with added comments.

## Disclaimer

For learning and defensive research only. These drivers collect telemetry and,
in 04, restrict handle access to a process you control in a disposable VM. Run
them in a VM, never on a machine you care about.
