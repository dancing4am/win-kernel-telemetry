# win-kernel-telemetry

Hands-on Windows kernel driver lab: KMDF/WDM telemetry drivers exploring the
primitives behind endpoint detection (EDR) and anti-cheat — process and
image-load monitoring, and related kernel callback techniques.

Each driver is small, commented, and built to be understood rather than
shipped. Everything runs in an isolated VM with test signing enabled; nothing
here is meant to run on a production machine.

## Drivers

| # | Driver | What it does | Technique |
|---|--------|--------------|-----------|
| 01 | `01-hello-world` | Minimal KMDF driver that logs `DriverEntry` and `EvtDeviceAdd` | KMDF skeleton, PnP load via a root-enumerated device |
| 02 | `02-process-monitor` | Logs every process create/exit, with PID, parent PID, and image path | WDM, `PsSetCreateProcessNotifyRoutineEx` |
| 03 | `03-image-load-monitor` | Logs DLL/driver image loads, filtered to images loaded from outside trusted install roots | WDM, `PsSetLoadImageNotifyRoutine` |

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
driver, or EXE mapped into any process fires the callback — which is a firehose,
since one app loads dozens of DLLs.

To stay useful (and to keep the debugged VM responsive), it filters: kernel
images are always of interest, and user images are logged only when loaded from
outside the normal install roots (`\Windows\`, `\Program Files\`,
`\Program Files (x86)\`, `\ProgramData\`). This mirrors the EDR principle of
*normal is quiet, suspicious is loud* — a DLL loading from a user's AppData or
Temp folder is exactly what you want to see.

This is a path heuristic, not a real trust decision. Any of those folders could
hold a malicious file, so production EDR checks the image's digital signature
instead. That signature-based check is the natural next step (see Roadmap).

## Cross-cutting lessons

- Callbacks must be cleaned up. A process/image notify routine left registered
  after the driver unloads means the kernel calls freed memory on the next
  event — an instant BSOD. `DriverUnload` always deregisters the callback.
- Callbacks must be lightweight. Logging over the network inside the callback
  made the VM visibly stutter, because every image load blocked on I/O. Real EDR
  captures minimal data in the callback and does the heavy work on a separate
  thread.
- Primitive drivers. A driver with no device doesn't install "on a device".
  Either remove the INF (02) or declare it primitive with a `[DefaultInstall]`
  section and `PnpLockdown=1` (03).

## Roadmap

- 04 — signature-based filtering (planned): replace the path heuristic with an
  actual image-signature check, and/or move logging off the callback thread onto
  a worker queue — both steps toward how production EDR really works.

## Building

- Visual Studio 2026 with the Desktop development with C++ workload and the
  Windows Driver Kit (WDK) component, plus the Spectre-mitigated libraries.
- A matching Windows SDK and WDK (build numbers must match).
- For the callback drivers, add `/INTEGRITYCHECK` under
  Linker > Command Line > Additional Options.
- Open the solution in each driver folder, select `Debug | x64`, and Build.

## Testing (isolated VM only)

Drivers are test-signed, so they load only on a machine with test signing on:

    bcdedit /set testsigning on

Load a service driver (02/03):

    sc create <Name> type= kernel binPath= C:\Windows\System32\drivers\<file>.sys
    sc start <Name>

(Note the required space after `type=` and `binPath=`.)

Log output is viewed with DebugView (Capture Kernel) or over a WinDbg
kernel-debug connection (KDNET). For `KdPrintEx` INFO-level messages to appear,
open the debug print filter:

    reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Debug Print Filter" /v IHVDRIVER /t REG_DWORD /d 0xF /f

## Credits

`01-hello-world` is based on Microsoft's official KMDF "Hello World" sample and
tutorial, adapted with added comments.

## Disclaimer

For learning and defensive research only. These drivers collect telemetry and
do not modify system behavior. Run them in a disposable VM, never on a machine
you care about.
