# win-kernel-telemetry

Hands-on Windows kernel driver lab: KMDF/WDM drivers exploring the primitives
behind endpoint detection (EDR) and anti-cheat — process and image-load
monitoring, and process protection.

Each driver is small, commented, and built to be understood rather than
shipped. Everything runs in an isolated VM with test signing enabled; nothing
here is meant to run on a production machine.

## Drivers

| # | Driver | What it does | Technique |
|---|--------|--------------|-----------|
| 01 | `01-hello-world` | Minimal KMDF driver that logs `DriverEntry` and `EvtDeviceAdd` | KMDF skeleton, PnP load via a root-enumerated device |
| 02 | `02-process-monitor` | Logs every process create/exit, with PID, parent PID, and image path | WDM, `PsSetCreateProcessNotifyRoutineEx` |
| 03 | `03-image-load-monitor` | Logs DLL/driver image loads, filtered to images loaded from outside trusted install roots | WDM, `PsSetLoadImageNotifyRoutine` |
| 04 | `04-process-protect` | Blocks other processes from reading/writing a protected process's memory (anti-cheat style), with a fakegame/reader test harness | WDM, `ObRegisterCallbacks` |

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
one app loads dozens of DLLs.

To stay useful (and to keep the debugged VM responsive), it filters: images are
logged only when loaded from outside the normal install roots (`\Windows\`,
`\Program Files\`, `\Program Files (x86)\`, `\ProgramData\`). This mirrors the
EDR principle of *normal is quiet, suspicious is loud* — a DLL loading from a
user's AppData or Temp folder is exactly what you want to see. It is a path
heuristic, not a trust decision; production EDR checks the image's digital
signature instead (see Roadmap).

### 04 — process protect
Where 01–03 observe, this one intervenes. Using `ObRegisterCallbacks`, it runs a
pre-operation callback before any handle to a process is created, and for the
protected "game" process it strips `PROCESS_VM_READ` / `PROCESS_VM_WRITE` from
the requested access. The opener still gets a handle, but the later
`ReadProcessMemory` fails with access denied. This is the anti-cheat side of the
same coin as 03: instead of watching the whole system, it protects one process
from external memory reads — the main defense against external cheats.

Scope choices that matter:
- Only `VM_READ` / `VM_WRITE` are stripped. Stripping `VM_OPERATION` /
  `TERMINATE` as well broke normal OS process management (a modern UWP Notepad
  wouldn't even launch). Trimming just the memory-access rights blocks cheats
  while leaving the OS able to create and manage the process.
- The protected target is a plain console exe (`fakegame`), not a UWP app, so
  the behaviour is clean and testable.

Test harness (`test/fakegame`, `test/reader`):
- `fakegame` holds a secret value and prints its PID and the value's address.
- `reader` opens that PID and tries to `ReadProcessMemory` the address.
- Without the driver: reader reads the value (1337). With the driver loaded:
  `OpenProcess` still succeeds, but `ReadProcessMemory` fails with error 5
  (access denied). The test binaries are built `/MT` (static runtime) so they
  run on a VM with no Visual C++ redistributable installed.

## Cross-cutting lessons

- Callbacks must be cleaned up. A notify/Ob callback left registered after the
  driver unloads means the kernel calls freed memory on the next event — an
  instant BSOD. `DriverUnload` always deregisters.
- Callbacks must be lightweight. Logging over the network inside the callback
  made the VM stutter, because every image load blocked on I/O. Real EDR
  captures minimal data in the callback and does heavy work on a worker thread.
- Protection is a balancing act. Too strict and the protected app (or the OS)
  breaks; too loose and a cheat gets through. 04 shows this directly.
- Primitive drivers. A driver with no device doesn't install "on a device".
  Either remove the INF, or declare it primitive with a `[DefaultInstall]`
  section and `PnpLockdown=1`.

## Roadmap

- 05 — signature-based filtering / off-thread logging (planned): replace 03's
  path heuristic with a real image-signature check, and move logging off the
  callback thread onto a worker queue — both steps toward how production EDR
  really works.
- Possible: narrow 04 to also consider the opener (trust OS-core processes),
  and protect by PID rather than image name.

## Building

- Visual Studio 2026 with the Desktop development with C++ workload and the
  Windows Driver Kit (WDK) component, plus the Spectre-mitigated libraries.
- A matching Windows SDK and WDK (build numbers must match).
- For the callback drivers (02/03/04), add `/INTEGRITYCHECK` under
  Linker > Command Line > Additional Options.
- Open the solution in each driver folder, select `Debug | x64`, and Build.
- Test exes (fakegame/reader) are plain console apps; build them `Release | x64`
  with Runtime Library set to `/MT` so they need no runtime DLLs on the VM.

## Testing (isolated VM only)

Drivers are test-signed, so they load only on a machine with test signing on:

    bcdedit /set testsigning on

Load a service driver (02/03/04):

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

For learning and defensive research only. These drivers collect telemetry and,
in 04, restrict handle access to a process you control in a disposable VM. Run
them in a VM, never on a machine you care about.
