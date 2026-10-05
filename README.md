# win-kernel-telemetry

Hands-on Windows kernel driver lab: KMDF telemetry drivers exploring the
primitives behind endpoint detection (EDR) and anti-cheat — process and
image-load monitoring, and related kernel callback techniques.

Each driver is small, commented, and built to be understood rather than
shipped. Everything runs in an isolated VM with test signing enabled; nothing
here is meant to run on a production machine.

## Drivers

| # | Driver | What it does | Technique |
|---|--------|--------------|-----------|
| 01 | `01-hello-world` | Minimal KMDF driver that logs `DriverEntry` and `EvtDeviceAdd` | KMDF skeleton, PnP load via a root-enumerated device |
| 02 | `02-process-monitor` | Logs every process create/exit | `PsSetCreateProcessNotifyRoutineEx` |
| 03 | `03-image-load-monitor` *(planned)* | Logs every DLL/driver image load | `PsSetLoadImageNotifyRoutine` |

## Background

- **KMDF** — Kernel-Mode Driver Framework, the modern framework for Windows
  kernel drivers, built on top of the older WDM (Windows Driver Model).
- **Why these callbacks** — process-create and image-load notify routines are
  exactly how EDR sensors and anti-cheat observe what runs on a machine. The
  image-load view in particular is the basis for detecting code injection.

## Building

- Visual Studio 2026 with the **Desktop development with C++** workload and the
  **Windows Driver Kit (WDK)** component.
- A matching Windows SDK and WDK (build numbers must match).
- Open the `.sln` in each driver folder, select `Debug | x64`, and Build.

## Testing (isolated VM only)

Drivers are test-signed, so they load only on a machine with test signing on:

```
bcdedit /set testsigning on
```

Log output is viewed with [DebugView](https://learn.microsoft.com/sysinternals/downloads/debugview)
(Capture Kernel) or over a WinDbg kernel-debug connection. For `KdPrintEx`
`INFO`-level messages to appear, open the debug print filter:

```
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Debug Print Filter" /v IHVDRIVER /t REG_DWORD /d 0xF /f
```

## Credits

`01-hello-world` is based on Microsoft's official KMDF "Hello World" sample and
tutorial, adapted with added comments.

## Disclaimer

For learning and defensive research only. These drivers collect telemetry and
do not modify system behavior. Run them in a disposable VM, never on a machine
you care about.
