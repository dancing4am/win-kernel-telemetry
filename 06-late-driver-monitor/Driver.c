#include <ntddk.h>

//
// 06-late-driver-monitor : flag KERNEL drivers that load late (after boot).
//
// Same image-load callback as 03, but with two changes:
//   1. We ignore every user-mode image and keep ONLY kernel-mode images
//      (drivers). Those are rare, so the callback can do its work inline --
//      no worker thread needed (that was 05's problem, not ours).
//   2. For each kernel driver load we read the system uptime. If it loaded
//      more than BOOT_WINDOW_SECONDS after boot, we tag it [LATE].
//
// Why this matters: a driver appearing long after boot is the core signal of
// a BYOVD ("bring your own vulnerable driver") attack -- an attacker loading a
// signed-but-vulnerable driver at runtime to get into the kernel. Boot-time
// drivers are expected and quiet; a late one is loud.
//

#define BOOT_WINDOW_SECONDS 120ULL // grace window after boot
#define HUNDRED_NS_PER_SEC  10000000ULL // KeQueryInterruptTime unit -> seconds

DRIVER_INITIALIZE DriverEntry;
DRIVER_UNLOAD LateDrvMonUnload;

VOID LateDrvMonLoadImageNotify(
    _In_opt_ PUNICODE_STRING FullImageName,
    _In_ HANDLE ProcessId,
    _In_ PIMAGE_INFO ImageInfo) {
    // Kernel-mode images only. SystemModeImage == 0 means a user-mode DLL/EXE
    // -> not our concern, drop it immediately. This is what keeps the volume
    // tiny and lets us stay synchronous.
    if(ImageInfo->SystemModeImage == 0) {
        return;
    }

    // Uptime = time since boot, in 100ns units. Convert to whole seconds.
    // Interrupt time starts at 0 at boot, so this is exactly "how long since
    // boot" with no subtraction and no sensitivity to wall-clock changes.
    ULONGLONG uptime100ns = KeQueryInterruptTime();
    ULONGLONG uptimeSec = uptime100ns / HUNDRED_NS_PER_SEC;

    BOOLEAN late = (uptimeSec > BOOT_WINDOW_SECONDS);

    if(FullImageName != NULL) {
        KdPrintEx(
            (DPFLTR_IHVDRIVER_ID,
             DPFLTR_INFO_LEVEL,
             "LateDrvMon: [%s] uptime=%llus pid=%llu  %wZ\n",
             late ? "LATE" : "boot",
             uptimeSec,
             (ULONG64)(ULONG_PTR)ProcessId,
             FullImageName));
    } else {
        KdPrintEx(
            (DPFLTR_IHVDRIVER_ID,
             DPFLTR_INFO_LEVEL,
             "LateDrvMon: [%s] uptime=%llus pid=%llu  (no name)\n",
             late ? "LATE" : "boot",
             uptimeSec,
             (ULONG64)(ULONG_PTR)ProcessId));
    }
}

NTSTATUS
DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath) {
    UNREFERENCED_PARAMETER(RegistryPath);
    NTSTATUS status;

    // Log our own arm time: the uptime at which this monitor started watching.
    // With auto/boot start this tells us how early the "guard clocked in".
    ULONGLONG armSec = KeQueryInterruptTime() / HUNDRED_NS_PER_SEC;
    KdPrintEx(
        (DPFLTR_IHVDRIVER_ID,
         DPFLTR_INFO_LEVEL,
         "LateDrvMon: DriverEntry (armed at uptime=%llus)\n",
         armSec));

    DriverObject->DriverUnload = LateDrvMonUnload;

    // Register for image-load events. We only get NEW loads from here on --
    // images already mapped before registration are not replayed.
    status = PsSetLoadImageNotifyRoutine(LateDrvMonLoadImageNotify);
    if(!NT_SUCCESS(status)) {
        KdPrintEx(
            (DPFLTR_IHVDRIVER_ID,
             DPFLTR_INFO_LEVEL,
             "LateDrvMon: register failed 0x%08X\n",
             status));
        return status;
    }

    return STATUS_SUCCESS;
}

VOID LateDrvMonUnload(_In_ PDRIVER_OBJECT DriverObject) {
    UNREFERENCED_PARAMETER(DriverObject);

    // Remove the callback, or the kernel calls freed code on the next load -> BSOD.
    PsRemoveLoadImageNotifyRoutine(LateDrvMonLoadImageNotify);

    KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "LateDrvMon: Unload\n"));
}
