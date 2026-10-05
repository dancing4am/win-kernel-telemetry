#include <ntddk.h>

// Forward declarations
DRIVER_INITIALIZE DriverEntry;
DRIVER_UNLOAD ProcMonUnload;

// Our process-notify callback.
// Called by the kernel every time a process is created or exits.
VOID ProcMonCreateProcessNotify(
    _Inout_ PEPROCESS Process,
    _In_ HANDLE ProcessId,
    _Inout_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo) {
    UNREFERENCED_PARAMETER(Process);

    if(CreateInfo != NULL) {
        // A process is STARTING.
        // CreateInfo->ImageFileName is a UNICODE_STRING (may be NULL).
        if(CreateInfo->ImageFileName != NULL) {
            KdPrintEx(
                (DPFLTR_IHVDRIVER_ID,
                 DPFLTR_INFO_LEVEL,
                 "ProcMon: START pid=%llu ppid=%llu  %wZ\n",    // w is wide(unicode), Z is UNICODE_STRING
                 (ULONG64)(ULONG_PTR)ProcessId,
                 (ULONG64)(ULONG_PTR)CreateInfo->ParentProcessId,
                 CreateInfo->ImageFileName));
        } else {
            KdPrintEx(
                (DPFLTR_IHVDRIVER_ID,
                 DPFLTR_INFO_LEVEL,
                 "ProcMon: START pid=%llu ppid=%llu  (no image name)\n",
                 (ULONG64)(ULONG_PTR)ProcessId,
                 (ULONG64)(ULONG_PTR)CreateInfo->ParentProcessId));
        }
    } else {
        // A process is EXITING.
        KdPrintEx(
            (DPFLTR_IHVDRIVER_ID,
             DPFLTR_INFO_LEVEL,
             "ProcMon: EXIT  pid=%llu\n",
             (ULONG64)(ULONG_PTR)ProcessId));
    }
}

// Called when the driver loads.
NTSTATUS
DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath) {
    UNREFERENCED_PARAMETER(RegistryPath);
    NTSTATUS status;

    KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "ProcMon: DriverEntry\n"));

    // Register the cleanup routine so the driver can be unloaded by sc stop.
    DriverObject->DriverUnload = ProcMonUnload;

    // Register our callback for process create/exit events.
    status = PsSetCreateProcessNotifyRoutineEx(ProcMonCreateProcessNotify, FALSE);  // FALSE means register
    if(!NT_SUCCESS(status)) {
        KdPrintEx(
            (DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "ProcMon: register failed 0x%08X\n", status));
        return status;
    }

    return STATUS_SUCCESS;
}

// Called when the driver unloads (sc stop / sc delete).
VOID ProcMonUnload(_In_ PDRIVER_OBJECT DriverObject) {
    UNREFERENCED_PARAMETER(DriverObject);

    // Remove our callback. The TRUE means "remove".
    // Without this, the kernel would still call us after we're gone -> BSOD.
    PsSetCreateProcessNotifyRoutineEx(ProcMonCreateProcessNotify, TRUE);    // TRUE mean unregister

    KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "ProcMon: Unload\n"));
}
