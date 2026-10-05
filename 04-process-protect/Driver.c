#include <ntifs.h>
#include <ntddk.h>

#ifndef PROCESS_TERMINATE
#define PROCESS_TERMINATE    0x0001
#define PROCESS_VM_OPERATION 0x0008
#define PROCESS_VM_READ      0x0010
#define PROCESS_VM_WRITE     0x0020
#endif

//
// 04-process-protect : anti-cheat style process protection (LEARNING / VM ONLY)
//
// Shows how anti-cheat (and EDR) use ObRegisterCallbacks to trim the access
// another process receives when it opens a handle to a protected process.
// The "protected game" here is simply notepad.exe so it is easy to test in an
// isolated VM. This only trims handle rights (the documented Microsoft
// technique); it does not hide the process or block inspection.
//

// Process we treat as "the game" (tail match on the image path, case-insensitive).
#define PROTECTED_IMAGE_NAME L"fakegame.exe"

// Memory-access rights removed from a handle opened against the protected
// process: these are what an external tool would need to read or write its
// memory. VM_OPERATION and TERMINATE are left intact so the OS can still
// create and manage the process normally.
#define DENIED_PROCESS_RIGHTS \
    (PROCESS_VM_READ | PROCESS_VM_WRITE)

static PVOID g_ObHandle = NULL; // registration handle, for unregister on unload

DRIVER_INITIALIZE DriverEntry;
DRIVER_UNLOAD ProcProtectUnload;

// TRUE if 'fullPath' ends with PROTECTED_IMAGE_NAME.
static BOOLEAN IsProtectedImage(_In_ PCUNICODE_STRING fullPath) {
    if(fullPath == NULL || fullPath->Buffer == NULL) {
        return FALSE;
    }

    UNICODE_STRING target;
    RtlInitUnicodeString(&target, PROTECTED_IMAGE_NAME);

    USHORT pathChars = fullPath->Length / sizeof(WCHAR);
    USHORT targetChars = target.Length / sizeof(WCHAR);
    if(targetChars == 0 || targetChars > pathChars) {
        return FALSE;
    }

    UNICODE_STRING tail;
    tail.Buffer = &fullPath->Buffer[pathChars - targetChars];
    tail.Length = target.Length;
    tail.MaximumLength = target.Length;

    return RtlEqualUnicodeString(&tail, &target, TRUE); // TRUE = case-insensitive
}

// Is 'Process' our protected "game"?
static BOOLEAN IsProtectedProcess(_In_ PEPROCESS Process) {
    PUNICODE_STRING fullName = NULL;
    if(!NT_SUCCESS(SeLocateProcessImageName(Process, &fullName)) || fullName == NULL) {
        return FALSE;
    }

    BOOLEAN match = IsProtectedImage(fullName);
    ExFreePool(fullName); // SeLocateProcessImageName allocates; we free it
    return match;
}

// Pre-operation callback: runs before a handle to a process is created or
// duplicated. We may lower the requested access here.
OB_PREOP_CALLBACK_STATUS
ProcProtectPreOp(_In_ PVOID RegistrationContext, _Inout_ POB_PRE_OPERATION_INFORMATION Info) {
    UNREFERENCED_PARAMETER(RegistrationContext);

    // Leave kernel-originated handle operations alone.
    if(Info->KernelHandle) {
        return OB_PREOP_SUCCESS;
    }

    PEPROCESS target = (PEPROCESS)Info->Object;

    // Never interfere with a process opening a handle to itself.
    if(target == PsGetCurrentProcess()) {
        return OB_PREOP_SUCCESS;
    }

    if(!IsProtectedProcess(target)) {
        return OB_PREOP_SUCCESS; // not the game — allow as-is
    }

    // Strip the dangerous rights from the requested/desired access.
    if(Info->Operation == OB_OPERATION_HANDLE_CREATE) {
        Info->Parameters->CreateHandleInformation.DesiredAccess &= ~DENIED_PROCESS_RIGHTS;
    } else if(Info->Operation == OB_OPERATION_HANDLE_DUPLICATE) {
        Info->Parameters->DuplicateHandleInformation.DesiredAccess &= ~DENIED_PROCESS_RIGHTS;
    }

    KdPrintEx(
        (DPFLTR_IHVDRIVER_ID,
         DPFLTR_INFO_LEVEL,
         "ProcProtect: trimmed access to protected process (opener pid=%llu)\n",
         (ULONG64)(ULONG_PTR)PsGetCurrentProcessId()));

    return OB_PREOP_SUCCESS;
}

NTSTATUS
DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath) {
    UNREFERENCED_PARAMETER(RegistryPath);
    NTSTATUS status;

    KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "ProcProtect: DriverEntry\n"));

    DriverObject->DriverUnload = ProcProtectUnload;

    // Describe one operation registration: watch process-handle create/dup.
    OB_OPERATION_REGISTRATION opReg;
    RtlZeroMemory(&opReg, sizeof(opReg));
    opReg.ObjectType = PsProcessType;
    opReg.Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
    opReg.PreOperation = ProcProtectPreOp;
    opReg.PostOperation = NULL;

    OB_CALLBACK_REGISTRATION cbReg;
    RtlZeroMemory(&cbReg, sizeof(cbReg));
    cbReg.Version = OB_FLT_REGISTRATION_VERSION;
    cbReg.OperationRegistrationCount = 1;
    // Altitude: an ordering string required by the OB callback system.
    RtlInitUnicodeString(&cbReg.Altitude, L"320000");
    cbReg.RegistrationContext = NULL;
    cbReg.OperationRegistration = &opReg;

    status = ObRegisterCallbacks(&cbReg, &g_ObHandle);
    if(!NT_SUCCESS(status)) {
        KdPrintEx(
            (DPFLTR_IHVDRIVER_ID,
             DPFLTR_INFO_LEVEL,
             "ProcProtect: ObRegisterCallbacks failed 0x%08X\n",
             status));
        return status;
    }

    return STATUS_SUCCESS;
}

VOID ProcProtectUnload(_In_ PDRIVER_OBJECT DriverObject) {
    UNREFERENCED_PARAMETER(DriverObject);

    if(g_ObHandle != NULL) {
        ObUnRegisterCallbacks(g_ObHandle); // must unregister, or BSOD later
        g_ObHandle = NULL;
    }

    KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "ProcProtect: Unload\n"));
}
