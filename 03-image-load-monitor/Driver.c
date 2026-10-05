#include <ntddk.h>

// Forward declarations
DRIVER_INITIALIZE DriverEntry;
DRIVER_UNLOAD ImageMonUnload;

// Case-insensitive check: does 'str' contain 'sub'?
// Simple scan — fine for the short paths we deal with here.
static BOOLEAN UnicodeContains(_In_ PCUNICODE_STRING str, _In_ PCWSTR sub) {
    if(str == NULL || str->Buffer == NULL) {
        return FALSE;
    }

    UNICODE_STRING subStr;
    RtlInitUnicodeString(&subStr, sub);

    USHORT strChars = str->Length / sizeof(WCHAR);
    USHORT subChars = subStr.Length / sizeof(WCHAR);

    if(subChars == 0 || subChars > strChars) {
        return FALSE;
    }

    for(USHORT i = 0; i + subChars <= strChars; i++) {
        UNICODE_STRING window;
        window.Buffer = &str->Buffer[i];
        window.Length = subStr.Length;
        window.MaximumLength = subStr.Length;

        // TRUE = case-insensitive
        if(RtlEqualUnicodeString(&window, &subStr, TRUE)) {
            return TRUE;
        }
    }
    return FALSE;
}

// Our image-load callback.
VOID ImageMonLoadImageNotify(
    _In_opt_ PUNICODE_STRING FullImageName,
    _In_ HANDLE ProcessId,
    _In_ PIMAGE_INFO ImageInfo) {
    BOOLEAN isKernel = (ImageInfo->SystemModeImage != 0);

    // An image counts as "trusted location" if it loads from one of the
    // normal install roots. NOTE: this is a path heuristic only. Real EDR
    // checks the digital signature instead, because any of these folders
    // could in principle hold a malicious file. (-> future: signature check)
    BOOLEAN trustedPath = UnicodeContains(FullImageName, L"\\Windows\\") ||
                          UnicodeContains(FullImageName, L"\\Program Files\\") ||
                          UnicodeContains(FullImageName, L"\\Program Files (x86)\\") ||
                          UnicodeContains(FullImageName, L"\\ProgramData\\");

    // Log only images loaded from OUTSIDE those trusted locations.
    // Applies to both kernel and user images.
    if(trustedPath) {
        return;
    }

    PCSTR kind = isKernel ? "KERNEL" : "user ";

    if(FullImageName != NULL) {
        KdPrintEx(
            (DPFLTR_IHVDRIVER_ID,
             DPFLTR_INFO_LEVEL,
             "ImageMon: [%s] pid=%llu  %wZ\n",
             kind,
             (ULONG64)(ULONG_PTR)ProcessId,
             FullImageName));
    } else {
        KdPrintEx(
            (DPFLTR_IHVDRIVER_ID,
             DPFLTR_INFO_LEVEL,
             "ImageMon: [%s] pid=%llu  (no name)\n",
             kind,
             (ULONG64)(ULONG_PTR)ProcessId));
    }
}

// Called when the driver loads.
NTSTATUS
DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath) {
    UNREFERENCED_PARAMETER(RegistryPath);
    NTSTATUS status;

    KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "ImageMon: DriverEntry\n"));

    DriverObject->DriverUnload = ImageMonUnload;

    // Register our callback for image-load events.
    status = PsSetLoadImageNotifyRoutine(ImageMonLoadImageNotify);
    if(!NT_SUCCESS(status)) {
        KdPrintEx((
            DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "ImageMon: register failed 0x%08X\n", status));
        return status;
    }

    return STATUS_SUCCESS;
}

// Called when the driver unloads (sc stop / sc delete).
VOID ImageMonUnload(_In_ PDRIVER_OBJECT DriverObject) {
    UNREFERENCED_PARAMETER(DriverObject);

    // Remove our callback. Without this, the kernel would still call us
    // after we're gone -> BSOD.
    PsRemoveLoadImageNotifyRoutine(ImageMonLoadImageNotify);

    KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "ImageMon: Unload\n"));
}
