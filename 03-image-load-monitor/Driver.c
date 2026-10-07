#include <ntddk.h>

// Forward declarations
DRIVER_INITIALIZE DriverEntry;
DRIVER_UNLOAD ImageMonUnload;

// ---- Signature-level observation --------------------------------------------
//
// Code Integrity (CI) labels each image it evaluates with a signing level
// (0..15), and the image-load callback hands that label to us in
// IMAGE_INFO.ImageSignatureLevel (Windows 8.1+).
//
// This build only OBSERVES. It counts how many user-mode images arrive at each
// level, so we can see the real distribution on a live system before choosing
// a detection rule. Key subtlety: level 0 is UNCHECKED ("CI did not look"),
// which is NOT the same as level 1, UNSIGNED ("CI looked, no signature").
//
// Names follow the Windows 8.1+ signing-level table.
static const PCSTR g_LevelName[16] = {
    "UNCHECKED", // 0  CI did not evaluate the image
    "UNSIGNED", // 1  CI evaluated it: no signature
    "CUSTOM_0", // 2
    "CUSTOM_1", // 3
    "AUTHENTICODE", // 4  any valid Authenticode signature
    "CUSTOM_2", // 5
    "STORE", // 6
    "ANTIMALWARE", // 7
    "MICROSOFT", // 8
    "CUSTOM_4", // 9
    "CUSTOM_5", // 10
    "DYNAMIC_CODEGEN", // 11
    "WINDOWS", // 12
    "WINDOWS_PPL", // 13
    "WINDOWS_TCB", // 14
    "CUSTOM_6" // 15
};

// One counter per signing level. The callback runs on whichever thread is
// loading the image, so several callbacks can run at the same time. A plain
// ++ is read-add-write and can lose updates; InterlockedIncrement is atomic.
static volatile LONG g_LevelCount[16];

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
    ULONG sigLevel = ImageInfo->ImageSignatureLevel & 0xF; // 4-bit field

    // Observation: count every user-mode image by signing level. Log one
    // individually only if CI checked it and found NO signature (UNSIGNED) —
    // that should be rare, so it cannot flood the log.
    if(!isKernel) {
        InterlockedIncrement(&g_LevelCount[sigLevel]);

        if(sigLevel == SE_SIGNING_LEVEL_UNSIGNED) {
            if(FullImageName != NULL) {
                KdPrintEx(
                    (DPFLTR_IHVDRIVER_ID,
                     DPFLTR_INFO_LEVEL,
                     "ImageMon: [UNSIGNED] pid=%llu  %wZ\n",
                     (ULONG64)(ULONG_PTR)ProcessId,
                     FullImageName));
            } else {
                KdPrintEx(
                    (DPFLTR_IHVDRIVER_ID,
                     DPFLTR_INFO_LEVEL,
                     "ImageMon: [UNSIGNED] pid=%llu  (no name)\n",
                     (ULONG64)(ULONG_PTR)ProcessId));
            }
        }
    }

    // An image counts as "trusted location" if it loads from one of the
    // normal install roots. NOTE: this is a path heuristic only. Real EDR
    // checks the digital signature instead, because any of these folders
    // could in principle hold a malicious file.
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
             "ImageMon: [%s] sig=%s pid=%llu  %wZ\n",
             kind,
             g_LevelName[sigLevel],
             (ULONG64)(ULONG_PTR)ProcessId,
             FullImageName));
    } else {
        KdPrintEx(
            (DPFLTR_IHVDRIVER_ID,
             DPFLTR_INFO_LEVEL,
             "ImageMon: [%s] sig=%s pid=%llu  (no name)\n",
             kind,
             g_LevelName[sigLevel],
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

    // Start the observation with clean counters.
    RtlZeroMemory((PVOID)g_LevelCount, sizeof(g_LevelCount));

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

    // Remove our callback first. Without this, the kernel would still call us
    // after we're gone -> BSOD. It also means no new counts arrive while we
    // print the totals below.
    PsRemoveLoadImageNotifyRoutine(ImageMonLoadImageNotify);

    // Print the signature-level histogram for user-mode images.
    LONG total = 0;
    for(ULONG i = 0; i < 16; i++) {
        total += g_LevelCount[i];
    }

    KdPrintEx(
        (DPFLTR_IHVDRIVER_ID,
         DPFLTR_INFO_LEVEL,
         "ImageMon: signature-level histogram, user-mode images (total=%ld)\n",
         total));

    for(ULONG i = 0; i < 16; i++) {
        if(g_LevelCount[i] != 0) {
            KdPrintEx(
                (DPFLTR_IHVDRIVER_ID,
                 DPFLTR_INFO_LEVEL,
                 "ImageMon:   %s (0x%X) = %ld\n",
                 g_LevelName[i],
                 i,
                 g_LevelCount[i]));
        }
    }

    KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "ImageMon: Unload\n"));
}
