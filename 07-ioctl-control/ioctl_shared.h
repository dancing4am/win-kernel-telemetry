#pragma once
//
// ioctl_shared.h - contract shared by the driver and the user-mode app.
// Keep an identical copy on both sides.
// User-mode TU: include <windows.h> then <winioctl.h>.
// Driver TU: <wdm.h> is already included first.
//
#define IOCTLCTL_USER_PATH   L"\\\\.\\IoctlCtl"
#define IOCTLCTL_DEVICE_NAME L"\\Device\\IoctlCtl"
#define IOCTLCTL_SYMLINK     L"\\DosDevices\\IoctlCtl"

// Function codes 0x800+ are reserved for third-party use.
#define IOCTL_GET_VERSION CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_READ_DATA)
#define IOCTL_SET_CONFIG  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_WRITE_DATA)

// Input payload for IOCTL_SET_CONFIG (app -> driver).
typedef struct _IOCTLCTL_CONFIG {
    ULONG Enabled; // 0 = off, 1 = on
    ULONG TargetPid; // 0 = all processes
} IOCTLCTL_CONFIG, *PIOCTLCTL_CONFIG;
