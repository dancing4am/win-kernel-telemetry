#include <windows.h>
#include <winioctl.h>
#include <stdio.h>
#include "ioctl_shared.h"

int main(void) {
    HANDLE h = CreateFileW(
        IOCTLCTL_USER_PATH, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
    if(h == INVALID_HANDLE_VALUE) {
        printf("CreateFile failed: %lu\n", GetLastError());
        return 1;
    }

    DWORD bytes = 0;

    ULONG version = 0;
    if(DeviceIoControl(h, IOCTL_GET_VERSION, NULL, 0, &version, sizeof(version), &bytes, NULL)) {
        printf("version = 0x%08lX (%lu bytes)\n", version, bytes);
    } else {
        printf("GET_VERSION failed: %lu\n", GetLastError());
    }

    IOCTLCTL_CONFIG cfg = {0};
    cfg.Enabled = 1;
    cfg.TargetPid = 1234;
    if(DeviceIoControl(h, IOCTL_SET_CONFIG, &cfg, sizeof(cfg), NULL, 0, &bytes, NULL)) {
        printf("SET_CONFIG ok (check DebugView for the driver log)\n");
    } else {
        printf("SET_CONFIG failed: %lu\n", GetLastError());
    }

    CloseHandle(h);
    return 0;
}
