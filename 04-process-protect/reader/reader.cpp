// reader.c  —  stands in for an external cheat.
// Prompts for a PID and address, then tries to read that process's memory.

#include <windows.h>
#include <stdio.h>

int main(void) {
    DWORD pid = 0;
    unsigned long long addrVal = 0;

    printf("=== reader (external memory reader) ===\n");
    printf("target PID: ");
    if(scanf_s("%lu", &pid) != 1) {
        printf("bad PID input\n");
        printf("\nPress Enter to exit...");
        getchar();
        getchar();
        return 1;
    }

    printf("target address (hex, e.g. 7ff6abcd1234): ");
    if(scanf_s("%llx", &addrVal) != 1) {
        printf("bad address input\n");
        printf("\nPress Enter to exit...");
        getchar();
        getchar();
        return 1;
    }

    void* addr = (void*)addrVal;

    // Ask for the memory-read right — this is what the driver strips.
    HANDLE h = OpenProcess(PROCESS_VM_READ, FALSE, pid);
    if(h == NULL) {
        printf("OpenProcess failed: %lu\n", GetLastError());
        printf("\nPress Enter to exit...");
        getchar();
        getchar();
        return 1;
    }
    printf("OpenProcess OK (handle=%p)\n", h);

    int value = 0;
    SIZE_T bytesRead = 0;
    BOOL ok = ReadProcessMemory(h, addr, &value, sizeof(value), &bytesRead);
    if(ok) {
        printf("ReadProcessMemory OK: value = %d\n", value);
    } else {
        printf(
            "ReadProcessMemory FAILED: %lu  (this is what we want when protected)\n",
            GetLastError());
    }

    CloseHandle(h);

    printf("\nPress Enter to exit...");
    getchar();
    getchar();
    return 0;
}
