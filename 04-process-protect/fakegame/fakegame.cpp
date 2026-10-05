// fakegame.c  —  stands in for a protected game process.
// Holds a "secret" value in memory and prints its PID and address,
// then waits so another process can try to read it.

#include <windows.h>
#include <stdio.h>

int main(void) {
    // The value a cheat would want to read (e.g. health, coordinates).
    volatile int secret = 1337;

    printf("fakegame running\n");
    printf("  PID     : %lu\n", GetCurrentProcessId());
    printf("  &secret : %p\n", (void*)&secret);
    printf("  secret  : %d\n", secret);
    printf("\nLeave this running, then use reader.exe with the PID and address.\n");

    // Keep the process (and 'secret') alive.
    while(1) {
        Sleep(1000);
    }
    return 0;
}
