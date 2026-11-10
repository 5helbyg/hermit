// x86_64-w64-mingw32-gcc -shared -Wall -Wextra -fcf-protection -o beacon.dll beacon.c
//
// Stand-in beacon: a loop that does work and sleeps.  It has no
// knowledge of the masking layer.  Any DLL whose IAT imports a sleep
// function works; this one just makes tick-counting easy to observe.

#include <windows.h>

__declspec(dllexport) volatile unsigned long long beacon_tick_count;

__declspec(dllexport) void beacon_main(void) {
    for (;;) {
        beacon_tick_count++;
        Sleep(1500);
    }
}

BOOL WINAPI DllMain(HINSTANCE h, DWORD reason, LPVOID reserved) {
    (void)h; (void)reason; (void)reserved;
    return TRUE;
}
