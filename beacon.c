// x86_64-w64-mingw32-gcc -shared -Wall -Wextra -fcf-protection -o beacon.dll beacon.c -lntdll
//
// Representative C2 beacon: a main loop plus a worker thread, each doing C2
// work and sleeping through a different import.  No knowledge of the masking
// layer.
//   main   -> Sleep()             (kernel32)   [trampoline A]
//   worker -> NtDelayExecution()  (ntdll)      [trampoline B]
// C2 traffic is a heap buffer the beacon zeroes after use (the heap is
// scoped out of the mask; zero-after-use is the beacon's job).

#include <windows.h>
#include <string.h>

LONG NTAPI NtDelayExecution(BOOLEAN Alertable, PLARGE_INTEGER DelayInterval);

__declspec(dllexport) volatile unsigned long long beacon_tick_count;

__declspec(dllexport) char beacon_config[] =
    "CONFIG:host=10.0.0.1;port=443;interval=60;key=DEADBEEF01234567";

// Simulated C2 exchange: take a tasking buffer, "send" it, zero it before it
// leaves the hot path.  Heap C2 data is not left at rest (the mask doesn't
// track heap; zero-after-use is the beacon's job).
static void c2_exchange(void) {
    char *buf = HeapAlloc(GetProcessHeap(), 0, 128);
    if (!buf) return;
    memcpy(buf, "TASKING:beacon;interval=15;channel=/api/v1",
           sizeof "TASKING:beacon;interval=15;channel=/api/v1");
    // (a real transport would read buf over the wire here)
    SecureZeroMemory(buf, 128);
    HeapFree(GetProcessHeap(), 0, buf);
}

static DWORD WINAPI worker(LPVOID a) {
    (void)a;
    for (;;) {
        c2_exchange();
        LARGE_INTEGER delay;
        delay.QuadPart = -1000LL * 10000LL;   // 1000 ms, relative
        NtDelayExecution(FALSE, &delay);
    }
    return 0;
}

__declspec(dllexport) void beacon_main(void) {
    CreateThread(NULL, 0, worker, NULL, 0, NULL);
    for (;;) {
        beacon_tick_count++;
        c2_exchange();
        Sleep(1500);
    }
}

BOOL WINAPI DllMain(HINSTANCE h, DWORD reason, LPVOID reserved) {
    (void)h; (void)reason; (void)reserved;
    return TRUE;
}
