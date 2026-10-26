# Hermit — a CET-native sleep mask

Memory scanners (Moneta, pe-sieve, the scanning layer in most EDRs) look for
private, committed, RX pages that aren't backed by a module on disk. An
implant's shellcode region at rest matches that shape exactly.

The beacon spends most of its lifetime inside `Sleep()` waiting for the next
callback. That dwell time is when scanners look. Leave the payload in
plaintext at rest and you're betting no scanner runs during the sleep window.
Against EDR, that's not a good bet.

A sleep mask encrypts the region during sleep and decrypts it before use.
Simple idea, harder in practice: encrypted shellcode can't run itself, so
something else has to drive the encrypt/sleep/decrypt cycle, touch
`VirtualProtect`, host the `Sleep`, and trigger the decrypt without being an
IOC and without leaving the stack pointing at the encrypted region (the stack
gets scanned too).

## Prior work

- **gargoyle** (Lospinoso, 2017) — first public sleep mask: ROP + APC in `ntdll`, XOR flip. Set the pattern: encrypt at rest, decrypt on wake, stack off your own shellcode.
  - **YouMayPasser** (waldo-irc, 2022) — x64 reimplementation of gargoyle. Timer trigger instead of APC, `SetThreadContext` for start-address spoofing.
- **FOLIAGE** (SecIdiot, ~2021) — APC-queued ROP chain + `NtContinue` to restore context around an encrypted sleep window. Pre-Ekko.
  - **AceLdr** (Avery, 2022) — FOLIAGE mask inside a stomped module. Backing store looks like an image on disk, not private memory. Two IOCs down to one.
- **SleepyCrypt** (SolomonSklash, 2021) — inline encrypt → `Sleep` → decrypt on the current thread. No timer, no APC, no ROP, no context swap.
- **Ekko** (C5pider, 2022) — timer-queue callback, ROP chain in `ntdll`, RC4 via `SystemFunction032`, `NtContinue` back to the captured context. Stack never points at the beacon during sleep.
  - **Cronos** (Idov31, 2022) — explicit Ekko derivative. `WaitableTimer` + APC instead of timer-queue; `QuadSleep` ROP wrapper splits the sleep across four `SleepEx` calls to break stack-walk heuristics.
- **DeathSleep** (janoglezcampos, 2022) — terminates the thread during sleep and reconstructs it afterward. No live thread to inspect while the region is encrypted.

### The shared assumption

All of them treat the beacon as a passive object. Something is done to it
during sleep. The mask fabricates a stack that doesn't point into the beacon,
drives encrypt/sleep/decrypt via ROP, APC, or callback chains, and resumes
via `NtContinue`, `SetThreadContext`, `longjmp`, or a fiber switch. This
worked because for a long time nobody checked whether return addresses were
legitimate.

## CET

Intel's Control-flow Enforcement Technology keeps a second, protected copy
of the return-address stack. Every `ret` cross-checks the regular stack
against the shadow stack. Mismatch is a `#CP` fault, which kills the
process. On Windows 11 24H2 it's on by default for compatible processes.

For the existing canon this is bad news:

- **ROP breaks.** Each gadget `ret`s to an address pushed by hand, not by a
  matching `call`. The shadow stack has no record of it.
- **`NtContinue` breaks the pairing.** Resuming into a captured context means
  `ret`ing to an address the shadow stack didn't push.
- **Stack spoofing creates mismatches by design.** The whole point of
  spoofing is that the regular stack lies; the shadow stack tells the truth.

You can disable CET for your process (`SetProcessMitigationPolicy`), but
that call is observable and reveals intent. You can manipulate the shadow
stack (`NtContinueEx`, `WRSS`), but those are novel enough to be their own
IOC.

## The technique

The different assumption: the beacon cooperates. It `ret`s out of the
region before it sleeps, so the stack is clean without any machinery to make
it look clean. Everything else follows from that. I'm uploading two examples.
Each with different goals. Hermit.c is more about the technique. The
hardened version is one example that uses different tradeoffs. Same core
mechanics with different signatures.

### The contract

One line:

```
call in -> ret out -> signal cold -> sleep
```

The beacon `call`s into the shellcode region. The payload runs and `ret`s
out. The beacon signals a dedicated masker thread via an auto-reset Event,
then sleeps. The loop:

```c
for (;;) {
    ((void(*)(void))region)();   // call in, ret out
    SetEvent(g_evt_sleep);      // signal cold
    Sleep(ms);                  // region now masked
}
```

The masker, blocked on that Event, wakes and encrypts the region. The
beacon sleeps with the region encrypted. On wake, the region decrypts either
lazily through a VEH on the beacon's next `call` into it, or eagerly on a
schedule.

### Why the stack is clean

The beacon `ret`'d out of the region before it signaled the masker. During
sleep:

- The beacon's RIP is in `ntdll` inside `NtDelayExecution`, not in the region.
- The beacon's stack is the natural call chain down to `Sleep`. No frame
  points into the region.
- The masker's stack is the natural call chain down to
  `WaitForSingleObjectEx` and into the encrypt routine. It operates on the
  region but isn't called from it.

Nothing points anywhere incriminating. No ROP chain, no spoofer, no unwind.
The stack is clean because it's clean, not because something made it look
that way.

The concession is small: the beacon must be a loop that calls into a payload
region and returns, not a blob that runs inside the region directly. That's
a loader concern, not a payload concern.

### Why CET is satisfied

Walk the wake path with the region still encrypted:

1. The loop executes `call [region]`.
2. `call` pushes the return address onto both the regular and shadow stacks.
3. RIP sets to the region start. The instruction fetch faults (the page is
   RW, not RX).
4. The VEH runs on the faulting thread, wins a CAS on the state, decrypts,
   flips back to RX, returns `EXCEPTION_CONTINUE_EXECUTION`.
5. The CPU retries the fetch. The instruction is now valid, decrypted.
6. The payload runs and eventually `ret`s.
7. `ret` pops both stacks. They match because both were pushed by the same
   `call`.

CET sees a call/ret pair. No reconciliation needed because the shadow stack
never diverged from the regular one. Ekko's wake path `NtContinue`s into a
captured RIP via `iret`, bypassing the push/pop pairing. Under CET that's
dead. Hermit's wake is just a `ret` matching a `call`.

The VEH does real work (decrypt, flip protections) but no control-flow work.
It doesn't fabricate a return or touch either stack. It decrypts and tells
the CPU to retry the beacon's own `call` target following its own `call`.

## Implementation

### Event-driven, not timer-driven

Prior masks need a timer queue as an external scheduler. Timer-queue
registration shows up in ETW. Hermit uses one auto-reset Event signaled by
the beacon. No timer queue, no periodic callbacks.

### One decrypt path

Both wake routes (lazy VEH, scheduled) converge on the same `decrypt()`.
Four states (plain / masked / decrypting / masking), CAS-guarded. Only the
thread that wins the CAS touches protections. Less surface, fewer edge
cases.

### Thin VEH

VEH chains are enumerable. A chatty handler with strings, logging, or CRT
calls is its own signature. Hermit's resolves syscalls up front, uses no
CRT, does no I/O, runs a tight state machine.

### Per-cycle rekeying

A static key means identical ciphertext every cycle. That's known-plaintext
recovery territory, and two snapshots from different sleeps diff
byte-for-byte, confirming "something at rest, same bytes, changes between
runtime moments." Hermit generates a fresh key per cycle, stores it only
while masked, and zeroes it on decrypt.

### Metadata hiding

Globals holding base, length, and key defeat the whole exercise. Hermit
allocates the descriptor on the heap and keeps a cookie-XOR'd pointer in
the global. Finding the descriptor means finding and un-XORing the cookie,
which means analyzing the binary, not reading globals.

### Decommit mode

Besides the default flip-to-RW, Hermit supports decommit: stash ciphertext
in a staging buffer, then `VirtualFree(..., MEM_DECOMMIT)` the region. During
sleep the VAD shows reserved and a scanner reading the range gets nothing.
Trades `VirtualProtect` churn for VAD churn. (Only on pages Hermit owns;
image pages can't be decommitted.)

### Churn knobs

Once static IOCs are gone, defenders correlate behavior. `VirtualProtect` at
a steady two-second cadence is a signal even if each call is innocuous.
Knobs:

- `jitter_ms` — randomized sleep duration (`base + prng % jitter`)
- `min_sleep_ms` — don't mask sleeps shorter than this (masking has overhead;
  cheap short sleeps aren't worth the churn)
- `coverage_n` — mask every Nth sleep, not every one
- `mode` — flip vs decommit
- `wake_on_demand` — VEH-triggered decrypt vs scheduled, different telemetry
  shape

The goal: deny stable features for correlation. If every tenth sleep is
masked, with jittered duration, in one of two modes, the shape varies across
operational time in ways that look more like noisy legitimate software than
a periodic implant.

## Costs

- **Cooperative beacon required.** The technique rests on the beacon obeying
  the contract. If your C2's beacon runs directly inside the region rather
  than as a loop that calls into it, you rework the loader. Prior masks
  worked with unmodified beacons; Hermit doesn't.
- **VEH registration is observable.** `AddVectoredExceptionHandler` at
  startup; handlers are enumerable. Smaller surface than ROP-driven
  alternatives, but not zero.
- **Extra thread.** One more entry in the thread list, one more target for
  behavioral analysis.
- **First-cycle wake latency.** The lazy path pays a decrypt cost on the
  first call after sleep. Negligible for most callbacks, non-zero.

What Hermit replaces: ROP chains, stack spoofing, `NtContinue`, timer queues,
shadow-stack reconciliation, fiber tricks. Where CET is enforced, that's a
clear win. Where it isn't, the simplification is still useful but not
uniquely necessary.

## Future work

- **IBT.** Indirect Branch Tracking is the other half of CET: indirect-call
  targets must start with `endbr64`. For Hermit this is a payload concern;
  prefix the region's first instruction with `endbr64` (`f3 0f 1e fa`).
  Orthogonal to the mask.
- **Direct syscalls.** The current build calls `NtProtectVirtualMemory`
  through `ntdll`. A hardened build would use syscall stubs to bypass
  user-mode hooks.
- **Multi-region.** Hermit protects one region. A real beacon has shellcode,
  strings, heap buffers, and C2 state, each with different lifetimes. A
  production build would mask multiple regions, potentially with different
  keys and modes.
- **Framework integration.** Sliver, Havoc, and custom C2s could adopt the
  contract. Small engineering, large architectural win.