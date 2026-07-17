# PVM2 portability: what assumptions does the recompiler make?

PVM2 today has exactly one JIT backend: x86-64 Linux running inside
a Hyperlight microkernel. The interpreter (`nub-exec::interp`) is
host-arch-independent and runs anywhere Rust does. But the
production-path JIT in `nub-arch-x86` makes a number of assumptions
about its host arch; if we ever build a second backend (AArch64 is
the obvious next target, RISC-V a more speculative one), we'll have
to satisfy each of those assumptions explicitly.

This document enumerates them and walks through how each holds on
the three hosts we might plausibly target: **x86-64** (today),
**AArch64** (likely next, both Linux servers and Apple Silicon), and
**RISC-V** (future-proofing only — no concrete plan).

The headline finding: PVM2's spec-level assumptions are all
defensible across the targets we care about. The work in porting to a
second host is dominated by rewriting the asm/codegen, not by spec
incompatibilities.

## Two categories of assumption

We separate them because they have different implications:

- **Spec-level assumption**: encoded in the guest blob. Every
  conforming JIT must implement it. A change here is an ISA change
  (= breaking + chain-coordinated).
- **Host-implementation assumption**: only the current x86 backend
  relies on it. A future port can solve it differently with no spec
  impact.

## Spec-level assumptions

These are the contract between guest blobs and any conforming
host. They show up in the wire format, the addressing model, or the
encoding choices in [`rv64e-xjar-eei.md`](rv64e-xjar-eei.md).

| # | Assumption | Where it shows up | Constrains what hosts? |
|---|---|---|---|
| S1 | 32-bit guest address space (4 GiB cap) | `addr & 0xFFFFFFFF` on every load/store (§Memory address space) | Any host that can provide 4 GiB of contiguous virtual address space — universal |
| S2 | Little-endian memory | RV-inherited | Any LE host (x86, ARM LE, RV LE) — universal in practice |
| S3 | No atomics, no concurrency within an invocation | `max-atomic-width: 0`, A extension reserved | Any single-threaded execution model; no host constraint |
| S4 | No floating point | F/D/Q/V reserved | Universal |
| S5 | Unaligned scalar loads/stores succeed | Zicclsm declared (§4.13) | Host must lower unaligned RV loads — see "Unaligned access" below |
| S6 | 15 logical registers (RV64E: x1, x2, x5..x15 + x3, x4) | RV64E reg file | Host MUST provide ≥ 13 GPRs; the 13 hot slots are register-resident, x3/x4 may be host-spilled (gas-charged at spill cost). See "Register floor" below |
| S7 | Code mapped read-only at `CODE_BASE` in the low 4 GiB; PC is a real virtual address | `auipc`/`jalr` resolution, PIC code reads | Host must map the code region RO inside the guest's 4 GiB window — universal |
| S8 | Branch/`jalr` targets are basic-block starts (ϖ); `jalr` validated at runtime | Linker invariant (branches) + runtime check (`jalr`) | No host implication |
| S9 | Memory layout in `Image.memory_mappings` is byte-granular but page-aligned | Transpiler emits 4 KiB-aligned regions today | Host page size — see "Page size" below |

### Page size (S9)

The transpiler currently aligns mappings to 4 KiB. This is **not** a
host-page-size assumption — it's a transpiler layout choice. The
production execution stack always interposes a microkernel between
the PVM2 guest and the OS host:

```
┌────────────────────────────────────────────┐
│ host OS  (whatever page size it picks)     │
├────────────────────────────────────────────┤
│ hypervisor / VM monitor                    │
│   sets stage-2 (IPA → host PA) granule     │
├────────────────────────────────────────────┤
│ nub microkernel (we own this layer)        │
│   sets stage-1 (guest VA → IPA), picks     │
│   4 KiB pages, programs TTBR/CR3           │
├────────────────────────────────────────────┤
│ JIT'd PVM2 guest code                      │
└────────────────────────────────────────────┘
```

On x86 the nub-arch-x86 microkernel programs page tables directly
with 4 KiB pages, regardless of the host OS's choice. On AArch64
under Apple Silicon's Hypervisor.framework, the same separation
holds: `TCR_EL1.TG0` is a guest register set by our nub, independent
of the host's stage-2 IPA granule. We can run 4 KiB stage-1 pages
even when the macOS host uses 16 KiB pages and the IPA granule is
16 KiB. The hardware MMU walks both stages and produces correct
translations.

Verified for AArch64-on-macOS in May 2026:
[Apple's `hv_vm_config_set_ipa_granule()`](https://developer.apple.com/documentation/hypervisor)
(public API in macOS 26, private API previously) lets the host set
the IPA granule to 4 KiB; the guest's stage-1 page size is fully
under our control regardless.

The performance footnote: 4 KiB stage-1 on Apple Silicon means more
TLB pressure than the native 16 KiB. Bench-driven decision when we
get there, not a portability blocker.

### Unaligned access (S5)

Spec-level we declare Zicclsm, meaning every conforming guest is
allowed to emit unaligned scalar loads/stores. Hosts must lower these
correctly — performance is host-implementation territory.

- **x86-64**: hardware-native unaligned. Free at cacheline-internal
  alignments; ~1 cycle for cacheline crossings. We get the full
  LLVM `+unaligned-scalar-mem` benefit (keccak code −44%, blake2b
  code −16%, cold times down 12–21% on hashers).
- **AArch64**: hardware-native unaligned on cacheable memory. Some
  atomicity is lost on misaligned (torn reads possible), but we
  have no atomics so that's moot.
- **RISC-V**: implementation-dependent. The
  [RVA22 and RVA23 profiles](https://github.com/riscv/riscv-profiles/blob/main/src/rva23-profile.adoc)
  both mandate Zicclsm — meaning all application-class RISC-V
  designed from 2022 onwards supports unaligned access. The spec
  warns it *might* be slow (a host may handle it in microcode or
  via M-mode trap-and-emulate), but it's always *correct*. In
  practice:
  - SiFive U74 / U54 (HiFive Unmatched, VisionFive 2): hardware-fast.
  - Spacemit K1, JH7110: hardware-handled but multi-cycle.
  - First-gen RVA23 silicon (SiFive P570 Gen3, Tenstorrent Ascalon,
    Ventana Veyron V2) shipping mid-2026: hardware-fast by design.

  Pre-RVA22 embedded RISC-V (RP2350 RP2040, BL808, K210) may
  trap-and-emulate or fault outright. We would never JIT to these —
  they lack the MMU, memory bandwidth, and code-cache reach the
  recompiler relies on for hosting anyway.

The trajectory is unambiguous: the application-processor RISC-V
ecosystem is consolidating around RVA23 (Ubuntu 25.10 mandates it,
Android-on-RISC-V targets it, NVIDIA's CUDA RISC-V port targets it).
Any host we'd realistically JIT to will support unaligned access.

### Register floor and x3/x4 spill (S6)

PVM2 has RV64E's full **15** GPRs (`x1`, `x2`, `x5`–`x15`, plus `x3`,
`x4`). A conforming host must provide at least **13** general-purpose
registers for the guest file:

- The **13 hot slots** (`x1`, `x2`, `x5`–`x15`) are **register-resident
  on every conforming host**. They are what the jar toolchain emits, so
  conformant guest code is fully register-mapped everywhere.
- `x3` and `x4` are **not** guaranteed register-resident. A host with
  exactly 13 GPRs (today's x86-64 backend, after reserving registers for
  the gas meter, scratch, and the native stack) holds them in memory and
  **spills** on each access. A host with ≥ 15 free GPRs (AArch64, RISC-V)
  may keep them resident with no spill.

Because the *worst-case* conforming host spills them, **x3/x4 accesses are
gas-charged at memory-spill cost unconditionally** — on every host,
whether or not it actually spills (see
[gas-cost.md](gas-cost.md)). Gas is a spec-fixed upper
bound, so a register-rich host runs faster than charged without affecting
consensus. This keeps the register count a *conformance* property (any
valid RV64E blob runs) while pinning the host requirement at a portable
floor of 13.

The jar toolchain does not emit x3/x4, so this spill path is reached only
by untrusted RV64E blobs — never by jar's own guests, whose hot paths stay
fully register-mapped on every host.

## Host-implementation assumptions (nub-arch-x86 today)

These are properties the current x86 backend exploits. A second
backend would have to satisfy each, but how it does so is local —
no spec change, no impact on the guest blob format.

| # | Assumption | x86-64 today | AArch64 cost | RISC-V cost |
|---|---|---|---|---|
| H1 | Host can mmap the low 4 GiB at fixed VAs | `MAP_FIXED` under Hyperlight; PVM addr == native VA | Same trick works | Same trick works |
| H2 | Hardware MMU with mprotect-style perms | mprotect / EPT | mprotect / stage-2 perms | mprotect / PMP (M-mode) |
| H3 | Trap-on-fault with recoverable PC (SIGSEGV / #PF) | SIGSEGV handler reads RIP from mcontext | SIGSEGV reads PC from mcontext; same model | RV trap frame reads `sepc`; same model |
| H4 | Coherent I-cache (no flush after writing JIT code) | Free on x86 | **Must add `dc cvau; ic ivau; dsb; isb`** after each code emission | **Must add `fence.i`** after each code emission |
| H5 | TSO / strong memory ordering for context fields (gas, exit_reason) | Free on x86 | **May need `dmb`** at exit points | **May need `fence`** at exit points |
| H6 | Native CALL/RET use a single downward stack | RSP, host_rsp_base | SP + LR (similar) | SP + RA (similar) |
| H7 | Sys V AMD64 ABI for helper-fn calls | Built into asm.rs | Needs AAPCS port | Needs RV ABI port |
| H8 | ±2 GiB RIP-relative reach for `CTX_VA` | x86 RIP-rel disp32 | AArch64 ADRP+ADD (±4 GiB) — works | RV AUIPC+offset (±2 GiB) — works |
| H9 | Hand-written x86-64 machine code emitter | `asm.rs` ~2 KLOC, `codegen.rs` ~3 KLOC | Full rewrite per arch | Full rewrite per arch |

The dominant cost in any port is H9 — rewriting the asm emitter and
per-opcode codegen. The "silent killers" are H4 and H5: on AArch64
or RISC-V, omitting an I-cache flush after JIT emission causes
intermittent miscompiles that look like memory corruption; omitting
a memory barrier on context writes causes torn reads of gas /
exit_reason that look like scheduler bugs. These are easy to forget
because x86 hides them.

## Per-arch port readiness

### x86-64 — current target
Everything works. Production path.

### AArch64 — most likely second target
Spec-level: clean. The unaligned-access and 4 KiB-page concerns
both dissolve as detailed above.

Host-level: the rewrite of `asm.rs` and `codegen.rs` is the bulk of
the work. The I-cache flush and memory-barrier additions (H4, H5)
are small but mandatory. Apple Silicon under Hypervisor.framework
needs the IPA-granule plumbing (4 KiB on macOS 26+; 16 KiB IPA with
4 KiB stage-1 on older macOS — both work).

Estimated effort: 3–6 weeks for a skilled JIT engineer to land a
working backend, plus another similar period for performance parity
with x86.

### RISC-V — speculative future target
RV→RV translation is the niche case. Possible cases:

- A RISC-V validator wanting to run PVM2 chain code natively. The
  host RISC-V (RVA23+) supports everything the guest needs.
- A "RISC-V everywhere" deployment where we want to avoid the
  emulator-translator-host stack and have the host arch match the
  guest arch.

Spec-level: clean, contingent on host being RVA22+ (= Zicclsm
guaranteed). Pre-RVA22 embedded RISC-V is not a target.

Host-level: same H1–H9 list as AArch64, with RISC-V instead of
ARMv8 mechanics. The interesting bit is H9 — emitting RV machine
code from a RV-based source. Much of the codegen could lower 1:1
(register-to-register moves, ALU ops) since both guest and host
share the same instruction set; the work shifts toward managing the
host's view of "guest memory" (since you can't rely on the host's
MMU configuring a 1:1 low-4GiB map identical to x86's setup).

Estimated effort: 4–8 weeks for the JIT, with the host-OS
integration likely the bigger unknown (less mature tooling than
on x86 / AArch64).

## What this means for current decisions

The portability audit feeds back into a couple of present-day spec
choices:

1. **Zicclsm in the PVM2 ISA**: justified by S5 + the RVA22/RVA23
   trajectory. The cost of declaring it (zero on x86 / AArch64;
   slight slowdown on theoretical pre-RVA22 RV hosts that we'd
   never deploy on) is dominated by the gain (LLVM emits dense
   unaligned scalar loads instead of byte-load sequences).

2. **Memory mapping byte granularity vs page units**: the current
   transpiler emits 4 KiB-aligned byte addresses. If we ever want
   to support hosts where the *nub itself* needs to run with
   non-4-KiB pages (e.g., a future "everything in 16 KiB pages"
   nub-arch-aarch64-mac variant for TLB-perf reasons), we'd want
   the spec to express layouts in abstract pages with the JIT
   applying the host page size. **Not required today** — every
   target we've examined can run the nub with 4 KiB stage-1
   pages — but worth flagging as a clean follow-on if we ever
   measure significant TLB pressure on a new host.

3. **`asm.rs` modularity**: the eventual second backend will
   exercise how cleanly the codegen separates from the
   x86-specific instruction emission. If we know we're going to
   port to AArch64, mid-term refactoring of `codegen.rs` to
   abstract the per-arch primitives (load-imm-into-reg, branch,
   memory access with bounds check) would amortise the port cost.
   No urgency until we commit to the second backend.
