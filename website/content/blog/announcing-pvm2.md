---
title: "Announcing PVM2: Reimagining PVM towards standard RISC-V"
date: 2026-05-28T00:00:00Z
authors:
  - name: sorpaas
    link: https://github.com/sorpaas
    image: https://github.com/sorpaas.png
tags: [pvm, pvm2, jar, risc-v]
---

### Background

PVM is the instruction set architecture (ISA) of PolkaVM. This is the planned ISA to be deployed on the JAM Chain, advertised to be fast. In March, we started [Grey](https://forum.polkadot.network/t/announcing-grey-0-1-llm-tries-to-build-a-jam-node-implementation/17284) (later known as [JAR](https://jarchain.org)). JAR's virtual machine JAVM is based on PVM ISA, and we managed to accomplish a [2x speed up](https://jarchain.org/benchmark/) for many of our PVM workloads compared with PolkaVM.

Our design has diverged a lot from JAM, challenging many of the JAM's design rationales. We have since had, notably, a capability-based system and a real kvm microkernel which give us some impressive performance results and security properties. But until recently, we still kept PVM ISA almost unmodified.

The PVM ISA is the part we think that is also worth some deep thinking for us. PVM ISA has an entirely custom encoding definition. So we asked ourselves a simple question: do we really need it? If we move PVM towards a mostly standard-compliant RISC-V, can we get the same performance?

### Specification: Defining PVM2

So we designed **PVM2**. A new ISA that is kept as close to the RISC-V spec as possible. How we define it is like this. We define a new base ISA. Supposedly, this will be the only thing we want to modify. Then we apply RISC-V extensions cleanly on top.

Our entire base ISA is defined as a short differential from RV64E, with just the following changes:

* Memory address space
* New meaning of `pc`
* Disabled `auipc`, `jalr` (and `c.jalr`).
* Standard-compliant `custom-0` RISC-V instructions, `trap`, `ecall.jar`, `ecalli.jar`, `br_table` and `fallthrough`.

That's basically it.

We then apply unmodified standard RISC-V extensions: `m`, `c`, `zbb`, `zba`, `zbs`, `zicond`, `zicclsm`.

### Rationale: Future-proofing the spec

Some of the designs in PVM is questionable, or at least, debatable. An example is `bitmask`, which bloats the binary size by 12.5%. Supposedly, this is for random access to the program. Yet, the new gas metering requires a pre-validation round, completely defeating the purpose. There's no flexibility in any of this: as an ISA spec, you either have it, or you do not. The middle ground is the worst of all places.

One of the rationales for PVM2 is to side-step this. We use the standard whenever possible. Avoid reinventing the wheels when it's not necessary.

A mostly-standard RISC-V ISA also has significant advantage in its tooling: if LLVM ships any optimizations, we get it immediately. No bikeshedding with the transpiler to "re-support". In addition, even our `custom-0` instructions are defined in a standard-compliant way. This means we can easily utilize, for example, Rust's `asm` macro, in a way that is not straightforward on PVM.

Our design also allows us to support new RISC-V extensions at ease.

### Findings: You don't need PVM

Our findings are quite clear: you don't need PVM – we implemented the PVM2 ISA for JAVM, and managed to get a recompiler that is as fast as the old custom ISA. Our benchmark results are as follows.

<style>
.pvm2-bench {
  --pb-ink: #14161a;
  --pb-ink-soft: #5a5e66;
  --pb-ink-muted: #8a8d94;
  --pb-rule: #e4e3dd;
  --pb-rule-soft: #f1f0ea;
  --pb-pvm: #b8b6ad;
  --pb-pvm2: #14161a;
  --pb-polka: #d8d6cd;
  --pb-accent: #2c9c5a;
  --pb-warn: #c97a2e;
  color: var(--pb-ink);
  font-variant-numeric: tabular-nums;
  margin: 24px 0 32px;
}
html.dark .pvm2-bench {
  --pb-ink: #f1efe8;
  --pb-ink-soft: #a8aab0;
  --pb-ink-muted: #6a6c72;
  --pb-rule: #2a2c31;
  --pb-rule-soft: #1c1e22;
  --pb-pvm: #4a4c52;
  --pb-pvm2: #f1efe8;
  --pb-polka: #2c2e34;
  --pb-accent: #6dd58c;
  --pb-warn: #d99a4c;
}
.pvm2-bench * { box-sizing: border-box; }
.pvm2-bench .mono {
  font-family: ui-monospace, "SF Mono", Menlo, monospace;
}

.pvm2-bench .legend {
  display: flex; flex-wrap: wrap; gap: 18px;
  font-family: ui-monospace, "SF Mono", Menlo, monospace;
  font-size: 11px;
  letter-spacing: 0.04em;
  text-transform: uppercase;
  color: var(--pb-ink-muted);
  padding-bottom: 10px;
}
.pvm2-bench .legend span { display: inline-flex; align-items: center; gap: 8px; }
.pvm2-bench .legend i {
  display: inline-block; width: 16px; height: 4px; border-radius: 1px;
}
.pvm2-bench .legend i.pvm2  { background: var(--pb-pvm2); }
.pvm2-bench .legend i.pvm   { background: var(--pb-pvm); }
.pvm2-bench .legend i.polka { background: var(--pb-polka); border: 1px solid var(--pb-rule); }

.pvm2-bench .col-headers {
  display: grid;
  grid-template-columns: 140px 1fr 80px;
  gap: 20px;
  padding: 0 0 10px;
  font-family: ui-monospace, "SF Mono", Menlo, monospace;
  font-size: 10px;
  letter-spacing: 0.12em;
  text-transform: uppercase;
  color: var(--pb-ink-muted);
}
.pvm2-bench .col-headers .bars-head {
  display: grid; grid-template-columns: 96px 1fr 64px; gap: 12px;
}
.pvm2-bench .col-headers .bars-head span:nth-child(3) { text-align: right; }
.pvm2-bench .col-headers .speedup-head { text-align: right; }

.pvm2-bench .bench-row {
  display: grid;
  grid-template-columns: 140px 1fr 80px;
  gap: 20px;
  align-items: center;
  padding: 10px 0;
  border-top: 1px solid var(--pb-rule);
}
.pvm2-bench .bench-row:last-child { border-bottom: 1px solid var(--pb-rule); }

.pvm2-bench .bench-name { display: flex; flex-direction: column; gap: 2px; }
.pvm2-bench .bench-name .label {
  font-family: ui-monospace, "SF Mono", Menlo, monospace;
  font-size: 13px;
  font-weight: 500;
  color: var(--pb-ink);
}
.pvm2-bench .bench-name .kind {
  font-family: ui-monospace, "SF Mono", Menlo, monospace;
  font-size: 10px;
  letter-spacing: 0.1em;
  text-transform: uppercase;
  color: var(--pb-ink-muted);
}

.pvm2-bench .bars { display: flex; flex-direction: column; gap: 4px; }
.pvm2-bench .bar-line {
  display: grid;
  grid-template-columns: 96px 1fr 64px;
  gap: 12px;
  align-items: center;
}
.pvm2-bench .bar-tag {
  font-family: ui-monospace, "SF Mono", Menlo, monospace;
  font-size: 10.5px;
  color: var(--pb-ink-soft);
  white-space: nowrap;
}
.pvm2-bench .bar-track {
  height: 10px;
  background: transparent;
  position: relative;
}
.pvm2-bench .bar-fill {
  height: 100%;
  border-radius: 1px;
  min-width: 1px;
}
.pvm2-bench .bar-fill.pvm   { background: var(--pb-pvm); }
.pvm2-bench .bar-fill.pvm2  { background: var(--pb-pvm2); }
.pvm2-bench .bar-fill.polka { background: var(--pb-polka); }
.pvm2-bench .bar-value {
  font-family: ui-monospace, "SF Mono", Menlo, monospace;
  font-size: 12px;
  text-align: right;
  color: var(--pb-ink);
}
.pvm2-bench .bar-value .unit { color: var(--pb-ink-muted); margin-left: 2px; }

.pvm2-bench .speedup {
  text-align: right;
  display: flex; flex-direction: column; align-items: flex-end; gap: 2px;
}
.pvm2-bench .speedup-x {
  font-size: 20px;
  font-weight: 600;
  letter-spacing: -0.02em;
  line-height: 1;
}
.pvm2-bench .speedup-x .x {
  color: var(--pb-ink-muted);
  font-size: 11px;
  font-weight: 500;
  margin-left: 1px;
}

.pvm2-bench table.data-table {
  width: 100%;
  border-collapse: collapse;
  font-family: ui-monospace, "SF Mono", Menlo, monospace;
  font-size: 12.5px;
  margin: 0;
  background: transparent;
}
.pvm2-bench table.data-table thead th {
  text-align: right;
  padding: 10px 12px;
  font-weight: 500;
  font-size: 10px;
  letter-spacing: 0.12em;
  text-transform: uppercase;
  color: var(--pb-ink-muted);
  border-bottom: 1px solid var(--pb-rule);
  white-space: nowrap;
  background: transparent;
}
.pvm2-bench table.data-table thead th:first-child { text-align: left; padding-left: 0; }
.pvm2-bench table.data-table thead th:last-child { padding-right: 0; }
.pvm2-bench table.data-table tbody td {
  text-align: right;
  padding: 9px 12px;
  border-top: 1px solid var(--pb-rule);
  color: var(--pb-ink);
  background: transparent;
}
.pvm2-bench table.data-table tbody td:first-child {
  text-align: left;
  padding-left: 0;
  font-weight: 500;
}
.pvm2-bench table.data-table tbody td:last-child { padding-right: 0; }
.pvm2-bench table.data-table tfoot td {
  border-top: 1px solid var(--pb-ink);
  padding: 12px;
  text-align: right;
  font-weight: 600;
  background: transparent;
}
.pvm2-bench table.data-table tfoot td:first-child { text-align: left; padding-left: 0; }
.pvm2-bench table.data-table tfoot td:last-child  { padding-right: 0; }
.pvm2-bench .data-table .unit  { color: var(--pb-ink-muted); margin-left: 2px; font-weight: 400; }
.pvm2-bench .data-table .delta.good { color: var(--pb-accent); }
.pvm2-bench .data-table .delta.bad  { color: var(--pb-warn); }
.pvm2-bench .data-table .ratio-cell { color: var(--pb-ink-soft); white-space: nowrap; }
.pvm2-bench .data-table .ratio-bar {
  display: inline-block;
  width: 56px;
  height: 6px;
  background: var(--pb-rule-soft);
  border-radius: 1px;
  overflow: hidden;
  vertical-align: middle;
  margin-right: 8px;
}
.pvm2-bench .data-table .ratio-bar > span {
  display: block;
  height: 100%;
  background: var(--pb-pvm2);
  border-radius: 1px;
}
.pvm2-bench .data-table .ratio-bar.shrink > span { background: var(--pb-accent); }

@media (max-width: 720px) {
  .pvm2-bench .col-headers { display: none; }
  .pvm2-bench .bench-row { grid-template-columns: 1fr 70px; gap: 12px; }
  .pvm2-bench .bench-name { grid-column: 1 / 2; }
  .pvm2-bench .speedup    { grid-column: 2 / 3; }
  .pvm2-bench .bars       { grid-column: 1 / -1; order: 3; }
  .pvm2-bench .bar-line   { grid-template-columns: 84px 1fr 56px; gap: 8px; }
  .pvm2-bench table.data-table { font-size: 11.5px; }
  .pvm2-bench table.data-table thead th,
  .pvm2-bench table.data-table tbody td,
  .pvm2-bench table.data-table tfoot td { padding: 8px 6px; }
  .pvm2-bench .data-table .ratio-bar { width: 36px; }
}
</style>

#### Benchmarking comparison

We measured recompile + execute time. JAVM (PVM2) runs as fast as JAVM (PVM) on most workloads. And JAVM (PVM) itself is around 2x faster than PolkaVM.

<div class="pvm2-bench not-prose">
  <div class="legend">
    <span><i class="pvm2"></i>JAVM (PVM2)</span>
    <span><i class="pvm"></i>JAVM (PVM)</span>
    <span><i class="polka"></i>PolkaVM (PVM)</span>
  </div>
  <div class="col-headers">
    <span>Workload</span>
    <div class="bars-head">
      <span>Runtime</span><span></span><span>Time</span>
    </div>
    <span class="speedup-head">× vs PolkaVM</span>
  </div>

  <div class="bench-row">
    <div class="bench-name"><span class="label">prime_sieve</span><span class="kind">arithmetic</span></div>
    <div class="bars">
      <div class="bar-line"><span class="bar-tag">JAVM (PVM)</span><div class="bar-track"><div class="bar-fill pvm" style="width:53.9%"></div></div><span class="bar-value">190.2<span class="unit">µs</span></span></div>
      <div class="bar-line"><span class="bar-tag">JAVM (PVM2)</span><div class="bar-track"><div class="bar-fill pvm2" style="width:79.7%"></div></div><span class="bar-value">281.5<span class="unit">µs</span></span></div>
      <div class="bar-line"><span class="bar-tag">PolkaVM (PVM)</span><div class="bar-track"><div class="bar-fill polka" style="width:100%"></div></div><span class="bar-value">353.0<span class="unit">µs</span></span></div>
    </div>
    <div class="speedup"><span class="speedup-x">1.25<span class="x">×</span></span></div>
  </div>

  <div class="bench-row">
    <div class="bench-name"><span class="label">keccak</span><span class="kind">hash</span></div>
    <div class="bars">
      <div class="bar-line"><span class="bar-tag">JAVM (PVM)</span><div class="bar-track"><div class="bar-fill pvm" style="width:43.9%"></div></div><span class="bar-value">61.4<span class="unit">µs</span></span></div>
      <div class="bar-line"><span class="bar-tag">JAVM (PVM2)</span><div class="bar-track"><div class="bar-fill pvm2" style="width:43.2%"></div></div><span class="bar-value">60.5<span class="unit">µs</span></span></div>
      <div class="bar-line"><span class="bar-tag">PolkaVM (PVM)</span><div class="bar-track"><div class="bar-fill polka" style="width:100%"></div></div><span class="bar-value">140.0<span class="unit">µs</span></span></div>
    </div>
    <div class="speedup"><span class="speedup-x">2.31<span class="x">×</span></span></div>
  </div>

  <div class="bench-row">
    <div class="bench-name"><span class="label">blake2b</span><span class="kind">hash</span></div>
    <div class="bars">
      <div class="bar-line"><span class="bar-tag">JAVM (PVM)</span><div class="bar-track"><div class="bar-fill pvm" style="width:36.7%"></div></div><span class="bar-value">101.4<span class="unit">µs</span></span></div>
      <div class="bar-line"><span class="bar-tag">JAVM (PVM2)</span><div class="bar-track"><div class="bar-fill pvm2" style="width:37.7%"></div></div><span class="bar-value">104.0<span class="unit">µs</span></span></div>
      <div class="bar-line"><span class="bar-tag">PolkaVM (PVM)</span><div class="bar-track"><div class="bar-fill polka" style="width:100%"></div></div><span class="bar-value">276.0<span class="unit">µs</span></span></div>
    </div>
    <div class="speedup"><span class="speedup-x">2.65<span class="x">×</span></span></div>
  </div>

  <div class="bench-row">
    <div class="bench-name"><span class="label">goldilocks_mul</span><span class="kind">field</span></div>
    <div class="bars">
      <div class="bar-line"><span class="bar-tag">JAVM (PVM)</span><div class="bar-track"><div class="bar-fill pvm" style="width:98.2%"></div></div><span class="bar-value">521.4<span class="unit">µs</span></span></div>
      <div class="bar-line"><span class="bar-tag">JAVM (PVM2)</span><div class="bar-track"><div class="bar-fill pvm2" style="width:85.3%"></div></div><span class="bar-value">452.9<span class="unit">µs</span></span></div>
      <div class="bar-line"><span class="bar-tag">PolkaVM (PVM)</span><div class="bar-track"><div class="bar-fill polka" style="width:100%"></div></div><span class="bar-value">531.0<span class="unit">µs</span></span></div>
    </div>
    <div class="speedup"><span class="speedup-x">1.17<span class="x">×</span></span></div>
  </div>

  <div class="bench-row">
    <div class="bench-name"><span class="label">ed25519</span><span class="kind">signature</span></div>
    <div class="bars">
      <div class="bar-line"><span class="bar-tag">JAVM (PVM)</span><div class="bar-track"><div class="bar-fill pvm" style="width:75.5%"></div></div><span class="bar-value">1.02<span class="unit">ms</span></span></div>
      <div class="bar-line"><span class="bar-tag">JAVM (PVM2)</span><div class="bar-track"><div class="bar-fill pvm2" style="width:47.7%"></div></div><span class="bar-value">644.6<span class="unit">µs</span></span></div>
      <div class="bar-line"><span class="bar-tag">PolkaVM (PVM)</span><div class="bar-track"><div class="bar-fill polka" style="width:100%"></div></div><span class="bar-value">1.35<span class="unit">ms</span></span></div>
    </div>
    <div class="speedup"><span class="speedup-x">2.09<span class="x">×</span></span></div>
  </div>

  <div class="bench-row">
    <div class="bench-name"><span class="label">ecrecover</span><span class="kind">signature</span></div>
    <div class="bars">
      <div class="bar-line"><span class="bar-tag">JAVM (PVM)</span><div class="bar-track"><div class="bar-fill pvm" style="width:45.0%"></div></div><span class="bar-value">1.49<span class="unit">ms</span></span></div>
      <div class="bar-line"><span class="bar-tag">JAVM (PVM2)</span><div class="bar-track"><div class="bar-fill pvm2" style="width:48.5%"></div></div><span class="bar-value">1.61<span class="unit">ms</span></span></div>
      <div class="bar-line"><span class="bar-tag">PolkaVM (PVM)</span><div class="bar-track"><div class="bar-fill polka" style="width:100%"></div></div><span class="bar-value">3.32<span class="unit">ms</span></span></div>
    </div>
    <div class="speedup"><span class="speedup-x">2.06<span class="x">×</span></span></div>
  </div>

  <div class="bench-row">
    <div class="bench-name"><span class="label">poseidon2_perm</span><span class="kind">hash</span></div>
    <div class="bars">
      <div class="bar-line"><span class="bar-tag">JAVM (PVM)</span><div class="bar-track"><div class="bar-fill pvm" style="width:90.0%"></div></div><span class="bar-value">1.82<span class="unit">ms</span></span></div>
      <div class="bar-line"><span class="bar-tag">JAVM (PVM2)</span><div class="bar-track"><div class="bar-fill pvm2" style="width:83.8%"></div></div><span class="bar-value">1.69<span class="unit">ms</span></span></div>
      <div class="bar-line"><span class="bar-tag">PolkaVM (PVM)</span><div class="bar-track"><div class="bar-fill polka" style="width:100%"></div></div><span class="bar-value">2.02<span class="unit">ms</span></span></div>
    </div>
    <div class="speedup"><span class="speedup-x">1.19<span class="x">×</span></span></div>
  </div>

  <div class="bench-row">
    <div class="bench-name"><span class="label">mini_verifier</span><span class="kind">zk-proof</span></div>
    <div class="bars">
      <div class="bar-line"><span class="bar-tag">JAVM (PVM)</span><div class="bar-track"><div class="bar-fill pvm" style="width:85.3%"></div></div><span class="bar-value">788.3<span class="unit">µs</span></span></div>
      <div class="bar-line"><span class="bar-tag">JAVM (PVM2)</span><div class="bar-track"><div class="bar-fill pvm2" style="width:78.8%"></div></div><span class="bar-value">727.7<span class="unit">µs</span></span></div>
      <div class="bar-line"><span class="bar-tag">PolkaVM (PVM)</span><div class="bar-track"><div class="bar-fill polka" style="width:100%"></div></div><span class="bar-value">924.0<span class="unit">µs</span></span></div>
    </div>
    <div class="speedup"><span class="speedup-x">1.27<span class="x">×</span></span></div>
  </div>

  <div class="bench-row">
    <div class="bench-name"><span class="label">poly_eval</span><span class="kind">field</span></div>
    <div class="bars">
      <div class="bar-line"><span class="bar-tag">JAVM (PVM)</span><div class="bar-track"><div class="bar-fill pvm" style="width:98.5%"></div></div><span class="bar-value">1.71<span class="unit">ms</span></span></div>
      <div class="bar-line"><span class="bar-tag">JAVM (PVM2)</span><div class="bar-track"><div class="bar-fill pvm2" style="width:93.0%"></div></div><span class="bar-value">1.62<span class="unit">ms</span></span></div>
      <div class="bar-line"><span class="bar-tag">PolkaVM (PVM)</span><div class="bar-track"><div class="bar-fill polka" style="width:100%"></div></div><span class="bar-value">1.74<span class="unit">ms</span></span></div>
    </div>
    <div class="speedup"><span class="speedup-x">1.08<span class="x">×</span></span></div>
  </div>

  <div class="bench-row">
    <div class="bench-name"><span class="label">fri_fold_tree</span><span class="kind">zk-proof</span></div>
    <div class="bars">
      <div class="bar-line"><span class="bar-tag">JAVM (PVM)</span><div class="bar-track"><div class="bar-fill pvm" style="width:82.0%"></div></div><span class="bar-value">788.5<span class="unit">µs</span></span></div>
      <div class="bar-line"><span class="bar-tag">JAVM (PVM2)</span><div class="bar-track"><div class="bar-fill pvm2" style="width:75.7%"></div></div><span class="bar-value">728.2<span class="unit">µs</span></span></div>
      <div class="bar-line"><span class="bar-tag">PolkaVM (PVM)</span><div class="bar-track"><div class="bar-fill polka" style="width:100%"></div></div><span class="bar-value">962.0<span class="unit">µs</span></span></div>
    </div>
    <div class="speedup"><span class="speedup-x">1.32<span class="x">×</span></span></div>
  </div>
</div>

#### In-house delta

The below table shows the in-house delta between JAVM (PVM2) and JAVM (PVM).

<div class="pvm2-bench not-prose">
<table class="data-table">
  <thead>
    <tr>
      <th>Workload</th>
      <th>JAVM (PVM)</th>
      <th>JAVM (PVM2)</th>
      <th>Δ</th>
      <th>PVM2 / PVM</th>
    </tr>
  </thead>
  <tbody>
    <tr><td>prime_sieve</td><td>190.2<span class="unit">µs</span></td><td>281.5<span class="unit">µs</span></td><td class="delta bad">+91.3<span class="unit">µs</span> · +48.0%</td><td class="ratio-cell"><span class="ratio-bar"><span style="width:100%"></span></span>148.00%</td></tr>
    <tr><td>keccak</td><td>61.4<span class="unit">µs</span></td><td>60.5<span class="unit">µs</span></td><td class="delta good">−0.9<span class="unit">µs</span> · −1.5%</td><td class="ratio-cell"><span class="ratio-bar shrink"><span style="width:98.53%"></span></span>98.53%</td></tr>
    <tr><td>blake2b</td><td>101.4<span class="unit">µs</span></td><td>104.0<span class="unit">µs</span></td><td class="delta bad">+2.6<span class="unit">µs</span> · +2.6%</td><td class="ratio-cell"><span class="ratio-bar"><span style="width:100%"></span></span>102.56%</td></tr>
    <tr><td>goldilocks_mul</td><td>521.4<span class="unit">µs</span></td><td>452.9<span class="unit">µs</span></td><td class="delta good">−68.5<span class="unit">µs</span> · −13.1%</td><td class="ratio-cell"><span class="ratio-bar shrink"><span style="width:86.86%"></span></span>86.86%</td></tr>
    <tr><td>ed25519</td><td>1.02<span class="unit">ms</span></td><td>644.6<span class="unit">µs</span></td><td class="delta good">−374.7<span class="unit">µs</span> · −36.8%</td><td class="ratio-cell"><span class="ratio-bar shrink"><span style="width:63.24%"></span></span>63.24%</td></tr>
    <tr><td>ecrecover</td><td>1.49<span class="unit">ms</span></td><td>1.61<span class="unit">ms</span></td><td class="delta bad">+116.5<span class="unit">µs</span> · +7.8%</td><td class="ratio-cell"><span class="ratio-bar"><span style="width:100%"></span></span>107.79%</td></tr>
    <tr><td>poseidon2_perm</td><td>1.82<span class="unit">ms</span></td><td>1.69<span class="unit">ms</span></td><td class="delta good">−126.0<span class="unit">µs</span> · −6.9%</td><td class="ratio-cell"><span class="ratio-bar shrink"><span style="width:93.07%"></span></span>93.07%</td></tr>
    <tr><td>mini_verifier</td><td>788.3<span class="unit">µs</span></td><td>727.7<span class="unit">µs</span></td><td class="delta good">−60.6<span class="unit">µs</span> · −7.7%</td><td class="ratio-cell"><span class="ratio-bar shrink"><span style="width:92.31%"></span></span>92.31%</td></tr>
    <tr><td>poly_eval</td><td>1.71<span class="unit">ms</span></td><td>1.62<span class="unit">ms</span></td><td class="delta good">−96.0<span class="unit">µs</span> · −5.6%</td><td class="ratio-cell"><span class="ratio-bar shrink"><span style="width:94.40%"></span></span>94.40%</td></tr>
    <tr><td>fri_fold_tree</td><td>788.5<span class="unit">µs</span></td><td>728.2<span class="unit">µs</span></td><td class="delta good">−60.3<span class="unit">µs</span> · −7.6%</td><td class="ratio-cell"><span class="ratio-bar shrink"><span style="width:92.35%"></span></span>92.35%</td></tr>
  </tbody>
  <tfoot>
    <tr><td>total</td><td>8.50<span class="unit">ms</span></td><td>7.92<span class="unit">ms</span></td><td class="delta good">−576.6<span class="unit">µs</span> · −6.8%</td><td>93.21%</td></tr>
  </tfoot>
</table>
</div>

#### Binary size comparison

The binary size of PVM2 is also competitive. This is probably mainly due to PVM's insistence of keeping `bitmask`, a 12.5% overhead. The reason that PVM2 can effortlessly enable a few more standard RISC-V extensions also helped.

<div class="pvm2-bench not-prose">
<table class="data-table">
  <thead>
    <tr>
      <th>Workload</th>
      <th>JAVM (PVM)</th>
      <th>JAVM (PVM2)</th>
      <th>Δ</th>
      <th>PVM2 / PVM</th>
    </tr>
  </thead>
  <tbody>
    <tr><td>prime_sieve</td><td>158,497<span class="unit">B</span></td><td>158,399<span class="unit">B</span></td><td class="delta good">−98<span class="unit">B</span></td><td class="ratio-cell"><span class="ratio-bar shrink"><span style="width:99.94%"></span></span>99.94%</td></tr>
    <tr><td>keccak</td><td>15,289<span class="unit">B</span></td><td>12,320<span class="unit">B</span></td><td class="delta good">−2,969<span class="unit">B</span></td><td class="ratio-cell"><span class="ratio-bar shrink"><span style="width:80.58%"></span></span>80.58%</td></tr>
    <tr><td>blake2b</td><td>30,704<span class="unit">B</span></td><td>22,014<span class="unit">B</span></td><td class="delta good">−8,690<span class="unit">B</span></td><td class="ratio-cell"><span class="ratio-bar shrink"><span style="width:71.70%"></span></span>71.70%</td></tr>
    <tr><td>goldilocks_mul</td><td>5,581<span class="unit">B</span></td><td>5,526<span class="unit">B</span></td><td class="delta good">−55<span class="unit">B</span></td><td class="ratio-cell"><span class="ratio-bar shrink"><span style="width:99.01%"></span></span>99.01%</td></tr>
    <tr><td>ed25519</td><td>229,041<span class="unit">B</span></td><td>94,136<span class="unit">B</span></td><td class="delta good">−134,905<span class="unit">B</span></td><td class="ratio-cell"><span class="ratio-bar shrink"><span style="width:41.10%"></span></span>41.10%</td></tr>
    <tr><td>ecrecover</td><td>261,330<span class="unit">B</span></td><td>203,894<span class="unit">B</span></td><td class="delta good">−57,436<span class="unit">B</span></td><td class="ratio-cell"><span class="ratio-bar shrink"><span style="width:78.02%"></span></span>78.02%</td></tr>
    <tr><td>poseidon2_perm</td><td>16,435<span class="unit">B</span></td><td>13,328<span class="unit">B</span></td><td class="delta good">−3,107<span class="unit">B</span></td><td class="ratio-cell"><span class="ratio-bar shrink"><span style="width:81.10%"></span></span>81.10%</td></tr>
    <tr><td>mini_verifier</td><td>20,152<span class="unit">B</span></td><td>15,632<span class="unit">B</span></td><td class="delta good">−4,520<span class="unit">B</span></td><td class="ratio-cell"><span class="ratio-bar shrink"><span style="width:77.57%"></span></span>77.57%</td></tr>
    <tr><td>poly_eval</td><td>72,821<span class="unit">B</span></td><td>72,404<span class="unit">B</span></td><td class="delta good">−417<span class="unit">B</span></td><td class="ratio-cell"><span class="ratio-bar shrink"><span style="width:99.43%"></span></span>99.43%</td></tr>
    <tr><td>fri_fold_tree</td><td>281,375<span class="unit">B</span></td><td>277,120<span class="unit">B</span></td><td class="delta good">−4,255<span class="unit">B</span></td><td class="ratio-cell"><span class="ratio-bar shrink"><span style="width:98.49%"></span></span>98.49%</td></tr>
  </tbody>
  <tfoot>
    <tr><td>total</td><td>1,091,225<span class="unit">B</span></td><td>874,773<span class="unit">B</span></td><td class="delta good">−216,452<span class="unit">B</span></td><td>80.16%</td></tr>
  </tfoot>
</table>
</div>
