#!/usr/bin/env python3
"""
Generate Lean test files from accumulate JSON test vectors.

Usage:
  python3 tools/gen_accumulate_tests.py <test_vectors_dir> <output_lean_file>
"""

import json
import os
import sys
from pathlib import Path


def hex_to_lean(hex_str: str) -> str:
    h = hex_str.removeprefix("0x")
    return f'hexSeq "{h}"'


def hex_to_bytes(hex_str: str) -> str:
    h = hex_str.removeprefix("0x")
    return f'hexToBytes "{h}"'


def sanitize_name(filename: str) -> str:
    name = Path(filename).stem
    return name.replace("-", "_")


# Counter for unique def names
_def_counter = 0


def next_id():
    global _def_counter
    _def_counter += 1
    return _def_counter


def gen_work_result(result_data: dict) -> str:
    """Generate WorkResult constructor."""
    if "ok" in result_data:
        data = result_data["ok"]
        return f'WorkResult.ok ({hex_to_bytes(data)})'
    elif "err" in result_data:
        err = result_data["err"]
        if err == "out_of_gas":
            return "WorkResult.err .outOfGas"
        elif err == "panic":
            return "WorkResult.err .panic"
        elif err == "bad_exports":
            return "WorkResult.err .badExports"
        elif err == "bad_code":
            return "WorkResult.err .badCode"
        elif err == "code_oversize":
            return "WorkResult.err .oversize"
    return 'WorkResult.ok ByteArray.empty'


def gen_work_digest(d: dict, prefix: str, idx: int) -> (str, str):
    ref = f"{prefix}_digest_{idx}"
    rl = d.get("refine_load", {})
    result = gen_work_result(d.get("result", {}))
    lines = [
        f"def {ref} : WorkDigest := {{",
        f"  serviceId := {d['service_id']},",
        f"  codeHash := {hex_to_lean(d['code_hash'])},",
        f"  payloadHash := {hex_to_lean(d['payload_hash'])},",
        f"  gasLimit := {d['accumulate_gas']},",
        f"  result := {result},",
        f"  gasUsed := {rl.get('gas_used', 0)},",
        f"  importsCount := {rl.get('imports', 0)},",
        f"  extrinsicsCount := {rl.get('extrinsic_count', 0)},",
        f"  extrinsicsSize := {rl.get('extrinsic_size', 0)},",
        f"  exportsCount := {rl.get('exports', 0)} }}",
    ]
    return "\n".join(lines), ref


def gen_work_report(report: dict, prefix: str) -> (str, str):
    """Generate a WorkReport def with extracted sub-defs."""
    ref = f"{prefix}_report"
    lines = []

    # Digests
    digest_refs = []
    for i, d in enumerate(report["results"]):
        defn, dref = gen_work_digest(d, prefix, i)
        lines.append(defn)
        lines.append("")
        digest_refs.append(dref)
    digests_str = "#[" + ", ".join(digest_refs) + "]" if digest_refs else "#[]"

    # Segment root lookup as Dict entries
    srl = report.get("segment_root_lookup", [])
    if srl:
        srl_entries = []
        for e in srl:
            if isinstance(e, dict):
                k = hex_to_lean(e["work_package_hash"])
                v = hex_to_lean(e["segment_tree_root"])
            else:
                k = hex_to_lean(e[0])
                v = hex_to_lean(e[1])
            srl_entries.append(f"({k}, {v})")
        srl_str = (
            "#[" + ", ".join(srl_entries) + "].foldl (init := Dict.empty) "
            "fun acc (k, v) => acc.insert k v"
        )
    else:
        srl_str = "Dict.empty"

    # Prerequisites
    prereqs = report["context"].get("prerequisites", [])
    prereqs_str = ", ".join(hex_to_lean(p) for p in prereqs)

    # AvailabilitySpec
    spec = report["package_spec"]
    spec_ref = f"{prefix}_spec"
    lines.append(f"def {spec_ref} : AvailabilitySpec := {{")
    lines.append(f"  packageHash := {hex_to_lean(spec['hash'])},")
    lines.append(f"  bundleLength := {spec['length']},")
    lines.append(f"  erasureRoot := {hex_to_lean(spec['erasure_root'])},")
    lines.append(f"  segmentRoot := {hex_to_lean(spec['exports_root'])},")
    lines.append(f"  segmentCount := {spec['exports_count']} }}")
    lines.append("")

    # RefinementContext
    ctx = report["context"]
    ctx_ref = f"{prefix}_ctx"
    lines.append(f"def {ctx_ref} : RefinementContext := {{")
    lines.append(f"  anchorHash := {hex_to_lean(ctx['anchor'])},")
    lines.append(f"  anchorStateRoot := {hex_to_lean(ctx['state_root'])},")
    lines.append(f"  anchorBeefyRoot := {hex_to_lean(ctx['beefy_root'])},")
    lines.append(f"  lookupAnchorHash := {hex_to_lean(ctx['lookup_anchor'])},")
    lines.append(f"  lookupAnchorTimeslot := {ctx['lookup_anchor_slot']},")
    lines.append(f"  prerequisites := #[{prereqs_str}] }}")
    lines.append("")

    # Auth output
    auth_output = report.get("auth_output", "0x")

    lines.append(f"def {ref} : WorkReport := {{")
    lines.append(f"  availSpec := {spec_ref},")
    lines.append(f"  context := {ctx_ref},")
    lines.append(f"  coreIndex := ⟨{report['core_index']}, sorry⟩,")
    lines.append(f"  authorizerHash := {hex_to_lean(report['authorizer_hash'])},")
    lines.append(f"  authOutput := {hex_to_bytes(auth_output)},")
    lines.append(f"  segmentRootLookup := {srl_str},")
    lines.append(f"  digests := {digests_str},")
    lines.append(f"  authGasUsed := {report.get('auth_gas_used', 0)} }}")
    return "\n".join(lines), ref


def gen_ready_record(rr: dict, prefix: str, idx: int) -> (str, str):
    """Generate a TAReadyRecord def."""
    ref = f"{prefix}_rr_{idx}"
    rr_prefix = f"{prefix}_rr{idx}"

    report_text, report_ref = gen_work_report(rr["report"], rr_prefix)
    deps = rr["dependencies"]
    deps_str = ", ".join(hex_to_lean(d) for d in deps)

    lines = [report_text, ""]
    lines.append(f"def {ref} : TAReadyRecord := {{")
    lines.append(f"  report := {report_ref},")
    lines.append(f"  dependencies := #[{deps_str}] }}")
    return "\n".join(lines), ref


def gen_service_account(acct: dict, prefix: str) -> (str, str):
    """Generate a ServiceAccount def."""
    sid = acct["id"]
    data = acct["data"]
    svc = data["service"]
    ref = f"{prefix}_acct_{sid}"

    lines = []

    # Storage entries
    storage = data.get("storage", [])
    if storage:
        storage_entries = []
        for item in storage:
            k = hex_to_bytes(item["key"])
            v = hex_to_bytes(item["value"])
            storage_entries.append(f"({k}, {v})")
        storage_str = (
            "#[" + ",\n    ".join(storage_entries) + "].foldl (init := Dict.empty) "
            "fun acc (k, v) => acc.insert k v"
        )
    else:
        storage_str = "Dict.empty"

    # Preimage blobs
    preimage_blobs = data.get("preimage_blobs", [])
    if preimage_blobs:
        blob_entries = []
        for item in preimage_blobs:
            h = hex_to_lean(item["hash"])
            b = hex_to_bytes(item["blob"])
            blob_entries.append(f"({h}, {b})")
        preimages_str = (
            "#[" + ",\n    ".join(blob_entries) + "].foldl (init := Dict.empty) "
            "fun acc (k, v) => acc.insert k v"
        )
    else:
        preimages_str = "Dict.empty"

    # Preimage requests
    preimage_requests = data.get("preimage_requests", [])
    if preimage_requests:
        req_entries = []
        for item in preimage_requests:
            h = hex_to_lean(item["key"]["hash"])
            length = item["key"]["length"]
            slots = item["value"]
            slots_str = ", ".join(str(s) for s in slots)
            req_entries.append(
                f"(({h}, ({length} : BlobLength)), #[{slots_str}])"
            )
        preimage_info_str = (
            "#[" + ",\n    ".join(req_entries) + "].foldl (init := Dict.empty) "
            "fun acc (k, v) => acc.insert k v"
        )
    else:
        preimage_info_str = "Dict.empty"

    lines.append(f"def {ref} : ServiceAccount := {{")
    lines.append(f"  storage := {storage_str},")
    lines.append(f"  preimages := {preimages_str},")
    lines.append(f"  preimageInfo := {preimage_info_str},")
    lines.append(f"  gratis := {svc.get('deposit_offset', 0)},")
    lines.append(f"  codeHash := {hex_to_lean(svc['code_hash'])},")
    lines.append(f"  balance := {svc['balance']},")
    lines.append(f"  minAccGas := {svc.get('min_item_gas', 0)},")
    lines.append(f"  minOnTransferGas := {svc.get('min_memo_gas', 0)},")
    lines.append(f"  created := {svc.get('creation_slot', 0)},")
    lines.append(f"  lastAccumulation := {svc.get('last_accumulation_slot', 0)},")
    lines.append(f"  parent := {svc.get('parent_service', 0)} }}")
    return "\n".join(lines), ref, sid


def gen_privileges(priv: dict, prefix: str) -> str:
    assign_str = ", ".join(str(a) for a in priv["assign"])
    always_acc = priv.get("always_acc", [])
    if always_acc:
        aa_entries = []
        for entry in always_acc:
            if isinstance(entry, dict):
                aa_entries.append(f"({entry['service']}, {entry['gas']})")
            else:
                aa_entries.append(f"({entry[0]}, {entry[1]})")
        aa_str = "#[" + ", ".join(aa_entries) + "]"
    else:
        aa_str = "#[]"

    return (
        f"{{ bless := {priv['bless']}, "
        f"assign := #[{assign_str}], "
        f"designate := {priv['designate']}, "
        f"register := {priv['register']}, "
        f"alwaysAcc := {aa_str} }}"
    )


def gen_statistics(stats: list, prefix: str) -> str:
    if not stats:
        return f"def {prefix}_stats : Array TAServiceStats := #[]"

    lines = [f"def {prefix}_stats : Array TAServiceStats := #["]
    for i, entry in enumerate(stats):
        sid = entry["id"]
        r = entry["record"]
        sep = "," if i < len(stats) - 1 else ""
        lines.append(f"  {{ serviceId := {sid},")
        lines.append(f"    providedCount := {r['provided_count']},")
        lines.append(f"    providedSize := {r['provided_size']},")
        lines.append(f"    refinementCount := {r['refinement_count']},")
        lines.append(f"    refinementGasUsed := {r['refinement_gas_used']},")
        lines.append(f"    imports := {r['imports']},")
        lines.append(f"    extrinsicCount := {r['extrinsic_count']},")
        lines.append(f"    extrinsicSize := {r['extrinsic_size']},")
        lines.append(f"    exports := {r['exports']},")
        lines.append(f"    accumulateCount := {r['accumulate_count']},")
        lines.append(f"    accumulateGasUsed := {r['accumulate_gas_used']} }}{sep}")
    lines.append("]")
    return "\n".join(lines)


def gen_state(state_data: dict, prefix: str) -> str:
    """Generate all defs for a state."""
    lines = []

    # Ready queue
    rq = state_data["ready_queue"]
    slot_refs = []
    for slot_idx, slot_entries in enumerate(rq):
        entry_refs = []
        for entry_idx, entry in enumerate(slot_entries):
            defn, ref = gen_ready_record(entry, f"{prefix}_rq{slot_idx}", entry_idx)
            lines.append(defn)
            lines.append("")
            entry_refs.append(ref)
        entries_str = ", ".join(entry_refs) if entry_refs else ""
        slot_ref = f"{prefix}_rq_slot_{slot_idx}"
        lines.append(f"def {slot_ref} : Array TAReadyRecord := #[{entries_str}]")
        lines.append("")
        slot_refs.append(slot_ref)

    rq_str = "#[" + ", ".join(slot_refs) + "]"
    lines.append(f"def {prefix}_rq : Array (Array TAReadyRecord) := {rq_str}")
    lines.append("")

    # Accumulated
    acc = state_data["accumulated"]
    acc_slots = []
    for slot_hashes in acc:
        if slot_hashes:
            hashes_str = ", ".join(hex_to_lean(h) for h in slot_hashes)
            acc_slots.append(f"#[{hashes_str}]")
        else:
            acc_slots.append("#[]")
    acc_str = "#[" + ", ".join(acc_slots) + "]"
    lines.append(f"def {prefix}_accumulated : Array (Array Hash) := {acc_str}")
    lines.append("")

    # Privileges
    priv = state_data["privileges"]
    priv_str = gen_privileges(priv, prefix)
    lines.append(f"def {prefix}_privileges : TAPrivileges := {priv_str}")
    lines.append("")

    # Statistics
    stats = state_data.get("statistics", [])
    lines.append(gen_statistics(stats, prefix))
    lines.append("")

    # Accounts
    acct_refs = []
    for acct in state_data.get("accounts", []):
        defn, ref, sid = gen_service_account(acct, prefix)
        lines.append(defn)
        lines.append("")
        acct_refs.append((sid, ref))

    if acct_refs:
        accts_str = (
            "#[" + ", ".join(f"(({sid} : ServiceId), {ref})" for sid, ref in acct_refs)
            + "].foldl (init := Dict.empty) fun acc (k, v) => acc.insert k v"
        )
    else:
        accts_str = "Dict.empty"
    lines.append(f"def {prefix}_accounts : Dict ServiceId ServiceAccount := {accts_str}")
    lines.append("")

    # State
    lines.append(f"def {prefix} : TAState := {{")
    lines.append(f"  slot := {state_data['slot']},")
    lines.append(f"  entropy := {hex_to_lean(state_data['entropy'])},")
    lines.append(f"  readyQueue := {prefix}_rq,")
    lines.append(f"  accumulated := {prefix}_accumulated,")
    lines.append(f"  privileges := {prefix}_privileges,")
    lines.append(f"  statistics := {prefix}_stats,")
    lines.append(f"  accounts := {prefix}_accounts }}")
    return "\n".join(lines)


def gen_input(inp_data: dict, prefix: str) -> str:
    """Generate input def."""
    lines = []
    report_refs = []
    for i, report in enumerate(inp_data["reports"]):
        defn, ref = gen_work_report(report, f"{prefix}_inp_r{i}")
        lines.append(defn)
        lines.append("")
        report_refs.append(ref)

    reports_str = "#[" + ", ".join(report_refs) + "]" if report_refs else "#[]"
    lines.append(f"def {prefix}_input : TAInput := {{")
    lines.append(f"  slot := {inp_data['slot']},")
    lines.append(f"  reports := {reports_str} }}")
    return "\n".join(lines)


def generate_test_file(test_dir: str, output_file: str):
    json_files = sorted(f for f in os.listdir(test_dir) if f.endswith(".json"))

    if not json_files:
        print(f"No JSON files found in {test_dir}")
        sys.exit(1)

    print(f"Generating tests for {len(json_files)} test vectors...")

    lines = []
    lines.append("import Jar.Test.Accumulate")
    lines.append("")
    lines.append("/-! Auto-generated accumulate test vectors. Do not edit. -/")
    lines.append("")
    lines.append("namespace Jar.Test.AccumulateVectors")
    lines.append("")
    lines.append("open Jar Jar.Test.Accumulate")
    lines.append("")

    # Helpers
    lines.append("def hexToBytes (s : String) : ByteArray :=")
    lines.append("  let chars := s.toList")
    lines.append("  let nibble (c : Char) : UInt8 :=")
    lines.append("    if c.toNat >= 48 && c.toNat <= 57 then (c.toNat - 48).toUInt8")
    lines.append("    else if c.toNat >= 97 && c.toNat <= 102 then (c.toNat - 87).toUInt8")
    lines.append("    else if c.toNat >= 65 && c.toNat <= 70 then (c.toNat - 55).toUInt8")
    lines.append("    else 0")
    lines.append("  let rec go (cs : List Char) (acc : ByteArray) : ByteArray :=")
    lines.append("    match cs with")
    lines.append("    | hi :: lo :: rest => go rest (acc.push ((nibble hi <<< 4) ||| nibble lo))")
    lines.append("    | _ => acc")
    lines.append("  go chars ByteArray.empty")
    lines.append("")
    lines.append("def hexSeq (s : String) : OctetSeq n := ⟨hexToBytes s, sorry⟩")
    lines.append("")

    test_names = []
    for json_file in json_files:
        with open(os.path.join(test_dir, json_file)) as f:
            data = json.load(f)

        test_name = sanitize_name(json_file)
        test_names.append(test_name)

        lines.append(f"-- ============================================================================")
        lines.append(f"-- {json_file}")
        lines.append(f"-- ============================================================================")
        lines.append("")

        # Pre state
        lines.append(gen_state(data["pre_state"], f"{test_name}_pre"))
        lines.append("")

        # Post state
        lines.append(gen_state(data["post_state"], f"{test_name}_post"))
        lines.append("")

        # Input
        lines.append(gen_input(data["input"], test_name))
        lines.append("")

        # Expected output hash
        output = data["output"]
        if "ok" in output:
            lines.append(f"def {test_name}_expected : Hash := {hex_to_lean(output['ok'])}")
        else:
            lines.append(f"def {test_name}_expected : Hash := Hash.zero")
        lines.append("")

    # Test runner
    lines.append("-- ============================================================================")
    lines.append("-- Test Runner")
    lines.append("-- ============================================================================")
    lines.append("")
    lines.append("end Jar.Test.AccumulateVectors")
    lines.append("")
    lines.append("open Jar.Test.Accumulate Jar.Test.AccumulateVectors in")
    lines.append("def main : IO Unit := do")
    lines.append('  IO.println "Running accumulate test vectors..."')
    lines.append("  let mut passed := (0 : Nat)")
    lines.append("  let mut failed := (0 : Nat)")

    for name in test_names:
        lines.append(
            f'  if (← runTest "{name}" {name}_pre {name}_input {name}_expected {name}_post)'
        )
        lines.append(f"  then passed := passed + 1")
        lines.append(f"  else failed := failed + 1")

    lines.append(
        f'  IO.println s!"Accumulate: {{passed}} passed, {{failed}} failed out of {len(test_names)}"'
    )
    lines.append("  if failed > 0 then")
    lines.append("    IO.Process.exit 1")

    with open(output_file, "w") as f:
        f.write("\n".join(lines) + "\n")

    print(f"Generated {output_file} with {len(test_names)} test cases")


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <test_vectors_dir> <output_lean_file>")
        sys.exit(1)
    generate_test_file(sys.argv[1], sys.argv[2])
