#!/usr/bin/env bash
# Run the full comparison, one process per row.
#
# One process per row is not just hygiene. Engines reserve large guard
# regions and install signal handlers at startup; nub's sandbox path
# takes a process-wide address-space reservation it never releases. In
# one process they would interfere, and the first engine to start would
# see a different environment than the last.
#
# Resumable: rows whose result file already exists are skipped, so an
# interrupted run picks up where it stopped. Delete target/results to
# start over.

set -uo pipefail
cd "$(dirname "$0")/.."

BIN=./target/release/bench-compare
[ -x "$BIN" ] || { echo "build first: cargo build --release" >&2; exit 1; }
[ -d artifacts ] || { echo "no artifacts: cargo run --release -p bench-build" >&2; exit 1; }

mkdir -p target/results

# `list` is the source of truth for what exists on this host.
PROGRAMS=$("$BIN" list | sed -n 's/^  \([a-z0-9-]*\) *artifacts:.*/\1/p')
ENGINES=$("$BIN" list | sed -n 's/^  \([a-z0-9_]*\) *family=.*/\1/p')

for kind in runtime compilation; do
    for program in $PROGRAMS; do
        for engine in $ENGINES; do
            out="target/results/${kind}__${program}__${engine}.json"
            [ -f "$out" ] && continue
            "$BIN" run "$kind/$program/$engine" --kinds "$kind"
        done
    done
done

"$BIN" report --write
