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

# `cold` first: it is the bench target, so an interrupted sweep still
# leaves the headline table complete.
#
# All four kinds go through this loop. An earlier version ran only
# `runtime` and `compilation` here and left `cold`/`invoke` to be invoked
# by hand — which meant the headline table was measured in ONE process
# shared by every program and every engine, against a guest heap that is
# never swept. That contaminated rows by up to 47%.
#
# `--exact` matters for the same reason: engine names nest
# (`..._sync_gas` is a prefix of `..._sync_gas_full`), and a substring
# filter naming the shorter one runs both in a single process.
for kind in cold invoke runtime compilation; do
    for program in $PROGRAMS; do
        for engine in $ENGINES; do
            out="target/results/${kind}__${program}__${engine}.json"
            [ -f "$out" ] && continue
            "$BIN" run "$kind/$program/$engine" --kinds "$kind" --exact
        done
    done
done

"$BIN" report --write
