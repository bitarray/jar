#!/usr/bin/env bash
# Quiet the machine for measurement, and put it back afterwards.
#
# Needs root. Everything here is optional — the suite runs without it,
# just noisier. What this buys you is roughly an order of magnitude less
# run-to-run variance, which matters when the difference between two
# engines is a few percent.
#
#   sudo ./scripts/tune.sh            # apply
#   sudo ./scripts/tune.sh --restore  # undo
#
# ASLR is handled by the harness itself (it re-execs with
# ADDR_NO_RANDOMIZE), so it is not here.

set -uo pipefail

RESTORE=0
[ "${1:-}" = "--restore" ] && RESTORE=1

if [ "$(id -u)" -ne 0 ]; then
    echo "needs root: sudo $0 ${1:-}" >&2
    exit 1
fi

# CPUs to reserve for the benchmark. Pick physical cores on one socket,
# avoiding CPU 0 (which fields most interrupts).
BENCH_CPUS="${BENCH_CPUS:-1-2}"

say() { printf '  %-42s %s\n' "$1" "$2"; }

# Write $2 to $1 if the path exists, reporting either way. Kernels vary
# in which knobs they expose; a missing one is not an error.
poke() {
    if [ -w "$1" ]; then
        echo "$2" > "$1" 2>/dev/null && say "$(basename "$1")" "$2" && return
    fi
    say "$(basename "$1")" "(unavailable)"
}

if [ "$RESTORE" -eq 1 ]; then
    echo "restoring defaults"
    poke /sys/devices/system/cpu/cpufreq/boost 1
    poke /proc/sys/kernel/sched_rt_runtime_us 950000
    poke /proc/sys/kernel/watchdog 1
    poke /proc/sys/vm/stat_interval 1
    for c in $(echo "$BENCH_CPUS" | tr ',-' ' '); do
        poke "/sys/devices/system/cpu/cpu$c/cpufreq/scaling_governor" schedutil
    done
    echo "done"
    exit 0
fi

echo "tuning for measurement (CPUs $BENCH_CPUS)"

# Turbo makes clock speed a function of thermal history, so the same
# code measures differently depending on what ran before it.
poke /sys/devices/system/cpu/cpufreq/boost 0

# Pin the bench CPUs to their maximum sustained frequency.
for c in $(echo "$BENCH_CPUS" | tr ',-' ' '); do
    poke "/sys/devices/system/cpu/cpu$c/cpufreq/scaling_governor" performance
done

# Let a SCHED_FIFO task run without the RT throttler preempting it.
poke /proc/sys/kernel/sched_rt_runtime_us -1
# The NMI watchdog fires periodically on every CPU.
poke /proc/sys/kernel/watchdog 0
# vmstat wakes every CPU once a second by default.
poke /proc/sys/vm/stat_interval 1000

cat <<EOF

Tuned. Now run the measurement pinned and at real-time priority:

  taskset -c $BENCH_CPUS chrt -f 99 \\
    ./target/release/bench-compare run

Undo with: sudo $0 --restore
EOF
