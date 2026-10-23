#!/usr/bin/env bash
# Milestone safety gate (PRD §11 "Testing for safety"): load scx_hush, run
# stress-ng on every CPU plus a fork bomb confined by pids.max for DURATION
# seconds, and check that sched_ext stayed enabled with our ops the whole
# time and that no watchdog safety net fired. Needs root and a sched_ext kernel.
#
#   sudo scripts/stress-gate.sh [DURATION_S=1800] [POLICY=config/policy.toml]
set -uo pipefail

DURATION=${1:-1800}
POLICY=${2:-config/policy.toml}
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
HUSHD="$ROOT/build/hushd"
SOCK=/run/hush-gate.sock
CG=$(awk '$3 == "cgroup2" { print $2; exit }' /proc/self/mounts)/hush-gate
fail=0

die() { echo "GATE FAIL: $*" >&2; fail=1; }
state() { cat /sys/kernel/sched_ext/state 2>/dev/null || echo missing; }
ops() { cat /sys/kernel/sched_ext/root/ops 2>/dev/null; }

[ "$(id -u)" = 0 ] || { echo "run as root" >&2; exit 2; }
command -v stress-ng >/dev/null || { echo "stress-ng not installed" >&2; exit 2; }
[ -x "$HUSHD" ] || { echo "build/hushd missing; run make" >&2; exit 2; }

"$HUSHD" --policy "$POLICY" --socket "$SOCK" --stats 60 &
HPID=$!
for _ in $(seq 50); do [ "$(ops)" = hush ] && break; sleep 0.1; done
[ "$(ops)" = hush ] || { kill $HPID; echo "scx_hush did not load" >&2; exit 1; }
echo "loaded: state=$(state) ops=$(ops)"

mkdir -p "$CG"
echo 256 > "$CG/pids.max" 2>/dev/null || echo "warning: pids controller unavailable; fork bomb skipped"
stress-ng --cpu "$(nproc)" --timeout "${DURATION}s" --metrics-brief &
SPID=$!
if [ -w "$CG/pids.max" ]; then
	sh -c "echo \$\$ > $CG/cgroup.procs; exec timeout ${DURATION}s sh -c ':(){ :|:& };:'" \
		>/dev/null 2>&1 &
fi

end=$((SECONDS + DURATION))
while [ $SECONDS -lt $end ]; do
	[ "$(state)" = enabled ] && [ "$(ops)" = hush ] || { die "scheduler unloaded at ${SECONDS}s (state=$(state))"; break; }
	kill -0 $HPID 2>/dev/null || { die "hushd exited"; break; }
	sleep 5
done

status=$(HUSH_SOCK=$SOCK python3 "$ROOT/cli/hushctl.py" --json status 2>/dev/null)
echo "$status" | python3 -c '
import json, sys
s = json.load(sys.stdin)
c = s["counters"]
bg = s["classes"]["BACKGROUND"]["wait_max_ns"] / 1e6
print(f"hard guard firings {c[\"hard_guard_firings\"]}, guard {c[\"guard_firings\"]}, longest BG wait {bg:.0f} ms")
sys.exit(1 if c["hard_guard_firings"] else 0)' || die "hard guard fired (BG wait approached the watchdog)"

kill $SPID 2>/dev/null
pkill -KILL -f "timeout ${DURATION}s sh -c" 2>/dev/null
kill -INT $HPID; wait $HPID; rc=$?
[ $rc = 0 ] || die "hushd exit code $rc"
[ "$(state)" = disabled ] || die "sched_ext still $(state) after unload"
rmdir "$CG" 2>/dev/null

[ $fail = 0 ] && echo "GATE PASS: ${DURATION}s stress, scheduler stayed loaded, clean unload"
exit $fail
