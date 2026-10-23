# scx_hush: an unfair-by-design CPU scheduler

scx_hush is a Linux CPU scheduler that you load at runtime through
[sched_ext](https://docs.kernel.org/scheduler/sched-ext.html). Background work
runs only on CPU time that foreground work does not want: foreground tasks
behave as if the machine were idle, and background tasks still finish.
It generalises the UFS design ([arXiv 2605.02377](https://arxiv.org/abs/2605.02377))
from one database to any machine with latency-critical and deferrable work:
laptops, robots and servers.

* **Strict classes.** FOREGROUND, NORMAL and BACKGROUND each have a dispatch
  queue, and CPUs drain them in that order. A waking foreground task
  preempts a CPU running background work.
* **Bounded starvation.** A rate-limited guard gives any background task that
  has waited longer than `guard_ms` (2 s by default) one slice. This costs
  foreground about 1%.
* **Priority inversion handled.** A background task holding a lock that a
  foreground task waits on is boosted until it releases the lock. Owners
  are found from PI futexes, glibc mutexes, optional `libhush` hints, or a
  same-process fallback.
* **Zero application changes.** Classes come from cgroups, process names and
  uids in a TOML policy, and the policy hot-reloads.
* **Safe.** All decisions run as verified BPF. Any error, a watchdog stall
  or SysRq-S returns every task to the default scheduler.

The design is specified in the *scx_hush PRD & Architecture* (Oct 22, 2026).
[`docs/IMPLEMENTATION_PLAN.md`](docs/IMPLEMENTATION_PLAN.md) maps every
requirement to code and records where the implementation adds to the PRD.

> **Status.** The scheduler, daemon, CLI, hint library and evaluation harness
> are implemented, and they build and pass their tests in CI. The BPF object is
> compiled and statically checked for x86-64 and arm64. Loading it and
> measuring it need a kernel with `CONFIG_SCHED_CLASS_EXT=y` (Linux ≥ 6.12),
> which is the next step (plan phase P6). No performance numbers have been
> measured yet. The CSVs in `bench/results/` and `reports/` are synthetic
> model output.

---

## Layout

```
bpf/scx_hush.bpf.c        scheduler (struct sched_ext_ops) + futex/exec/uprobe hooks
bpf/hush_compat.bpf.h     the only file naming sched_ext kfuncs (NFR-9)
include/hush_intf.h       structs and constants shared by BPF and user space
hushd/                    daemon/loader in C: policy, cgroups, control socket, selftest
libhush/                  hint library: hush_critical_enter() / hush_critical_exit()
cli/hushctl.py            CLI over /run/hush.sock
config/policy.toml        default policy
tools/                    inversion_micro (E5) and periodic_loop (E2/E9) workloads
bench/real/               evaluation harness (E1–E9, baselines B0–B6) and plots
tests/                    C unit tests (tests/c) and pytest suites
sim/, daemon/hushd.py     Python simulator + simulated daemon (teaching, demo, tests)
demo/                     web visualiser for the simulator
scripts/fetch-deps.sh     pinned scx headers, bpftool and libbpf
```

## Build

Requirements: clang ≥ 17, gcc or clang for user space, make, git, libelf
and zlib headers. On Ubuntu 24.04:

```sh
sudo apt-get install clang llvm libelf-dev zlib1g-dev make gcc
make deps          # pinned sched-ext/scx headers, bpftool + static libbpf → third_party/
make               # build/scx_hush.bpf.o, build/hush.skel.h, build/hushd, build/libhush.so, build/tools/*
make test          # C unit tests + pytest
sudo make install  # /usr/local/sbin/hushd, /usr/local/bin/hushctl, libhush, /etc/scx_hush/policy.toml
```

`make bpf ARCH=arm64` cross-builds the BPF object for arm64 (Raspberry Pi 5,
Jetson). The build uses the running kernel's BTF when it has sched_ext types,
and otherwise falls back to the `vmlinux.h` vendored by the scx project.

## Run

```sh
hushd --selftest                                # can this machine run it?
hushd --dry-run --policy config/policy.toml     # validate the policy, show what it resolves to
sudo hushd --policy /etc/scx_hush/policy.toml   # load; Ctrl-C unloads (FR-20)
```

```sh
hushctl status                       # per-class runtime and waits, kicks, guard firings, boosts
hushctl class <pid>                  # a task's class and the rule or boost behind it
sudo hushctl promote <pid|cgroup>    # foreground until demoted, reset or exit
sudo hushctl demote  <pid|cgroup>
sudo hushctl reset   <pid|cgroup>    # back to the policy
sudo hushctl reload                  # same as: sudo kill -HUP $(pidof hushd)
sudo hushctl selftest
sudo hushctl trace start /tmp/wakeups.csv && sleep 10 && sudo hushctl trace stop
```

Read-only commands work for any user. Commands that change state need root,
which the daemon checks through the socket's peer credentials.

**Safety.** If anything goes wrong, sched_ext unloads the scheduler and every
task returns to the default scheduler. `hushd` then prints the kernel's exit
reason. To stop it from the kernel side at any time, independently of
`hushd`, run `echo S | sudo tee /proc/sysrq-trigger`. Check the state with
`cat /sys/kernel/sched_ext/state`.

### Policy

```toml
[scheduler]
fg_slice_ms = 5
normal_slice_ms = 10
bg_slice_ms = 20
guard_ms = 2000          # must be <= watchdog_ms / 4, or hushd refuses to load
boost_ms = 50
boost_cap_pct = 10

[[rule]]
match = { cgroup = "/user.slice/user-1000.slice/session-*.scope" }   # also matches every cgroup below
class = "foreground"

[[rule]]
match = { comm = ["cc1", "cc1plus", "rustc", "ld"] }
class = "background"

[[rule]]
match = { uid = 1001 }
class = "background"
```

Rules match in order and the first match wins. A cgroup match beats a comm
match, which beats a uid match. An unmatched task inherits its parent's class
at fork, and is NORMAL otherwise. Kernel threads are always NORMAL.
`config/policy.toml` documents every key.

### Hints (optional)

```c
#include <libhush.h>          /* link with -lhush */
pthread_mutex_lock(&m);
hush_critical_enter();        /* "I hold something foreground may need" */
/* ... */
hush_critical_exit();
pthread_mutex_unlock(&m);
```

The functions are empty. `hushd` attaches uprobes to them, so they cost
almost nothing when scx_hush is not loaded. A thread can only mark itself,
and its boosted time is capped at 10% of each second.

## Evaluate

```sh
bench/real/run.py -e all --dry-run                          # print the experiment matrix
sudo bench/real/run.py -e E1,E2,E5 --reps 5 --duration 120 --warmup 30 --pin-freq
bench/real/plot.py bench/real/results/<timestamp>           # the five figures of PRD §12.5
```

Each run writes `meta.json` (with `uname -a`, the git commit, the governor and
the policy used), `metrics.csv` (raw, one row per metric per repetition),
`summary.csv` (median and 95% bootstrap CI) and raw tool output. The
workloads need `schbench`, `stress-ng` or `HUSH_BUILD_CMD` (for example
`make -j$(nproc) -C ~/linux`), `zstd`, `rsync`, PostgreSQL with `pgbench`
(E3), and `perf` or `hackbench` (E7).

## Simulator and demo

`sim/scheduler_core.py` is a discrete-event model of the design. It is used
for teaching, for the web demo (`python run_demo.py`) and for unit tests. Its
daemon speaks the same protocol as `hushd`:

```sh
python daemon/hushd.py --socket /tmp/hush-sim.sock &
HUSH_SOCK=/tmp/hush-sim.sock python cli/hushctl.py status
```

`bench/run_experiments.py` and `bench/workloads.py` produce **synthetic**
numbers from hand-picked distributions, for exercising the report pipeline.
They are not measurements.
