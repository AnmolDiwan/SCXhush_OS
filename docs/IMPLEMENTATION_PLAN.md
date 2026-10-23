# scx_hush — Implementation Plan

| | |
|---|---|
| **Source document** | *scx_hush — Unfair-by-Design Scheduler: PRD & Architecture* (Oct 22, 2026) |
| **Plan date** | Oct 23, 2026 |
| **Branch** | `claude/optimistic-hopper-ldpqwd` |
| **Status** | P0 to P5 are implemented and verified in this change (§4). P6, the on-hardware evaluation, needs a sched_ext kernel. |

This plan compares the repository with the PRD, lists what has to change, and splits the
work into phases with clear exit criteria. Each phase maps to a PRD milestone gate (§13).
Requirement IDs (FR-*, NFR-*) refer to the PRD.

---

## 1. Assessment of the repository before this change

### 1.1 What existed

| Area | Files | State |
|---|---|---|
| BPF scheduler | `bpf/scx_hush.bpf.c`, `include/scx_compat.h`, `include/scx_hush_types.h` | Draft. **Does not compile**, see 1.2. |
| Daemon | `daemon/hushd.py` | Python. Drives the **simulator**, not the kernel. Listens on TCP, not on `/run/hush.sock`. |
| CLI | `cli/hushctl.py` | Python, TCP only. The command set matches PRD §9.3. |
| Hint library | `libhush/` | Mostly right. No build rule for the `.so`. |
| Simulator | `sim/scheduler_core.py` | Discrete-event model of the design. Useful for teaching and for unit tests. |
| Benchmarks | `bench/workloads.py`, `bench/run_experiments.py`, `bench/results/*.csv`, `reports/` | **Synthetic.** Each baseline's latency is a hard-coded log-normal distribution (for example `B6: lognormal(mean=0.32, …)`). Nothing is measured. |
| Demo | `demo/`, `real_engine/`, `engine/`, `run_demo.py` | Web visualiser and a Windows-oriented user-space harness. Outside the PRD scope. |
| Tests | `tests/*.py` | 21 pytest tests, all against the simulator. |
| Build/CI | none | No Makefile, no CI. Bytecode (`__pycache__`) was committed. |

### 1.2 Defects in the BPF draft

1. **It cannot build.** It includes a `vmlinux.h` that does not exist. `scx_hush_types.h` pulls `<stdint.h>` into a BPF compile. `BPF_STRUCT_OPS`, `bpf_for` and `scx_bpf_now` are used but never defined. `bpf_core_read()` is called with the wrong arity. `scx_bpf_dsq_move_to_local()` uses a signature that newer kernels have replaced, which is the drift NFR-9 warns about.
2. **Callbacks are missing:** `init_task`, `exit_task`, `enable`, `runnable` and `quiescent` (PRD §7.3).
3. **Classification is wrong.** `classify_task()` reads `bpf_get_current_comm()`, which is the comm of the *calling* task, not of `p`. There is no fork inheritance (FR-4), no kernel-thread rule (§7.7) and no uid matching (FR-3).
4. **The starvation guard is wrong.** It fires on the queue length, not on the age of the head of `BG_DSQ` (§7.5).
5. **Virtual time is a stub.** `tctx->vtime += delta` has no weight scaling and no wake-up clamp (§7.6), and `p->scx.dsq_vtime` is never used.
6. **Inversion handling (§8) is a stub.** The futex hook records `wait_uaddr` and nothing else: no owner lookup, no boost, no release and no expiry. Classic `tp/` programs cannot call the kfuncs that the boost path needs.
7. **Nothing records exit info.** `hushd` therefore cannot print the reason for an abort (§11).
8. **No user-space loader exists.** Nothing opens, loads or attaches the BPF object.

### 1.3 Gap matrix against the PRD

| Req | Before | After this change |
|---|---|---|
| FR-1 three classes | sim only | BPF `resolve_class()` + `effective_class()` |
| FR-2 cgroup policy, SIGHUP reload | sim only | `hushd` resolves globs to cgroup IDs, inotify, SIGHUP, generation counter |
| FR-3 comm / uid rules | sim only (no uid) | `class_by_comm`, `class_by_uid` maps; cgroup precedence |
| FR-4 fork inheritance | missing | `init_task` with `args->fork` inherits from parent |
| FR-5 promote/demote | sim only | `class_by_pid` overrides + cgroup overrides |
| FR-6/7/9 strict order, BG preemption | partial draft | `enqueue` + bounded CPU scan + `SCX_KICK_PREEMPT` |
| FR-8 weighted vtime | stub | `dsq_vtime` scaled by `100/weight`, clamped on wake-up |
| FR-10 long BG slice | draft | per-class slices from `config` |
| FR-11/12 guard | wrong | head-age check, per-CPU rate limit, watchdog validation, hard-guard safety net |
| FR-13 hint API | partial | uprobes on `libhush.so`, nesting, 10% cap |
| FR-14 futex detection | stub | tier 2 (PI owner TID), tier 3 (glibc `__owner`, selftest-gated), same-process fallback |
| FR-15 boost expiry | missing | `boost_until`, renewal only while the waiter is still blocked |
| FR-16 D-state escape | missing | quiescent/runnable tracking, 20 ms escape window |
| FR-17 counters | partial | per-CPU per-class stats |
| FR-18 status | sim only | `hushctl status` / `class` over `/run/hush.sock` |
| FR-19 trace | sim only | 4 MiB ring buffer, CSV writer |
| FR-20 Ctrl-C unload | sim only | signalfd → link destroy; UEI exit report |
| NFR-1/2 safety | n/a | all logic in verified BPF; sched_ext fallback; SysRq-S documented |
| NFR-3 hint security | partial | uprobes act on `current` only; cap + `hint_abuse` |
| NFR-4/6 O(1) hot path | partial | bounded loops only; task storage only |
| NFR-7/8 portability | none | CO-RE, libbpf, x86-64 + arm64 BPF builds in CI |
| NFR-9 API isolation | header existed but unused | `bpf/hush_compat.bpf.h` is the only file that names `scx_bpf_*` |
| NFR-10 reproducibility | synthetic | `bench/real/` harness writes raw CSV, the policy used, `uname -a` and the git commit |
| NFR-11 one command | sim only | `sudo hushd --policy policy.toml` |

---

## 2. Target architecture (as built)

```
user space                                   kernel (sched_ext)
──────────                                   ──────────────────
apps ── futex syscalls ─────────────────────► tp_btf/sys_enter, sys_exit   (tiers 2,3,fallback)
     ── libhush.so hush_critical_* ─────────► uprobes                       (tier 1)
                                              tp_btf/sched_process_exec     (re-classify on exec)
hushd (C, libbpf skeleton)                         │ writes task_ctx.boost_until
  ├ policy.toml ──► class_by_cgroup/comm/uid/pid   ▼
  ├ config map (slices, guard, gen, flags) ──► scx_hush struct_ops
  ├ stats (per-CPU) ◄───────────────────────────  select_cpu/enqueue/dispatch/
  ├ trace_rb (4 MiB) ◄──────────────────────────  running/stopping/tick/...
  ├ UEI exit info ◄─────────────────────────────  exit
  └ /run/hush.sock (NDJSON) ◄── hushctl (Python)   FG_DSQ(vtime) NORMAL_DSQ(vtime) BG_DSQ(FIFO)
```

### 2.1 Source layout

| Path | Purpose |
|---|---|
| `bpf/scx_hush.bpf.c` | Scheduler and hook programs |
| `bpf/hush_compat.bpf.h` | **NFR-9.** The only file that names sched_ext kfuncs and flags |
| `include/hush_intf.h` | ABI shared by BPF and user space (classes, structs, flags) |
| `hushd/` | C daemon: `main.c`, `policy.[ch]`, `cgroup.c`, `ctl.c`, `json.[ch]`, `selftest.c`, `util.[ch]` |
| `third_party/tomlc99/` | Vendored MIT TOML parser |
| `libhush/` | Hint library, built as `libhush.so` |
| `tools/` | `inversion_micro.c` (E5) and `periodic_loop.c` (E2/E9) |
| `cli/hushctl.py` | CLI. Unix socket by default, TCP fallback for the simulator on Windows |
| `scripts/fetch-deps.sh` | Fetches the pinned scx headers, `vmlinux.h`, libbpf and bpftool |
| `bench/real/` | Real evaluation harness (E1 to E9, B0 to B6) and the plotting script |
| `sim/`, `daemon/hushd.py`, `demo/` | Simulator, kept as a teaching and test backend. It speaks the same socket protocol |
| `tests/c/` | C unit tests for policy parsing and matching |

### 2.2 Key design decisions and deviations from the PRD

Each item records a decision the PRD left open or a place where the implementation goes
beyond the PRD text. The reason is given for each.

1. **Two extra classification maps: `class_by_uid` and `class_by_pid`.** FR-3 asks for uid rules and FR-5 asks for PID promotion. The PRD's seven maps cannot express either. Both are small hashes written only by `hushd`, so the PRD rule "user space writes only policy maps" still holds.
2. **Per-cgroup classes are resolved in user space.** `hushd` walks `/sys/fs/cgroup` and evaluates the rules in order. A rule also matches descendant cgroups. `hushd` stores the final class per cgroup ID. The BPF side therefore does one hash lookup, with no ancestor walk (NFR-4). New cgroups are picked up through inotify.
3. **Cgroup moves are caught without a hook.** `task_ctx` stores the cgroup ID the task was classified under. `enqueue` and `select_cpu` compare it with the task's current cgroup, two pointer reads, and re-classify on a mismatch. Comm changes are caught with `tp_btf/sched_process_exec`, so `cc1` started from a NORMAL shell becomes BACKGROUND, and with `tp_btf/task_rename` for `pthread_setname_np`. Both hooks only zero the task's `policy_gen`; re-classification then happens on the next enqueue.
4. **Hard guard (safety net beyond §7.5).** The per-CPU rate limit (one BG slice per CPU per guard interval) caps the cost to FG at about 1%. With many more BG tasks than CPUs, though, a FIFO can still keep the tail waiting past the watchdog timeout, and the kernel then ejects the scheduler. When the head of `BG_DSQ` has waited **more than half the watchdog timeout**, the guard ignores the rate limit. This path should never fire in normal operation. A counter records it (`hard_guard_firings`), and the soak test (E8) checks that it stays at zero.
5. **Hooks are `tp_btf`, not classic `tp/`.** The boost path needs `bpf_task_from_pid()` and `scx_bpf_kick_cpu()`. Those kfuncs exist for `BPF_PROG_TYPE_TRACING` but not for classic tracepoints. `tp_btf/sys_enter` fires on every syscall, so the first instruction filters on `__NR_futex`. The B5 ablation (`hushd --no-inversion`) does not attach these hooks at all.
6. **Uprobes do not kick CPUs.** Kprobe-type programs cannot call sched_ext kfuncs. A hinted task is running at the moment it calls `hush_critical_enter()`, so the uprobe only marks the local `cpu_ctx` as FOREGROUND. That stops the preemption scan from kicking the task off its CPU. The `tick` backstop handles the exit edge.
7. **The 10% cap covers every boost source, not only hints.** The window is a rolling 1 s of wall-clock time. Without this, a stuck futex boost could pin a BG task at FOREGROUND forever. Only denied *hint* calls increment `hint_abuse`, as §8.3 says.
8. **Pinned BG tasks stay in `BG_DSQ`.** §7.7 inserts every pinned task into its CPU's local DSQ. For a BG task that would bypass FR-6: a local DSQ runs ahead of `FG_DSQ`. `scx_bpf_dsq_move_to_local()` already skips tasks that cannot run on the consuming CPU, so pinned BG tasks are safe in the shared FIFO. Pinned FG/NORMAL tasks and per-CPU kthreads go to the local DSQ, as specified.
9. **Kernel-API compatibility uses the scx project headers.** `hush_compat.bpf.h` wraps the scx `common.bpf.h` and `compat.bpf.h` at a pinned commit. Those headers already carry `___compat` fallbacks for renamed kfuncs, such as `scx_bpf_dispatch` → `scx_bpf_dsq_insert` and `move_to_local` gaining `enq_flags` in v7.1. Re-implementing them would repeat the bug class NFR-9 describes.
10. **Tier 3 is gated by selftest.** `hushd` runs the glibc layout check at start-up (§8.4). It sets `HUSH_F_TIER3` in `config.flags` only when the check passes.
11. **The simulator is kept, but labelled.** The synthetic CSVs and report in `bench/results/` and `reports/` are now marked *synthetic model output* in the README, and real measurements go to `bench/real/results/`. Synthetic numbers must not be cited as evaluation results.
12. **The guard also covers `NORMAL_DSQ`.** Sustained FG saturation would otherwise starve NORMAL tasks, kernel threads included, until the watchdog ejected the scheduler. NORMAL heads get the same per-CPU rate-limited slice (`guard_normal` counter). FR-9 is unaffected: BACKGROUND never preempts NORMAL.
13. **Guard slices are protected.** A task granted a guard slice is marked `HUSH_TF_GUARDED`. Neither the §7.4 scan nor the `tick` backstop evicts it, or the guarantee would last only until the next tick.
14. **The control socket checks privilege.** `/run/hush.sock` is mode 0666 so that `status` and `class` work for any user. `promote`, `demote`, `reset`, `reload`, `trace` and `selftest` require a root peer (`SO_PEERCRED`).
15. **Two kernel-free modes.** `hushd --dry-run` prints the resolved policy (comm, uid and every classified cgroup) and exits. `hushd --no-load` runs the full control plane (socket, inotify, reload, overrides) without loading BPF, which lets CI integration-test it on any kernel.
16. **One clock domain.** Kprobe-type programs (uprobes) cannot call `scx_bpf_now()`, and their timestamps are compared in scheduler callbacks, so every BPF timestamp uses `bpf_ktime_get_ns()`. `hushctl class` uses `CLOCK_MONOTONIC`, the same clock.
17. **Futex owners are checked.** The owner TID is read from user memory, so a FOREGROUND waiter could name any task. A glibc owner must be in the waiter's process. A PI owner must be in the waiter's process or have the same euid. Without this, one user could lend FOREGROUND to another user's task.

---

## 3. Work breakdown

### P0 — Repository hygiene and toolchain *(PRD Gate 1 prerequisites)*
- Remove committed `__pycache__` files.
- Add `scripts/fetch-deps.sh` with pinned versions: scx `d65d9eb`, bpftool `v7.8.1` with libbpf `v1.8`. It also picks the `vmlinux.h`: the host's BTF when it contains `sched_ext_ops`, else the vendored scx copy.
- Add a top-level `Makefile` with targets `deps`, `all`, `bpf`, `hushd`, `libhush`, `tools`, `test`, `install` and `clean`. It cross-builds the BPF object for `ARCH=x86|arm64`.
- **Exit:** `make` produces `build/scx_hush.bpf.o`, `build/hush.skel.h`, `build/hushd`, `build/libhush.so` and `build/tools/*` on a clean Ubuntu 24.04.

### P1 — Core scheduler *(Gate 2)*
- `include/hush_intf.h`: classes, `task_ctx`, `cpu_ctx`, `hush_config`, `hush_stats` and `trace_event`, with fixed-width layout.
- `bpf/scx_hush.bpf.c`: three DSQs; `select_cpu` direct insert on idle; `enqueue` with re-classification and the §7.4 preemption scan; strict `dispatch`; `running` and `stopping` with weighted vtime; `tick` backstop; kthread and pinned rules; `init` and `exit` with UEI.
- **Exit:** the object compiles for x86-64 and arm64 with clang ≥ 17, and the skeleton generates. *On hardware:* FG p99 beats nice 19 in a first E1 run.

### P2 — Starvation guard and control plane *(Gate 3)*
- Guard: head-age check, per-CPU rate limit, hard guard.
- `hushd`: TOML policy and validation (`guard_ms ≤ watchdog_ms/4`, slice bounds, class names); cgroup resolution and inotify; comm, uid and PID maps; SIGHUP and `reload`; generation counter; stats aggregation; Unix-socket NDJSON server; trace ring-buffer drain to CSV; UEI exit report; `--dry-run` and `--selftest` modes that work without sched_ext.
- `hushctl`: Unix socket `/run/hush.sock` (override with `$HUSH_SOCK`); `status`, `class`, `promote`, `demote`, `reload`, `selftest` and `trace start|stop`.
- **Exit:** C unit tests for policy parsing, glob matching and validation pass. `hushd --dry-run` prints the resolved maps. *On hardware:* no BG wait exceeds the guard and the stress test has zero aborts.

### P3 — Priority inversion *(Gate 4, MVP)*
- Tier 1: uprobes on `libhush.so`, crit-depth nesting, cap, `hint_abuse`.
- Tier 2: `FUTEX_LOCK_PI` / `LOCK_PI2` owner TID from the futex word.
- Tier 3: `FUTEX_WAIT` owner from the glibc `__owner` field at offset 8, with a same-tgid check, gated by selftest.
- Fallback: an LRU map of recent BG threads per process, boosting those that ran in the last 10 ms.
- Boost lifecycle: `boost_until = now + boost_ms`, `boost_pending`, a dispatch walk over the first 64 entries of `BG_DSQ`, a kick, release on `FUTEX_WAKE`/`UNLOCK_PI`/`critical_exit`, expiry, and renewal while the waiter is still blocked.
- Tier 4 (Could): D-state escape window.
- **Exit:** the BPF object compiles with every hook. `tools/inversion_micro` builds with `pi`, `glibc` and `hinted` modes. *On hardware:* E5 shows bounded blocking for B6 against B5.

### P4 — Evaluation harness *(Gate 5 tooling)*
- `bench/real/run.py`: sets up baselines B0 to B6 (nice 19, `chrt -i 0`, a `cpu.idle` cgroup, `hushd --no-inversion`, `hushd`); runs workloads E1 to E9 with reps, warm-up, duration and seed; writes raw CSV plus `meta.json` (policy, `uname -a`, git commit, CPU governor).
- `bench/real/plot.py`: the five figures in PRD §12.5.
- `tools/periodic_loop.c`: 100 Hz loop that writes per-cycle deviation.
- **Exit:** `run.py --dry-run` prints the full experiment matrix. On hardware it produces CSV and figures.

### P5 — CI, docs, safety
- GitHub Actions: build BPF for x86-64 and arm64, build `hushd`/`libhush`/tools, run the C unit tests and pytest.
- README rewrite covering build, run, safety (SysRq-S, `/sys/kernel/sched_ext/state`) and the synthetic-vs-real data labelling.
- **Exit:** CI green.

### P6 — On-hardware validation *(needs a sched_ext kernel, not doable in this container)*
- Boot Linux ≥ 6.12 with `CONFIG_SCHED_CLASS_EXT=y` (QEMU/virtme-ng or bare metal).
- Gate check after every phase: `sudo scripts/stress-gate.sh 1800` (stress-ng on all CPUs plus a fork bomb confined by pids.max; checks that the scheduler stays loaded, that no hard guard fires, and that it unloads cleanly).
- Run the verifier load, then 30-minute `stress-ng` plus fork-bomb-limited cgroup runs after each gate (§11), then E1 to E9 with 5 reps each, then the 24 h soak (E8).
- Tune the slices and the guard default from E6.
- Answer the PRD §14 open questions: NORMAL preemption, `BG_DSQ` sharding past 16 CPUs, and kick latency under 100 µs.

---

## 4. Verification strategy

| Level | What | Where |
|---|---|---|
| Static | BPF compiles for two arches against sched_ext BTF; skeleton generates | `make bpf`, CI |
| Unit (C) | TOML parse, validation (FR-12), glob/ancestor matching, first-match order, override precedence | `make test` → `tests/c/test_policy` |
| Unit (Py) | Simulator semantics, CLI protocol | `pytest` |
| Integration (no kernel) | `hushd --no-load` driven over its socket: status, class, overrides, reload (rejected and accepted), SIGHUP, inotify, malformed JSON; `--dry-run` cgroup resolution; `run.py --dry-run` | `tests/test_hushd_c.py`, CI |
| Harness smoke | `run.py` on real processes for B0 to B3: cgroups, nice, SCHED_IDLE, cpu.stat accounting, summary, figures | manual, as root |
| Kernel (P6) | load and verifier, stress, E1 to E9, soak | `bench/real/`, sched_ext machine |

**Not verified in this change:** loading the scheduler. The development container's kernel
(6.18, without `CONFIG_SCHED_CLASS_EXT`) cannot load sched_ext programs, so verifier
acceptance and runtime behaviour must be checked in P6. Static compilation catches type and
API errors. It cannot catch verifier rejections, such as an unbounded-loop proof or a
pointer-provenance issue.

---

## 5. Risks specific to the implementation

| Risk | Mitigation in code |
|---|---|
| Verifier rejects the DSQ walk or CPU scan | `bpf_for` / `bpf_for_each(scx_dsq)` with constant caps (64, `nr_cpu_ids` ≤ 512) |
| `tp_btf/sys_enter` overhead | Filter on the syscall number first; B5 / `--no-inversion` skips attaching; measured in E7 |
| glibc layout varies | selftest gates tier 3; same-tgid validation on every read |
| PID namespaces (containers) | `bpf_task_from_pid` uses the init namespace. Documented limitation: tiers 2/3 only resolve owners in the root namespace |
| Kernel API drift after the pinned scx commit | Bump `SCX_COMMIT` in `fetch-deps.sh`; CI builds against the vendored BTF |
