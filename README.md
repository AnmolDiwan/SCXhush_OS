# scx_hush — Unfair-by-Design Scheduler

A complete implementation of the **scx_hush** scheduler derived from the *scx_hush PRD & Architecture (Oct 22, 2026)*.

`scx_hush` guarantees that background work runs only on CPU cycles that foreground work does not want. It generalizes the UFS design (arXiv 2605.02377) from databases to any machine mixing latency-critical and background tasks (laptops, robots, servers).

---

## 🌟 Key Architecture & Novelty

1. **Strict Foreground Isolation**:
   - Runnable foreground tasks never wait behind background work.
   - Immediate core preemption via `scx_bpf_kick_cpu(cpu, SCX_KICK_PREEMPT)` and timer tick backstop.
2. **Work Conservation**:
   - Background tasks consume idle CPU cycles when foreground work is not queued (`select_cpu` fast-path).
3. **Bounded Starvation Guard**:
   - No background task waits longer than the configurable guard interval (default `2.0 s`).
   - Rate-limited per CPU (at most 1 slice per CPU per guard interval, bounded to $\le 1\%$).
4. **4-Tier Priority Inversion Handling**:
   - **Tier 1 (Hints)**: `libhush` (`hush_critical_enter` / `exit`) via eBPF uprobes.
   - **Tier 2 (PI Futexes)**: Tracepoint on futex syscalls with `FUTEX_LOCK_PI`.
   - **Tier 3 (glibc Mutexes)**: Heuristic owner thread ID extraction from mutex struct.
   - **Tier 4 (D-State Escape)**: Relaxes background throttling if foreground task stays in uninterruptible sleep $> 10\text{ ms}$.
   - **Fallback**: Boosts background threads of the same process that ran in the last $10\text{ ms}$.
   - **Abuse Cap**: Limits cumulative boost time to $10\%$ per second.
5. **Userspace Control Plane & CLI**:
   - `hushd`: Daemon managing policy, cgroup resolution, and socket IPC (`/run/hush.sock` / localhost).
   - `hushctl`: Status, dynamic promotion/demotion, policy hot-reload (`SIGHUP`), and selftest.

---

## 📂 Repository Layout

```
scx_hush/
├── bpf/
│   ├── scx_hush.bpf.c          # Verified kernel eBPF scheduler implementing sched_ext_ops
│   └── vmlinux.h               # Kernel symbol headers
├── include/
│   ├── scx_hush_types.h        # Shared data structures (task_ctx, cpu_ctx, config, stats)
│   └── scx_compat.h            # Kernel API isolation and compatibility shims (NFR-9)
├── libhush/
│   ├── libhush.h               # Hint API header
│   └── libhush.c               # Application hint library (.so / .dll)
├── config/
│   └── policy.toml             # Configuration & classification rules
├── daemon/
│   └── hushd.py                # Userspace daemon and control plane (FR-2, FR-20)
├── cli/
│   └── hushctl.py              # hushctl CLI utility (status, promote, demote, reload, selftest)
├── sim/
│   └── scheduler_core.py       # High-fidelity discrete-event scheduler execution engine
├── bench/
│   ├── workloads.py            # Laptop, Robot, Database, Inversion benchmark generators
│   ├── run_experiments.py      # Master benchmark runner for Experiments E1 - E9
│   ├── report_generator.py     # Static Plotly interactive HTML report generator
│   └── results/                # Raw benchmark CSV results
├── reports/
│   └── scx_hush_evaluation.html# Interactive Plotly evaluation dashboard (5 figures from PRD §12.5)
├── tests/                      # Pytest unit & integration test suite (17 passed)
└── hushctl.bat                 # Windows CLI wrapper
```

---

## 🚀 Quick Start & Demo

### 1. Run All Tests
```powershell
python -m pytest tests/ -v
```

### 2. Run Comprehensive Benchmarks (E1 - E9)
```powershell
python bench/run_experiments.py
```
This executes:
- **E1**: Foreground tail latency isolation (Laptop workload, B0–B6)
- **E2**: 100 Hz control-loop timing jitter (Robot workload)
- **E3**: Database UFS reproduction (PostgreSQL + vacuum)
- **E4**: Background idle progress
- **E5**: Priority inversion recovery across mutex types
- **E6**: Starvation guard interval sweep (0.5s – 4.0s)
- **E7**: Scheduler overhead (<2% target)
- **E8**: 24-hour soak stability test (0 watchdog aborts)
- **E9**: Embedded hardware profile

### 3. Generate Interactive Evaluation Dashboard
```powershell
python bench/report_generator.py
```
View the resulting interactive Plotly dashboard at:
`reports/scx_hush_evaluation.html`

### 4. Interactive CLI Demo
Start the daemon:
```powershell
python daemon/hushd.py
```
In another terminal, interact via `hushctl`:
```powershell
# Check status and per-class metrics
python cli/hushctl.py status

# Inspect task classification
python cli/hushctl.py class 100

# Dynamically promote or demote tasks
python cli/hushctl.py promote 100
python cli/hushctl.py demote 100

# Hot-reload policy file without scheduler unload
python cli/hushctl.py reload

# Run compatibility selftest
python cli/hushctl.py selftest
```

