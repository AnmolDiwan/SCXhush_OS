#!/usr/bin/env python3
"""
hush_top - Real-time terminal visualizer for scx_hush
Displays live CPU cores, queue depths, and per-class metrics in terminal.
"""

import os
import sys
import time
from pathlib import Path

# Add project root
sys.path.insert(0, str(Path(__file__).parent.parent))

from sim.scheduler_core import ScxHushScheduler, CLASS_FOREGROUND, CLASS_BACKGROUND, CLASS_NAMES

def main():
    sched = ScxHushScheduler(nr_cpus=4)
    policy_path = Path(__file__).parent.parent / "config" / "policy.toml"
    sched.load_policy(str(policy_path))

    # Prepopulate tasks
    for i in range(1, 4):
        sched.enqueue(sched.register_task(100+i, 100+i, f"fg_task_{i}", "/user.slice"), 0.0)
    for i in range(1, 7):
        sched.enqueue(sched.register_task(200+i, 200+i, f"bg_build_{i}", "/system.slice"), 0.0)

    sim_time = 0.0

    try:
        while True:
            sim_time += 0.05
            sched.tick(sim_time)
            for i in range(4):
                if sched.cpus[i].cur_task is None:
                    sched.dispatch(i, sim_time)

            # Clear terminal
            os.system('cls' if os.name == 'nt' else 'clear')

            print("="*65)
            print("        scx_hush — Live Terminal Scheduler Monitor (htop-style)")
            print("="*65)
            print(f" Sim Time: {sim_time:8.2f}s | Guard: {sched.guard_sec:.1f}s | Watchdog: 8.0s (OK)")
            print("-"*65)
            print(" CPU Cores (sched_ext Dispatch):")
            for c in sched.cpus:
                t_comm = c.cur_task.comm if c.cur_task else "[IDLE]"
                t_cls = CLASS_NAMES.get(c.cur_class, "IDLE")
                bar = "██████████" if c.cur_task else "░░░░░░░░░░"
                print(f"   Core {c.cpu_id} [{bar}] {t_cls:<11} -> {t_comm}")

            print("-"*65)
            print(f" Queues: FG_DSQ: {len(sched.fg_dsq)}  |  NORMAL_DSQ: {len(sched.normal_dsq)}  |  BG_DSQ: {len(sched.bg_dsq)}")
            print(f" Stats:  Guard Firings: {sched.stats['guard_firings']} | Boosts: {sched.stats['boost_count']} | BG Preempts: {sched.stats['preemptions'][CLASS_BACKGROUND]}")
            print("="*65)
            print(" Press Ctrl+C to exit monitor")

            time.sleep(0.3)
    except KeyboardInterrupt:
        print("\nExited monitor.")

if __name__ == "__main__":
    main()
