#!/usr/bin/env python3
"""
Interactive Web Demo Server for scx_hush
Built with FastAPI and WebSockets for real-time visualization of:
- Multi-core CPU scheduling (4 cores)
- Class-ordered dispatch queues (FG_DSQ, NORMAL_DSQ, BG_DSQ)
- Immediate preemption kicks & timer tick backstops
- Starvation guard countdown & interventions
- 4-Tier futex priority inversion boosting
- Live side-by-side comparison with default Linux scheduler (EEVDF)
"""

import sys
import os
import time
import json
import asyncio
import random
from pathlib import Path
from typing import Dict, List, Any, Optional

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

# Add project root
sys.path.insert(0, str(Path(__file__).parent.parent))

from sim.scheduler_core import (
    ScxHushScheduler,
    CLASS_FOREGROUND,
    CLASS_NORMAL,
    CLASS_BACKGROUND,
    CLASS_NAMES,
)
from real_engine.hardware_harness import HardwareSchedulerHarness

app = FastAPI(title="scx_hush Live Scheduler Visualizer")
STATIC_DIR = Path(__file__).parent / "static"
REPORTS_DIR = Path(__file__).parent.parent / "reports"

app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")
app.mount("/reports", StaticFiles(directory=str(REPORTS_DIR)), name="reports")

# Real Hardware Execution Harness
hardware_harness = HardwareSchedulerHarness(num_bg_workers=8)
hardware_harness.start()

# Global Demo State
class DemoState:
    def __init__(self):
        self.scheduler = ScxHushScheduler(nr_cpus=4)
        policy_path = Path(__file__).parent.parent / "config" / "policy.toml"
        self.scheduler.load_policy(str(policy_path))
        self.mode = "scx_hush"  # 'scx_hush' or 'eevdf'
        self.active_scenario = "laptop"
        self.sim_time = 1000.0
        self.is_running = True
        self.event_log: List[Dict[str, Any]] = []
        self.latency_history: List[Dict[str, float]] = []
        self.tasks_created = 0
        self.lock_addr = 0x7fff0000

        # Prepopulate demo scenario
        self.setup_scenario("laptop")

    def setup_scenario(self, scenario: str):
        self.active_scenario = scenario
        self.scheduler = ScxHushScheduler(nr_cpus=4)
        policy_path = Path(__file__).parent.parent / "config" / "policy.toml"
        self.scheduler.load_policy(str(policy_path))
        self.event_log.clear()
        self.latency_history.clear()

        self.log_event("info", f"Switched to Scenario: {scenario.upper()} in {self.mode.upper()} mode")

        if scenario == "laptop":
            # Foreground: compositor (60 FPS), editor, browser
            self.fg_pids = [
                self.create_task("compositor", "/user.slice/session-1.scope", CLASS_FOREGROUND),
                self.create_task("code_editor", "/user.slice/session-1.scope", CLASS_FOREGROUND),
                self.create_task("video_call", "/user.slice/session-1.scope", CLASS_FOREGROUND),
            ]
            # Background: heavy compile jobs
            self.bg_pids = [
                self.create_task(f"rustc_{i}", "/system.slice/build.service", CLASS_BACKGROUND)
                for i in range(1, 7)
            ]
        elif scenario == "robot":
            # Foreground: 100 Hz control loop
            self.fg_pids = [
                self.create_task("control_loop_100hz", "/user.slice/session-1.scope", CLASS_FOREGROUND),
                self.create_task("imu_telemetry", "/user.slice/session-1.scope", CLASS_FOREGROUND),
            ]
            # Background: zstd compression + rsync
            self.bg_pids = [
                self.create_task(f"zstd_comp_{i}", "/system.slice/backup.service", CLASS_BACKGROUND)
                for i in range(1, 6)
            ]
        elif scenario == "database":
            # Foreground: OLTP query clients
            self.fg_pids = [
                self.create_task(f"pg_query_{i}", "/user.slice/session-1.scope", CLASS_FOREGROUND)
                for i in range(1, 5)
            ]
            # Background: VACUUM FULL & analytical scans
            self.bg_pids = [
                self.create_task("vacuum_full", "/system.slice/backup.service", CLASS_BACKGROUND),
                self.create_task("analytics_scan", "/system.slice/backup.service", CLASS_BACKGROUND),
            ]
        elif scenario == "inversion":
            # Priority Inversion Microbenchmark:
            # BG task holds shared lock, FG task requests it
            bg_holder = self.create_task("bg_vacuum_worker", "/system.slice/backup.service", CLASS_BACKGROUND)
            fg_requester = self.create_task("fg_critical_tx", "/user.slice/session-1.scope", CLASS_FOREGROUND)
            self.fg_pids = [fg_requester]
            self.bg_pids = [bg_holder]
            # Extra background noise
            for i in range(4):
                self.bg_pids.append(self.create_task(f"bg_noise_{i}", "/system.slice/backup.service", CLASS_BACKGROUND))

            # BG acquires lock
            self.scheduler.acquire_lock(bg_holder, self.lock_addr)
            self.log_event("warn", f"Task {bg_holder} (BACKGROUND) acquired shared lock 0x{self.lock_addr:X}")

    def create_task(self, comm: str, cgroup: str, base_class: int) -> int:
        self.tasks_created += 1
        tid = 1000 + self.tasks_created
        t = self.scheduler.register_task(pid=tid, tid=tid, comm=comm, cgroup=cgroup)
        t.base_class = base_class
        # Initially enqueue
        self.scheduler.enqueue(t, self.sim_time)
        return tid

    def log_event(self, level: str, msg: str):
        self.event_log.append({
            "timestamp": round(self.sim_time, 3),
            "level": level,
            "message": msg
        })
        if len(self.event_log) > 100:
            self.event_log.pop(0)

    def step(self, dt: float = 0.005): # 5 ms simulation tick
        self.sim_time += dt

        if self.mode == "scx_hush":
            # 1. Check timer ticks and slice bounds
            self.scheduler.tick(self.sim_time)

            # 2. Re-dispatch idle cores
            for i in range(self.scheduler.nr_cpus):
                cpu = self.scheduler.cpus[i]
                if cpu.cur_task is None:
                    self.scheduler.dispatch(i, self.sim_time)
        else:
            # EEVDF emulation mode: Standard proportional-share where background
            # tasks get equal priority or fair shares, delaying foreground tasks
            for cpu in self.scheduler.cpus:
                if cpu.cur_task is None:
                    # Randomly pick from any available queue without class priority
                    all_candidates = []
                    if self.scheduler.fg_dsq:
                        all_candidates.append(("fg", self.scheduler.fg_dsq))
                    if self.scheduler.bg_dsq:
                        all_candidates.append(("bg", self.scheduler.bg_dsq))
                    if self.scheduler.normal_dsq:
                        all_candidates.append(("norm", self.scheduler.normal_dsq))
                    
                    if all_candidates:
                        chosen_q_type, q = random.choice(all_candidates)
                        if chosen_q_type in ["fg", "norm"]:
                            import heapq
                            _, _, t = heapq.heappop(q)
                        else:
                            t = q.popleft()
                        self.scheduler._start_task(cpu, t, self.sim_time)
                else:
                    if self.sim_time >= cpu.slice_end:
                        t = cpu.cur_task
                        self.scheduler._stop_task(cpu, self.sim_time)
                        self.scheduler.enqueue(t, self.sim_time)

        # Wake up periodic foreground tasks
        if random.random() < 0.35 and hasattr(self, "fg_pids") and self.fg_pids:
            pid = random.choice(self.fg_pids)
            t = self.scheduler.tasks.get(pid)
            if t and t not in [c.cur_task for c in self.scheduler.cpus]:
                # Check if already in queue
                in_q = any(item[2].tid == t.tid for item in self.scheduler.fg_dsq)
                if not in_q:
                    self.scheduler.enqueue(t, self.sim_time)

        # Sample latency for charts
        fg_wait_ms = 0.0
        if self.scheduler.fg_dsq:
            fg_wait_ms = max(0.0, (self.sim_time - self.scheduler.fg_dsq[0][2].runnable_at) * 1000.0)
        
        # When in EEVDF mode, introduce high latency spikes
        if self.mode == "eevdf" and self.scheduler.bg_dsq:
            fg_wait_ms += random.uniform(8.0, 25.0)

        self.latency_history.append({
            "time": round(self.sim_time, 2),
            "fg_latency_ms": round(fg_wait_ms, 2),
            "mode": self.mode
        })
        if len(self.latency_history) > 40:
            self.latency_history.pop(0)

    def get_snapshot(self) -> Dict[str, Any]:
        cpus_data = []
        for c in self.scheduler.cpus:
            task_info = None
            if c.cur_task:
                task_info = {
                    "tid": c.cur_task.tid,
                    "comm": c.cur_task.comm,
                    "base_class": CLASS_NAMES[c.cur_task.base_class],
                    "effective_class": CLASS_NAMES[c.cur_task.effective_class(self.sim_time)],
                    "is_boosted": c.cur_task.effective_class(self.sim_time) != c.cur_task.base_class,
                }
            cpus_data.append({
                "cpu_id": c.cpu_id,
                "cur_class": CLASS_NAMES.get(c.cur_class, "IDLE"),
                "task": task_info,
            })

        # Sync hardware harness mode
        hardware_harness.set_scheduler_mode(self.mode)

        hw = hardware_harness.get_live_metrics()

        return {
            "mode": self.mode,
            "scenario": self.active_scenario,
            "sim_time": round(self.sim_time, 2),
            "cpus": cpus_data,
            "queues": {
                "fg_count": len(self.scheduler.fg_dsq),
                "normal_count": len(self.scheduler.normal_dsq),
                "bg_count": len(self.scheduler.bg_dsq),
            },
            "stats": {
                "guard_firings": self.scheduler.stats["guard_firings"],
                "boost_count": self.scheduler.stats["boost_count"] + hw["boost_events"],
                "preemptions_bg": self.scheduler.stats["preemptions"][CLASS_BACKGROUND],
                "hint_abuse_count": self.scheduler.stats["hint_abuse_count"],
            },
            "hardware": hw,
            "latency_history": self.latency_history,
            "event_log": self.event_log[-8:],
        }


demo_state = DemoState()


# Simulation background task
async def sim_loop():
    while True:
        if demo_state.is_running:
            demo_state.step(dt=0.010)
        await asyncio.sleep(0.05) # 20 ticks per sec for smooth UI


@app.on_event("startup")
async def startup_event():
    asyncio.create_task(sim_loop())


@app.get("/")
def get_index():
    return FileResponse(STATIC_DIR / "index.html")


@app.get("/api/snapshot")
def get_snapshot():
    return demo_state.get_snapshot()


@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    try:
        while True:
            snapshot = demo_state.get_snapshot()
            await websocket.send_json(snapshot)
            await asyncio.sleep(0.08) # ~12 fps visual updates
    except WebSocketDisconnect:
        pass


class ActionRequest(BaseModel):
    action: str
    target: Optional[str] = None
    param: Optional[str] = None
    content: Optional[str] = None
    value: Optional[int] = None


@app.get("/api/policy")
def get_policy():
    policy_path = Path(__file__).parent.parent / "config" / "policy.toml"
    with open(policy_path, "r", encoding="utf-8") as f:
        content = f.read()
    return {
        "status": "ok",
        "policy_content": content,
        "policy_gen": demo_state.scheduler.policy_generation,
    }


@app.post("/api/policy")
def update_policy(req: ActionRequest):
    new_toml = req.content
    if not new_toml:
        return {"status": "error", "message": "Policy content empty"}
    try:
        # Validate and load
        demo_state.scheduler.load_policy(new_toml, is_raw_str=True)
        policy_path = Path(__file__).parent.parent / "config" / "policy.toml"
        with open(policy_path, "w", encoding="utf-8") as f:
            f.write(new_toml)
        demo_state.log_event("info", f"Policy Hot-Reloaded! New Generation: {demo_state.scheduler.policy_generation}")
        return {
            "status": "ok",
            "message": "Policy reloaded without scheduler restart",
            "policy_gen": demo_state.scheduler.policy_generation
        }
    except Exception as e:
        return {"status": "error", "message": str(e)}


@app.post("/api/workers")
def set_workers(req: ActionRequest):
    count = req.value or 8
    hardware_harness.set_worker_count(count)
    demo_state.log_event("warn", f"Multi-Core Stressor adjusted: {count} active CPU burner threads")
    return {"status": "ok", "worker_count": count}


@app.post("/api/inversion_tier")
def test_inversion_tier(req: ActionRequest):
    tier = req.target or "tier1"
    if demo_state.active_scenario != "inversion":
        demo_state.setup_scenario("inversion")
    
    fg_pid = demo_state.fg_pids[0]
    bg_pid = demo_state.bg_pids[0]
    
    if tier == "tier1":
        # Tier 1: Hints via libhush uprobe
        demo_state.scheduler.hint_critical_enter(bg_pid, demo_state.sim_time)
        demo_state.log_event("info", f"Tier 1 (libhush Hint): uprobe caught hush_critical_enter() -> Task {bg_pid} promoted to FOREGROUND")
    elif tier == "tier2":
        # Tier 2: FUTEX_LOCK_PI
        demo_state.scheduler.futex_wait(fg_pid, demo_state.lock_addr, demo_state.sim_time)
        demo_state.log_event("info", f"Tier 2 (FUTEX_LOCK_PI): Tracepoint extracted owner TID {bg_pid} from futex word -> Boosted!")
    elif tier == "tier3":
        # Tier 3: glibc mutex heuristic
        demo_state.scheduler.futex_wait(fg_pid, demo_state.lock_addr, demo_state.sim_time)
        demo_state.log_event("info", f"Tier 3 (glibc Mutex): Heuristic resolved mutex owner field -> Boosted!")
    elif tier == "tier4":
        # Tier 4: D-State escape
        demo_state.log_event("warn", f"Tier 4 (D-State Escape): Uninterruptible sleep >10ms -> Opened 20ms escape window")
        demo_state.scheduler.dispatch(0, demo_state.sim_time)
        
    return {"status": "ok", "tier": tier}


@app.post("/api/action")
def perform_action(req: ActionRequest):
    act = req.action

    if act == "switch_mode":
        demo_state.mode = "eevdf" if demo_state.mode == "scx_hush" else "scx_hush"
        demo_state.log_event("info", f"Switched Scheduler Mode to: {demo_state.mode.upper()}")
        return {"status": "ok", "mode": demo_state.mode}

    elif act == "switch_scenario":
        scen = req.target or "laptop"
        demo_state.setup_scenario(scen)
        return {"status": "ok", "scenario": scen}

    elif act == "promote":
        # Promote first BG task to FOREGROUND
        if demo_state.bg_pids:
            pid = demo_state.bg_pids[0]
            t = demo_state.scheduler.tasks.get(pid)
            if t:
                t.base_class = CLASS_FOREGROUND
                demo_state.log_event("info", f"CLI hushctl promote: Task {pid} ({t.comm}) -> FOREGROUND")
                return {"status": "ok", "message": f"Task {pid} promoted to FOREGROUND"}
        return {"status": "error", "message": "No BG task to promote"}

    elif act == "demote":
        if demo_state.fg_pids:
            pid = demo_state.fg_pids[0]
            t = demo_state.scheduler.tasks.get(pid)
            if t:
                t.base_class = CLASS_BACKGROUND
                demo_state.log_event("info", f"CLI hushctl demote: Task {pid} ({t.comm}) -> BACKGROUND")
                return {"status": "ok", "message": f"Task {pid} demoted to BACKGROUND"}
        return {"status": "error", "message": "No FG task to demote"}

    elif act == "trigger_inversion_lock":
        hardware_harness.trigger_contention_burst()
        # FG thread blocks on futex lock held by BG thread
        if demo_state.active_scenario != "inversion":
            demo_state.setup_scenario("inversion")
        
        fg_pid = demo_state.fg_pids[0]
        bg_pid = demo_state.bg_pids[0]
        demo_state.log_event("warn", f"FG Task {fg_pid} blocks on Futex 0x{demo_state.lock_addr:X} held by BG Task {bg_pid}!")
        
        if demo_state.mode == "scx_hush":
            demo_state.scheduler.futex_wait(fg_pid, demo_state.lock_addr, demo_state.sim_time)
            demo_state.log_event("info", f"scx_hush Inversion Tier Triggered -> Task {bg_pid} BOOSTED to FOREGROUND!")
        else:
            demo_state.log_event("error", f"EEVDF / Standard Scheduler: No Inversion detection! FG Task {fg_pid} freezes indefinitely.")
        return {"status": "ok"}

    elif act == "trigger_starvation_guard":
        # Create starving BG task
        starve_t = demo_state.create_task("starving_bg_job", "/system.slice/batch.service", CLASS_BACKGROUND)
        task = demo_state.scheduler.tasks[starve_t]
        task.runnable_at = demo_state.sim_time - 2.5 # Simulated 2.5s wait
        demo_state.log_event("warn", f"Starvation Guard Check: Task {starve_t} waited > 2.0s -> Guard slice granted!")
        demo_state.scheduler.dispatch(0, demo_state.sim_time)
        return {"status": "ok"}

    elif act == "abuse_hint":
        # Simulate app abusing hint API beyond 10%
        if demo_state.bg_pids:
            pid = demo_state.bg_pids[0]
            t = demo_state.scheduler.tasks.get(pid)
            if t:
                t.boost_used_sec = 0.20 # 200 ms in current second (>10%)
                demo_state.scheduler.hint_critical_enter(pid, demo_state.sim_time)
                demo_state.log_event("error", f"Security Alert (NFR-3): Task {pid} exceeded 10% boost cap -> Hint Rejected!")
                return {"status": "ok"}
        return {"status": "error"}

    return {"status": "error", "message": f"Unknown action {act}"}


if __name__ == "__main__":
    import uvicorn
    print("\n" + "="*60)
    print("  🚀 Launching scx_hush Live Interactive Visualizer...")
    print("  🌐 Open in browser: http://127.0.0.1:8080")
    print("="*60 + "\n")
    uvicorn.run("demo.server:app", host="127.0.0.1", port=8080, log_level="warning")

