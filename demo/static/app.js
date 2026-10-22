// WebSocket Client & Live Dashboard Logic for scx_hush

let ws;
let currentMode = "scx_hush";
let latencyTimes = [];
let latencyValues = [];
let isPlotInitialized = false;

function initWebSocket() {
    const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
    const wsUrl = `${protocol}//${window.location.host}/ws`;

    ws = new WebSocket(wsUrl);

    ws.onmessage = function (event) {
        const data = JSON.parse(event.data);
        updateDashboard(data);
    };

    ws.onclose = function () {
        setTimeout(initWebSocket, 1000);
    };
}

function updateDashboard(data) {
    currentMode = data.mode;

    // Update Mode Button & Tag
    const modeBtn = document.getElementById("btn-toggle-mode");
    const modeText = document.getElementById("mode-text");
    const compTag = document.getElementById("chart-comparison-tag");

    if (data.mode === "scx_hush") {
        modeBtn.className = "mode-badge mode-hush";
        modeText.innerText = "scx_hush (Active)";
        compTag.className = "badge-hush";
        compTag.innerText = "Strict Isolation Mode";
    } else {
        modeBtn.className = "mode-badge mode-eevdf";
        modeText.innerText = "Default EEVDF (Standard Linux)";
        compTag.className = "badge-eevdf-alert";
        compTag.innerText = "Proportional Fair-Share (Jitter Spikes)";
    }

    // Update Quick Stats
    document.getElementById("stat-guard").innerText = data.stats.guard_firings;
    document.getElementById("stat-boosts").innerText = data.stats.boost_count;
    document.getElementById("stat-preempts").innerText = data.stats.preemptions_bg;
    document.getElementById("stat-abuse").innerText = data.stats.hint_abuse_count;

    // Update Queues (DSQs)
    document.getElementById("count-fg").innerText = data.queues.fg_count;
    document.getElementById("count-normal").innerText = data.queues.normal_count;
    document.getElementById("count-bg").innerText = data.queues.bg_count;

    // Update Cores
    const coresContainer = document.getElementById("cores-container");
    coresContainer.innerHTML = "";
    data.cpus.forEach(cpu => {
        const coreDiv = document.createElement("div");
        coreDiv.className = "core-card";

        let badgeClass = "badge-idle";
        let taskName = "Idle (Waiting dispatch)";
        let badgeText = "IDLE";

        if (cpu.task) {
            taskName = cpu.task.comm;
            if (cpu.task.is_boosted) {
                badgeClass = "badge-boosted";
                badgeText = "BOOSTED (PI)";
            } else if (cpu.task.effective_class === "FOREGROUND") {
                badgeClass = "badge-fg";
                badgeText = "FOREGROUND";
            } else if (cpu.task.effective_class === "NORMAL") {
                badgeClass = "badge-normal";
                badgeText = "NORMAL";
            } else {
                badgeClass = "badge-bg";
                badgeText = "BACKGROUND";
            }
        }

        coreDiv.innerHTML = `
            <div class="core-header">
                <span>CPU ${cpu.cpu_id}</span>
                <span class="core-badge ${badgeClass}">${badgeText}</span>
            </div>
            <div class="core-task-name">${taskName}</div>
            <div style="font-size: 11px; color: #64748b;">
                PID: ${cpu.task ? cpu.task.tid : '-'} &bull; ${cpu.task ? 'Slice active' : 'Ready'}
            </div>
        `;
        coresContainer.appendChild(coreDiv);
    });

    // Update Latency Chart
    if (data.latency_history && data.latency_history.length > 0) {
        latencyTimes = data.latency_history.map(item => item.time);
        latencyValues = data.latency_history.map(item => item.fg_latency_ms);

        const traceColor = data.mode === "scx_hush" ? "#10b981" : "#ef4444";

        if (!isPlotInitialized) {
            const plotData = [{
                x: latencyTimes,
                y: latencyValues,
                mode: "lines",
                name: "Wakeup Delay",
                line: { color: traceColor, width: 2.5 },
                fill: 'tozeroy',
                fillcolor: data.mode === "scx_hush" ? "rgba(16, 185, 129, 0.1)" : "rgba(239, 68, 68, 0.1)"
            }];

            const layout = {
                paper_bgcolor: "transparent",
                plot_bgcolor: "transparent",
                margin: { l: 45, r: 20, t: 15, b: 35 },
                xaxis: { color: "#64748b", showgrid: false, title: "Sim Time (s)" },
                yaxis: { color: "#64748b", gridcolor: "#1e293b", title: "Latency (ms)", range: [0, 35] },
                font: { family: "-apple-system, sans-serif" }
            };

            Plotly.newPlot("latency-plot", plotData, layout, { responsive: true, displayModeBar: false });
            isPlotInitialized = true;
        } else {
            Plotly.animate("latency-plot", {
                data: [{
                    x: [latencyTimes],
                    y: [latencyValues],
                    line: { color: traceColor },
                    fillcolor: data.mode === "scx_hush" ? "rgba(16, 185, 129, 0.1)" : "rgba(239, 68, 68, 0.1)"
                }]
            }, {
                transition: { duration: 0 },
                frame: { duration: 0, redraw: false }
            });
        }
    }

    // Update Terminal Event Log
    const term = document.getElementById("event-terminal");
    term.innerHTML = "";
    data.event_log.forEach(ev => {
        const line = document.createElement("div");
        line.className = "log-entry";
        line.innerHTML = `
            <span class="log-time">[${ev.timestamp.toFixed(2)}s]</span>
            <span class="log-${ev.level}">${ev.message}</span>
        `;
        term.appendChild(line);
    });
    term.scrollTop = term.scrollHeight;
}

// Interactive API Handlers
async function sendAction(action, target = null) {
    try {
        const resp = await fetch("/api/action", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ action: action, target: target })
        });
        return await resp.json();
    } catch (e) {
        console.error("Action failed:", e);
    }
}

function toggleMode() {
    sendAction("switch_mode");
}

function selectScenario(name) {
    document.querySelectorAll(".btn-scenario").forEach(b => b.classList.remove("active"));
    const activeBtn = document.getElementById(`scen-${name}`);
    if (activeBtn) activeBtn.classList.add("active");
    sendAction("switch_scenario", name);
}

function triggerInversion() {
    sendAction("trigger_inversion_lock");
}

function triggerStarvation() {
    sendAction("trigger_starvation_guard");
}

function promoteTask() {
    sendAction("promote");
}

function demoteTask() {
    sendAction("demote");
}

function triggerAbuse() {
    sendAction("abuse_hint");
}

window.onload = function () {
    initWebSocket();
};
