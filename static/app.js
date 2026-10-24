const $ = (id) => document.getElementById(id);
let currentView = "overview";
let page = 0;
const pageSize = 100;
let currentTotal = 0;
let currentEventData = null;
let currentSessionData = null;
let currentModalTab = "ai-view";

function esc(value) {
  return String(value ?? "").replace(/[&<>"']/g, c => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"
  }[c]));
}

function fmtTime(value) {
  if (!value) return "—";
  const d = new Date(value);
  return Number.isNaN(d.getTime()) ? value : d.toLocaleString([], {
    month: "short", day: "2-digit", hour: "2-digit", minute: "2-digit", second: "2-digit", hour12: false
  });
}

function statusClass(s) {
  const v = String(s || "").toLowerCase();
  if (v.includes("interaction") || v.includes("command")) return "interaction";
  if (v.includes("end") || v.includes("close")) return "end";
  if (v.includes("start") || v.includes("login_success")) return "";
  return "other";
}

function statusBadge(s) {
  const v = s || "Unknown";
  return `<span class="status ${statusClass(v)}">${esc(v)}</span>`;
}

async function api(url) {
  const r = await fetch(url, { cache: "no-store" });
  if (!r.ok) throw new Error(`API ${r.status}`);
  return r.json();
}

function toast(message) {
  const t = $("toast");
  if (!t) return;
  t.textContent = message;
  t.classList.add("show");
  setTimeout(() => t.classList.remove("show"), 2200);
}

function eventRow(e, extended = false) {
  const what = e.command || e.message || e.request_uri || e.service_description || "—";
  const hasAi = Boolean(e.command_output && e.command_output.trim());
  const aiBadge = hasAi ? `<span class="ai-badge" title="AI Honeypot responded">⚡ AI Response</span>` : "";

  return `<tr>
    <td class="mono">${esc(fmtTime(e.timestamp))}</td>
    <td>
      <span class="mono source-ip">${esc(e.source_ip || "—")}</span>
      ${e.source_port ? `<div class="muted" style="color:var(--muted);font-size:9px;">port ${esc(e.source_port)}</div>` : ""}
    </td>
    <td><span class="mono" style="color:var(--cyan);">${esc(e.protocol ? e.protocol.toUpperCase() : "SSH")}</span></td>
    <td title="${esc(what)}">
      <span style="font-weight:${e.command ? '600' : '400'};color:${e.command ? '#fff' : '#b6c2d0'}">${esc(what.length > 60 ? what.slice(0, 57) + "…" : what)}</span>
      ${aiBadge}
    </td>
    ${extended ? `<td>${esc(e.username || "—")}</td>` : ""}
    <td>${statusBadge(e.event_status)}</td>
    <td>
      <button class="text-button" onclick="showDetail(${Number(e.id)}, 'ai-view')">Inspect ↗</button>
      <button class="text-button mono-btn" onclick="showDetail(${Number(e.id)}, 'json-view')" title="View pure JSON">{ } JSON</button>
    </td>
  </tr>`;
}

async function loadStats() {
  const s = await api("/api/stats");
  if (!s) return;
  $("metric-total").textContent = Number(s.total_events || 0).toLocaleString();
  $("metric-24h").textContent = Number(s.events_24h || 0).toLocaleString();
  $("metric-ips").textContent = Number(s.unique_ips || 0).toLocaleString();
  $("metric-sessions").textContent = Number(s.sessions || 0).toLocaleString();
  $("nav-event-count").textContent = Number(s.total_events || 0).toLocaleString();
  $("last-updated").textContent = "Updated " + new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });

  const protocols = s.protocols || [];
  $("protocol-chart").innerHTML = protocols.length ? protocols.map((x, i) => {
    const max = Math.max(...protocols.map(y => y.value), 1);
    return `<div class="bar-row"><span class="bar-label">${esc(x.label)}</span><div class="bar-track"><div class="bar-fill" style="width:${Math.max(2, x.value / max * 100)}%;opacity:${1 - i * .05}"></div></div><span class="bar-value">${x.value}</span></div>`;
  }).join("") : `<div class="empty">No protocol data yet</div>`;

  const timeline = s.timeline || [];
  if (!timeline.length) {
    $("timeline").innerHTML = `<div class="empty">Waiting for events…</div>`;
  } else {
    const map = new Map(timeline.map(x => [x.hour, x.count]));
    const now = new Date();
    const slots = [];
    for (let i = 23; i >= 0; i--) {
      const d = new Date(now.getTime() - i * 3600000);
      const key = d.toISOString().slice(0, 13);
      slots.push({ key, label: d.getHours().toString().padStart(2, "0"), count: map.get(key) || 0 });
    }
    const max = Math.max(...slots.map(x => x.count), 1);
    $("timeline").innerHTML = slots.map(x => `<div class="timeline-col" title="${esc(x.key)}: ${x.count} events"><div class="timeline-bar-wrap"><div class="timeline-bar" style="height:${Math.max(x.count ? 4 : 1, x.count / max * 100)}%"></div></div><small>${x.label}</small></div>`).join("");
  }

  const topIps = s.top_ips || [];
  $("top-ips").innerHTML = topIps.length ? topIps.map(x => `<div class="ip-row"><div><div class="mono source-ip">${esc(x.ip)}</div><div class="muted" style="color:var(--muted);font-size:10px;">${esc(fmtTime(x.last_seen))}</div></div><span class="ip-count">${x.count} events</span></div>`).join("") : `<div class="empty">No source IPs yet</div>`;

  const statuses = s.statuses || [], maxStatus = Math.max(...statuses.map(x => x.value), 1);
  $("status-list").innerHTML = statuses.length ? statuses.map(x => `<div class="bar-row"><span class="bar-label">${esc(x.label)}</span><div class="bar-track"><div class="bar-fill" style="width:${x.value / maxStatus * 100}%;background:linear-gradient(90deg,#6555a9,#9b8cff)"></div></div><span class="bar-value">${x.value}</span></div>`).join("") : `<div class="empty">No status data yet</div>`;
}

async function loadLatest() {
  const d = await api("/api/events?limit=8");
  $("latest-body").innerHTML = d.items.length ? d.items.map(e => eventRow(e)).join("") : `<tr><td colspan="6" class="empty">No events received yet. Generate a test connection to the honeypot.</td></tr>`;
}

async function loadFilters() {
  const d = await api("/api/filters");
  $("protocol-filter").innerHTML = `<option value="">All protocols</option>` + d.protocols.map(x => `<option>${esc(x)}</option>`).join("");
  $("status-filter").innerHTML = `<option value="">All statuses</option>` + d.statuses.map(x => `<option>${esc(x)}</option>`).join("");
}

async function loadEvents() {
  const params = new URLSearchParams({
    limit: pageSize,
    offset: page * pageSize,
    q: $("search-input").value.trim(),
    protocol: $("protocol-filter").value,
    status: $("status-filter").value,
    ip: $("ip-filter").value.trim()
  });
  const d = await api("/api/events?" + params.toString());
  currentTotal = d.total;
  $("events-body").innerHTML = d.items.length ? d.items.map(e => eventRow(e, true)).join("") : `<tr><td colspan="7" class="empty">No matching events.</td></tr>`;
  $("event-total-tag").textContent = `${d.total.toLocaleString()} events`;
  const start = d.total ? page * pageSize + 1 : 0, end = Math.min((page + 1) * pageSize, d.total);
  $("pagination-label").textContent = `Showing ${start}–${end} of ${d.total.toLocaleString()} events`;
  $("prev-page").disabled = page === 0;
  $("next-page").disabled = (page + 1) * pageSize >= d.total;
}

async function loadSources() {
  const s = await api("/api/stats");
  $("sources-body").innerHTML = s.top_ips.length ? s.top_ips.map(x => `<tr><td class="mono source-ip">${esc(x.ip)}</td><td class="mono">${x.count}</td><td class="mono">${esc(fmtTime(x.last_seen))}</td><td><button class="text-button" onclick="filterByIp('${esc(x.ip).replace(/'/g, "\\'")}')">View events ↗</button></td></tr>`).join("") : `<tr><td colspan="4" class="empty">No source IPs recorded yet.</td></tr>`;
}

/* RENDER MODAL CONTENT ACCORDING TO ACTIVE TAB */
function renderModalBody() {
  if (!currentEventData) return;
  const e = currentEventData;
  const container = $("event-detail");

  if (currentModalTab === "ai-view") {
    const hasCommand = Boolean(e.command && e.command.trim());
    const hasOutput = Boolean(e.command_output && e.command_output.trim());

    let aiTerminalHtml = "";
    if (hasCommand) {
      aiTerminalHtml = `
      <div class="ai-terminal">
        <div class="terminal-bar">
          <span class="t-dot t-red"></span>
          <span class="t-dot t-yellow"></span>
          <span class="t-dot t-green"></span>
          <span class="terminal-title">BEELZEBUB AI TERMINAL SIMULATION (SSH SHELL)</span>
        </div>
        <div class="terminal-content">
          <div class="terminal-prompt-line">
            <span class="user-host">${esc(e.username || 'root')}@beelzebub</span>:<span class="dir">~</span># <span class="term-cmd">${esc(e.command)}</span>
          </div>
          <div class="terminal-output">${esc(hasOutput ? e.command_output : '[No stdout / Empty output returned]')}</div>
        </div>
        <div class="terminal-footer">
          <span>⚡ Phản hồi do AI Honeypot (LLM Virtualization) tự động sinh ra cho Attacker</span>
          <span>Status: ${esc(e.event_status || 'Interaction')}</span>
        </div>
      </div>`;
    } else {
      aiTerminalHtml = `
      <div class="ai-terminal empty-term">
        <div class="terminal-bar">
          <span class="t-dot t-red"></span>
          <span class="t-dot t-yellow"></span>
          <span class="t-dot t-green"></span>
          <span class="terminal-title">SSH CONNECTION INITIALIZED</span>
        </div>
        <div class="terminal-content">
          <div class="term-info">
            🔹 <strong>Trạng thái: ${esc(e.event_status || 'Start')} (${esc(e.message || 'New SSH Terminal Session')})</strong><br>
            Kẻ tấn công từ IP <code>${esc(e.source_ip || 'unknown')}</code> vừa đăng nhập thành công với tài khoản <code>${esc(e.username || 'unknown')}</code>.<br>
            <em>ℹ️ Ở sự kiện bắt đầu phiên này, attacker chưa thực thi lệnh nên trường lệnh & AI trả lời đang để trống. Xem tab <strong>Session Replay</strong> để theo dõi toàn bộ lệnh và phản hồi AI tiếp theo trong phiên này.</em>
          </div>
        </div>
        <div class="terminal-footer">
          <span>Beelzebub Deception Runtime</span>
          <span>Session: ${esc(e.session_id ? e.session_id.slice(0, 18) + '…' : '—')}</span>
        </div>
      </div>`;
    }

    const fields = [
      ["Timestamp", e.timestamp],
      ["Source IP", e.source_ip],
      ["Source Port", e.source_port ? String(e.source_port) : "—"],
      ["Protocol", e.protocol ? e.protocol.toUpperCase() : "SSH"],
      ["Session ID", e.session_id],
      ["Status", e.event_status],
      ["Username", e.username],
      ["Message", e.message],
      ["Service / Decoy", e.service_description]
    ];

    container.innerHTML = `
      ${aiTerminalHtml}
      <div class="eyebrow" style="margin-bottom:8px;">SESSION & METRIC DETAILS</div>
      <div class="detail-grid">
        ${fields.map(([k, v]) => `
          <div class="detail-field">
            <label>${esc(k)}</label>
            <div>${esc(v || "—")}</div>
          </div>
        `).join("")}
      </div>
    `;

  } else if (currentModalTab === "session-view") {
    if (!currentSessionData || !currentSessionData.events || !currentSessionData.events.length) {
      container.innerHTML = `<div class="empty">No other session events found or session ID is empty.</div>`;
      return;
    }

    const sessEvents = currentSessionData.events;
    const commandEvents = sessEvents.filter(ev => ev.command || ev.command_output);

    container.innerHTML = `
      <div class="welcome-row" style="margin-bottom:12px;">
        <div>
          <h3>Full Session Interaction History (${sessEvents.length} events, ${commandEvents.length} commands)</h3>
          <p>Trình tự toàn bộ tương tác giữa Attacker và AI Honeypot trong phiên <code>${esc(currentEventData.session_id || '')}</code></p>
        </div>
      </div>
      <div class="session-stream">
        ${sessEvents.map((ev, idx) => {
          const isCmd = Boolean(ev.command);
          return `
          <div class="stream-item" style="${ev.id === currentEventData.id ? 'border-color:var(--cyan);' : ''}">
            <div class="stream-head">
              <span>#${idx + 1} · ${esc(fmtTime(ev.timestamp))} · Status: <b style="color:var(--cyan);">${esc(ev.event_status || '—')}</b></span>
              <span>User: <b>${esc(ev.username || 'root')}</b></span>
            </div>
            ${isCmd ? `
              <div class="stream-cmd">$ ${esc(ev.command)}</div>
              <div class="stream-output">${esc(ev.command_output || '[Empty Output]')}</div>
            ` : `
              <div style="font-size:11px;color:#94a3b6;">${esc(ev.message || 'Connection event')}</div>
            `}
          </div>`;
        }).join("")}
      </div>
    `;

  } else if (currentModalTab === "json-view") {
    const jsonStr = JSON.stringify(e, null, 2);
    container.innerHTML = `
      <div class="raw-container">
        <div class="raw-actions">
          <button class="secondary-btn btn-sm" onclick="copyRawJson()">📋 Copy JSON String</button>
          <button class="secondary-btn btn-sm" onclick="downloadCurrentJson()">⬇ Download event-${e.id}.json</button>
        </div>
        <pre class="raw-block"><code>${esc(jsonStr)}</code></pre>
      </div>
    `;
  }
}

async function showDetail(id, tab = "ai-view") {
  try {
    currentModalTab = tab;
    $("modal-eyebrow").textContent = `EVENT INSPECTOR #${id}`;
    $("modal-title").textContent = "Loading event details…";
    $("modal-api-link").href = `/api/events/${id}`;
    $("event-detail").innerHTML = `<div class="empty">Loading event #${id}…</div>`;
    $("modal").classList.remove("hidden");

    // Update tab active classes
    document.querySelectorAll(".modal-tab").forEach(t => {
      t.classList.toggle("active", t.dataset.tab === currentModalTab);
    });

    const e = await api(`/api/events/${id}`);
    if (e.error) throw new Error("Event not found");
    currentEventData = e;
    $("modal-title").textContent = `Event #${e.id} · ${esc(e.protocol ? e.protocol.toUpperCase() : 'SSH')} (${esc(e.event_status || 'Event')})`;

    // Fetch session events if session_id is available
    if (e.session_id) {
      try {
        const sess = await api(`/api/sessions/${encodeURIComponent(e.session_id)}`);
        currentSessionData = sess;
        $("session-count-tab").textContent = sess.events ? String(sess.events.length) : "1";
      } catch (err) {
        currentSessionData = { events: [e] };
        $("session-count-tab").textContent = "1";
      }
    } else {
      currentSessionData = { events: [e] };
      $("session-count-tab").textContent = "1";
    }

    renderModalBody();
  } catch (err) {
    toast("Could not load event details: " + err.message);
  }
}

function copyRawJson() {
  if (!currentEventData) return;
  const jsonStr = JSON.stringify(currentEventData, null, 2);
  navigator.clipboard.writeText(jsonStr).then(() => {
    toast("✓ Raw JSON copied to clipboard!");
  }).catch(() => {
    toast("Could not copy to clipboard");
  });
}

function downloadCurrentJson() {
  if (!currentEventData) return;
  const jsonStr = JSON.stringify(currentEventData, null, 2);
  const blob = new Blob([jsonStr], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `event-${currentEventData.id}.json`;
  a.click();
  URL.revokeObjectURL(url);
  toast(`✓ Downloaded event-${currentEventData.id}.json`);
}

window.showDetail = showDetail;
window.copyRawJson = copyRawJson;
window.downloadCurrentJson = downloadCurrentJson;
window.filterByIp = (ip) => {
  $("ip-filter").value = ip;
  switchView("events");
  page = 0;
  loadEvents();
};

function switchView(view) {
  currentView = view;
  document.querySelectorAll(".view").forEach(el => el.classList.add("hidden"));
  $("view-" + view).classList.remove("hidden");
  document.querySelectorAll(".nav-item").forEach(el => el.classList.toggle("active", el.dataset.view === view));
  $("page-title").textContent = ({ overview: "Overview", events: "Security events", sources: "Attacker sources" })[view];
  if (view === "events") loadEvents();
  if (view === "sources") loadSources();
}

document.querySelectorAll(".nav-item").forEach(b => b.addEventListener("click", () => switchView(b.dataset.view)));
document.querySelectorAll("[data-goto]").forEach(b => b.addEventListener("click", () => switchView(b.dataset.goto)));
$("refresh-btn").addEventListener("click", () => refreshAll(true));
$("apply-filters").addEventListener("click", () => { page = 0; loadEvents(); });
$("clear-filters").addEventListener("click", () => {
  $("search-input").value = "";
  $("protocol-filter").value = "";
  $("status-filter").value = "";
  $("ip-filter").value = "";
  page = 0;
  loadEvents();
});
$("prev-page").addEventListener("click", () => { if (page > 0) { page--; loadEvents(); } });
$("next-page").addEventListener("click", () => { if ((page + 1) * pageSize < currentTotal) { page++; loadEvents(); } });
$("search-input").addEventListener("keydown", e => { if (e.key === "Enter") { page = 0; loadEvents(); } });

$("close-modal").addEventListener("click", () => $("modal").classList.add("hidden"));
$("modal").addEventListener("click", e => { if (e.target === $("modal")) $("modal").classList.add("hidden"); });
$("modal-copy-btn").addEventListener("click", copyRawJson);

// Tab switching inside modal
document.querySelectorAll(".modal-tab").forEach(tabBtn => {
  tabBtn.addEventListener("click", () => {
    document.querySelectorAll(".modal-tab").forEach(b => b.classList.remove("active"));
    tabBtn.classList.add("active");
    currentModalTab = tabBtn.dataset.tab;
    renderModalBody();
  });
});

async function refreshAll(showToast = false) {
  try {
    const health = await api("/api/health");
    let statusText = "Container not found";
    let isConnected = false;
    if (health.docker_container_found) {
      statusText = `Connected (${health.container_name || "Docker"})`;
      isConnected = true;
    } else if (health.log_files_found && health.log_files_found.length > 0) {
      const fname = health.log_files_found[0].split("/").pop();
      statusText = `File log active (${fname})`;
      isConnected = true;
    } else if (health.container_name) {
      statusText = `No container '${health.container_name}'`;
    }
    $("sensor-status").textContent = statusText;
    const pulseEl = document.querySelector(".pulse");
    if (pulseEl) pulseEl.style.background = isConnected ? "var(--green)" : "var(--red)";

    await Promise.all([loadStats(), loadLatest(), loadFilters()]);
    if (currentView === "events") await loadEvents();
    if (currentView === "sources") await loadSources();
    if (showToast) toast("Dashboard refreshed");
  } catch (e) {
    console.error("refreshAll error:", e);
    $("sensor-status").textContent = "API unavailable";
    const pulseEl = document.querySelector(".pulse");
    if (pulseEl) pulseEl.style.background = "var(--red)";
    if (showToast) toast("Could not reach dashboard API");
  }
}

refreshAll();
setInterval(() => refreshAll(false), 10000);
