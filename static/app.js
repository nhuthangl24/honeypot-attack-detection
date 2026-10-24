const $ = (id) => document.getElementById(id);
let currentView = "overview";
let page = 0;
const pageSize = 100;
let currentTotal = 0;
let currentEventData = null;
let currentSessionData = null;
let currentModalTab = "ai-view";
let jsonViewMode = "code";
let jsonSearchQuery = "";
let currentSessionMlData = null;

// ==============================================================================
// 1. CÒI HÚ CẢNH BÁO ĐỎ BẰNG WEB AUDIO API (SIREN ALARM)
// ==============================================================================

class SirenAudio {
  constructor() {
    this.ctx = null;
    this.osc = null;
    this.gain = null;
    this.interval = null;
    this.isPlaying = false;
  }
  init() {
    if (!this.ctx) {
      const AudioCtx = window.AudioContext || window.webkitAudioContext;
      if (AudioCtx) this.ctx = new AudioCtx();
    }
  }
  start() {
    if (this.isPlaying) return;
    try {
      this.init();
      if (!this.ctx) return;
      if (this.ctx.state === "suspended") this.ctx.resume();
      this.osc = this.ctx.createOscillator();
      this.gain = this.ctx.createGain();
      this.osc.type = "sawtooth";
      this.osc.frequency.setValueAtTime(800, this.ctx.currentTime);
      this.gain.gain.setValueAtTime(0.12, this.ctx.currentTime);
      this.osc.connect(this.gain);
      this.gain.connect(this.ctx.destination);
      this.osc.start();
      this.isPlaying = true;

      let high = false;
      this.interval = setInterval(() => {
        if (!this.osc || !this.ctx) return;
        const targetFreq = high ? 750 : 1200;
        this.osc.frequency.setTargetAtTime(targetFreq, this.ctx.currentTime, 0.12);
        high = !high;
      }, 350);
    } catch (e) {
      console.warn("Audio siren error:", e);
    }
  }
  stop() {
    if (!this.isPlaying) return;
    try {
      if (this.interval) clearInterval(this.interval);
      if (this.osc) {
        this.osc.stop();
        this.osc.disconnect();
      }
    } catch (e) {}
    this.isPlaying = false;
  }
}

const siren = new SirenAudio();
let soundEnabled = true;
let dismissedAlertId = 0;
let activeAlertSessionId = null;

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

function mlBadge(pred, conf) {
  if (!pred) return `<span class="ml-badge benign">Đang chờ ML…</span>`;
  const p = pred.toLowerCase();
  let cls = "interactive";
  let icon = "⚡";
  if (p.includes("exploit") || p.includes("dropper") || p.includes("malware")) {
    cls = "exploit";
    icon = "🚨";
  } else if (p.includes("brute")) {
    cls = "brute";
    icon = "🔑";
  } else if (p.includes("recon") || p.includes("thám") || p.includes("quét")) {
    cls = "recon";
    icon = "🔍";
  }
  const confStr = conf ? ` (${conf}%)` : "";
  return `<span class="ml-badge ${cls}">${icon} ${esc(pred)}${confStr}</span>`;
}

async function api(url, opts) {
  const r = await fetch(url, { cache: "no-store", ...opts });
  if (!r.ok) throw new Error(`API ${r.status}`);
  return r.json();
}

function toast(message) {
  const t = $("toast");
  if (!t) return;
  t.textContent = message;
  t.classList.add("show");
  setTimeout(() => t.classList.remove("show"), 2500);
}

// ==============================================================================
// 2. CHECK ALERT & CHUÔNG BÁO ĐỘNG ĐỎ
// ==============================================================================

async function checkAlarmLoop() {
  try {
    const alertData = await api("/api/ml/latest-alert");
    const banner = $("alarm-banner");
    if (!banner) return;

    if (alertData && alertData.has_alert && alertData.alert_id !== dismissedAlertId) {
      activeAlertSessionId = alertData.session_id;
      banner.classList.remove("hidden");
      $("alarm-title").textContent = `PHÁT HIỆN ${alertData.attack_type.toUpperCase()} - TIN CẬY: ${alertData.confidence}%!`;
      $("alarm-desc").textContent = `Session: ${alertData.session_id} | Attacker IP: ${alertData.source_ip} | Mức độ: ${alertData.alert_level} (${alertData.risk_score}/100)`;
      
      if (soundEnabled) {
        siren.start();
      }
    } else {
      banner.classList.add("hidden");
      siren.stop();
    }
  } catch (e) {
    // silently ignore network jitter
  }
}

// Tắt chuông cảnh báo
$("alarm-silence-btn")?.addEventListener("click", async () => {
  siren.stop();
  $("alarm-banner")?.classList.add("hidden");
  try {
    const res = await api("/api/ml/latest-alert");
    if (res && res.alert_id) dismissedAlertId = res.alert_id;
    await api("/api/ml/dismiss-alert", { method: "POST" });
  } catch (e) {}
  toast("Đã tắt chuông cảnh báo");
});

// Xem 14 đặc trưng từ banner
$("alarm-inspect-btn")?.addEventListener("click", () => {
  if (activeAlertSessionId) {
    showSessionMlModal(activeAlertSessionId);
  }
});

// Nút Bật / Tắt âm thanh còi hú
$("sound-toggle-btn")?.addEventListener("click", () => {
  soundEnabled = !soundEnabled;
  const btn = $("sound-toggle-btn");
  if (soundEnabled) {
    btn.classList.remove("muted");
    btn.classList.add("active");
    btn.textContent = "🔔 Còi báo: BẬT";
    toast("Đã bật âm thanh cảnh báo");
  } else {
    btn.classList.remove("active");
    btn.classList.add("muted");
    btn.textContent = "🔕 Còi báo: TẮT";
    siren.stop();
    toast("Đã tắt âm thanh cảnh báo");
  }
});

// Nút Test giả lập Exploit
$("test-exploit-btn")?.addEventListener("click", async () => {
  toast("Đang giả lập Kali Linux tấn công Exploit...");
  try {
    const res = await api("/api/test/exploit", { method: "POST" });
    toast("Đã kích hoạt giả lập! XGBoost đang phân loại & bật chuông đỏ.");
    await refreshAll(false);
    await checkAlarmLoop();
  } catch (e) {
    toast("Lỗi gửi request test exploit: " + e.message);
  }
});

// ==============================================================================
// 3. RENDER BẢNG DỮ LIỆU SỰ KIỆN
// ==============================================================================

function eventRow(e, extended = false) {
  const what = e.command || e.message || e.request_uri || e.service_description || "—";
  const hasAi = Boolean(e.command_output && e.command_output.trim());
  const aiBadge = hasAi ? `<span class="ai-badge" title="AI Honeypot responded">⚡ AI Response</span>` : "";

  return `<tr>
    <td class="mono">${esc(fmtTime(e.timestamp))}</td>
    <td>
      <span class="mono source-ip" onclick="filterByIp('${esc(e.source_ip)}')">${esc(e.source_ip || "—")}</span>
      ${e.source_port ? `<div class="muted" style="color:var(--muted);font-size:9px;">port ${esc(e.source_port)}</div>` : ""}
    </td>
    <td><span class="mono" style="color:var(--cyan);">${esc(e.protocol ? e.protocol.toUpperCase() : "SSH")}</span></td>
    <td title="${esc(what)}">
      <span style="font-weight:${e.command ? '600' : '400'};color:${e.command ? '#fff' : '#b6c2d0'}">${esc(what.length > 55 ? what.slice(0, 52) + "…" : what)}</span>
      ${aiBadge}
    </td>
    ${extended ? `<td>${esc(e.username || "—")}</td>` : ""}
    <td>${mlBadge(e.ml_prediction, e.ml_confidence)}</td>
    <td>${statusBadge(e.event_status)}</td>
    <td>
      <button class="text-button" onclick="showDetail(${Number(e.id)}, 'ai-view')">Inspect ↗</button>
      <button class="text-button mono-btn" onclick="showDetail(${Number(e.id)}, 'ml-view')" title="Xem 14 đặc trưng ML">🧠 ML</button>
    </td>
  </tr>`;
}

async function loadStats() {
  const [s, mlStats] = await Promise.all([
    api("/api/stats"),
    api("/api/ml/stats").catch(() => null)
  ]);

  if (!s) return;
  $("metric-total").textContent = Number(s.total_events || 0).toLocaleString();
  $("metric-24h").textContent = Number(s.events_24h || 0).toLocaleString();
  $("metric-ml-sessions").textContent = Number(mlStats?.total_analyzed_sessions || s.sessions || 0).toLocaleString();
  $("metric-critical").textContent = Number(mlStats?.critical_attacks_count || 0).toLocaleString();

  $("nav-event-count").textContent = Number(s.total_events || 0).toLocaleString();
  $("nav-ml-count").textContent = Number(mlStats?.total_analyzed_sessions || 0).toLocaleString();
  $("last-updated").textContent = "Updated " + new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });

  // Biểu đồ phân loại tấn công ML (XGBoost)
  const attacks = mlStats?.attack_distribution || s.ml_attacks || [];
  if (attacks.length) {
    const maxVal = Math.max(...attacks.map(x => x.value), 1);
    $("ml-chart").innerHTML = attacks.map(x => {
      const isExploit = x.label.toLowerCase().includes("exploit") || x.label.toLowerCase().includes("dropper");
      const bg = isExploit ? "linear-gradient(90deg, #ef4444, #f87171)" : "linear-gradient(90deg, #3b82f6, #60a5fa)";
      return `<div class="bar-row">
        <span class="bar-label" title="${esc(x.label)}">${esc(x.label)}</span>
        <div class="bar-track">
          <div class="bar-fill" style="width:${Math.max(4, (x.value / maxVal) * 100)}%;background:${bg}"></div>
        </div>
        <span class="bar-value">${x.value} <small style="color:var(--muted);font-size:10px;">(${x.avg_confidence || x.confidence || 95}%)</small></span>
      </div>`;
    }).join("");
  } else {
    $("ml-chart").innerHTML = `<div class="empty">Chưa có phiên phân loại ML</div>`;
  }

  // Biểu đồ protocols
  const protocols = s.protocols || [];
  $("protocol-chart").innerHTML = protocols.length ? protocols.map((x, i) => {
    const max = Math.max(...protocols.map(y => y.value), 1);
    return `<div class="bar-row"><span class="bar-label">${esc(x.label)}</span><div class="bar-track"><div class="bar-fill" style="width:${Math.max(2, x.value / max * 100)}%;opacity:${1 - i * .05}"></div></div><span class="bar-value">${x.value}</span></div>`;
  }).join("") : `<div class="empty">No protocol data yet</div>`;

  // Timeline
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

  // Top source IPs
  const topIps = s.top_ips || [];
  $("top-ips").innerHTML = topIps.length ? topIps.map(x => `<div class="ip-row"><div><div class="mono source-ip" onclick="filterByIp('${esc(x.ip)}')">${esc(x.ip)}</div><div class="muted" style="color:var(--muted);font-size:10px;">${esc(fmtTime(x.last_seen))}</div></div><span class="ip-count">${x.count} events</span></div>`).join("") : `<div class="empty">No source IPs yet</div>`;
}

async function loadLatest() {
  const d = await api("/api/events?limit=8");
  $("latest-body").innerHTML = d.items.length ? d.items.map(e => eventRow(e)).join("") : `<tr><td colspan="7" class="empty">No events received yet. Ingestion active.</td></tr>`;
}

async function loadEvents() {
  const q = encodeURIComponent($("search-input").value.trim());
  const protocol = encodeURIComponent($("protocol-filter").value);
  const status = encodeURIComponent($("status-filter").value);
  const ip = encodeURIComponent($("ip-filter").value.trim());
  const offset = page * pageSize;

  const url = `/api/events?q=${q}&protocol=${protocol}&status=${status}&ip=${ip}&limit=${pageSize}&offset=${offset}`;
  const data = await api(url);
  currentTotal = data.total;
  $("event-total-tag").textContent = `${currentTotal.toLocaleString()} events`;
  $("pagination-label").textContent = currentTotal === 0 ? "Showing 0 events" : `Showing ${offset + 1}–${Math.min(offset + pageSize, currentTotal)} of ${currentTotal.toLocaleString()}`;
  $("prev-page").disabled = page === 0;
  $("next-page").disabled = (page + 1) * pageSize >= currentTotal;

  $("events-body").innerHTML = data.items.length ? data.items.map(e => eventRow(e, true)).join("") : `<tr><td colspan="8" class="empty">No events match your criteria.</td></tr>`;
}

async function loadMlSessions() {
  const list = await api("/api/ml/predictions?limit=50");
  const tbody = $("ml-sessions-body");
  if (!tbody) return;

  if (!list || !list.length) {
    tbody.innerHTML = `<tr><td colspan="8" class="empty">Chưa có phiên nào được phân tích. Hãy tạo kết nối thử nghiệm hoặc bấm 'Test Exploit & Báo Động'!</td></tr>`;
    return;
  }

  tbody.innerHTML = list.map(item => {
    const isCritical = item.is_critical_alarm || item.alert_level === "CRITICAL";
    const alarmPill = isCritical ? `<span class="status red-status">🚨 CÒI HÚ</span>` : `<span class="status other">Bình thường</span>`;
    return `<tr>
      <td class="mono" style="color:var(--cyan);font-weight:600;">${esc(item.session_id)}</td>
      <td class="mono source-ip" onclick="filterByIp('${esc(item.source_ip)}')">${esc(item.source_ip || "—")}</td>
      <td>${mlBadge(item.attack_type, item.confidence)}</td>
      <td class="mono"><strong>${item.confidence}%</strong></td>
      <td><span class="status ${item.risk_score >= 80 ? 'red-status' : item.risk_score >= 50 ? 'interaction' : 'other'}">${item.risk_score}/100</span></td>
      <td>${alarmPill}</td>
      <td class="mono">${esc(fmtTime(item.analyzed_at))}</td>
      <td>
        <button class="primary-btn btn-sm" onclick="showSessionMlModal('${esc(item.session_id)}')">🧠 14 Đặc Trưng</button>
      </td>
    </tr>`;
  }).join("");
}

async function loadSources() {
  const s = await api("/api/stats");
  const topIps = s.top_ips || [];
  $("sources-body").innerHTML = topIps.length ? topIps.map(x => `<tr>
    <td class="mono source-ip" onclick="filterByIp('${esc(x.ip)}')">${esc(x.ip)}</td>
    <td>${x.count}</td>
    <td class="mono">${esc(fmtTime(x.last_seen))}</td>
    <td><button class="text-button" onclick="filterByIp('${esc(x.ip)}')">Filter events ↗</button></td>
  </tr>`).join("") : `<tr><td colspan="4" class="empty">No sources recorded yet.</td></tr>`;
}

async function loadFilters() {
  const f = await api("/api/filters");
  const pSel = $("protocol-filter");
  const sSel = $("status-filter");
  if (pSel.children.length <= 1) {
    f.protocols.forEach(p => {
      const opt = document.createElement("option");
      opt.value = p; opt.textContent = p.toUpperCase();
      pSel.appendChild(opt);
    });
  }
  if (sSel.children.length <= 1) {
    f.statuses.forEach(st => {
      const opt = document.createElement("option");
      opt.value = st; opt.textContent = st;
      sSel.appendChild(opt);
    });
  }
}

// ==============================================================================
// 4. MODAL INSPECTOR & 14 VECTOR ĐẶC TRƯNG ML (XGBOOST EXPLAINABILITY)
// ==============================================================================

async function showDetail(eventId, tab = "ai-view") {
  currentModalTab = tab;
  $("modal").classList.remove("hidden");
  $("event-detail").innerHTML = `<div class="empty">Đang nạp chi tiết sự kiện & ML…</div>`;

  try {
    const data = await api(`/api/events/${eventId}`);
    currentEventData = data;
    $("modal-title").textContent = `Sự kiện #${data.id} · ${data.protocol ? data.protocol.toUpperCase() : "SSH"}`;
    $("modal-api-link").href = `/api/events/${eventId}`;

    if (data.session_id) {
      try {
        const [sessData, mlData] = await Promise.all([
          api(`/api/sessions/${data.session_id}`),
          api(`/api/sessions/${data.session_id}/ml`).catch(() => null)
        ]);
        currentSessionData = sessData;
        currentSessionMlData = mlData;
        $("session-count-tab").textContent = sessData.total || 0;
      } catch (err) {
        currentSessionData = null;
        currentSessionMlData = null;
      }
    } else {
      currentSessionData = null;
      currentSessionMlData = null;
      $("session-count-tab").textContent = "0";
    }

    switchModalTab(currentModalTab);
  } catch (e) {
    $("event-detail").innerHTML = `<div class="empty">Lỗi tải sự kiện: ${esc(e.message)}</div>`;
  }
}

async function showSessionMlModal(sessionId) {
  $("modal").classList.remove("hidden");
  $("event-detail").innerHTML = `<div class="empty">Đang trích xuất 14 đặc trưng của Session '${esc(sessionId)}'…</div>`;
  currentModalTab = "ml-view";

  try {
    const [sessData, mlData] = await Promise.all([
      api(`/api/sessions/${sessionId}`),
      api(`/api/sessions/${sessionId}/ml`)
    ]);
    currentSessionData = sessData;
    currentSessionMlData = mlData;
    currentEventData = sessData.events && sessData.events.length ? sessData.events[0] : null;
    $("modal-title").textContent = `Session: ${sessionId}`;
    $("session-count-tab").textContent = sessData.total || 0;
    switchModalTab("ml-view");
  } catch (e) {
    $("event-detail").innerHTML = `<div class="empty">Lỗi tải dữ liệu session: ${esc(e.message)}</div>`;
  }
}

function switchModalTab(tab) {
  currentModalTab = tab;
  document.querySelectorAll(".modal-tab").forEach(t => {
    t.classList.toggle("active", t.dataset.tab === currentModalTab);
  });
  renderModalBody();
}

function renderModalBody() {
  const d = currentEventData;
  if (!d && currentModalTab !== "ml-view") {
    $("event-detail").innerHTML = `<div class="empty">Không có dữ liệu sự kiện</div>`;
    return;
  }

  if (currentModalTab === "ml-view") {
    renderMlTab();
  } else if (currentModalTab === "ai-view") {
    renderAiTerminalTab(d);
  } else if (currentModalTab === "session-view") {
    renderSessionViewTab();
  } else if (currentModalTab === "json-view") {
    renderJsonTab(d);
  }
}

function renderMlTab() {
  const ml = currentSessionMlData;
  if (!ml || (!ml.features && !ml.features_14)) {
    $("event-detail").innerHTML = `
      <div class="empty" style="padding:40px;">
        <p>Phiên này chưa hoàn tất phân tích ML hoặc đang chờ sự kiện kết thúc phiên (Session Closed).</p>
        <button class="primary-btn" onclick="showSessionMlModal('${esc(currentEventData?.session_id || '')}')">🔄 Kích hoạt phân tích ngay</button>
      </div>`;
    return;
  }

  const f = ml.features || ml.features_14 || {};
  const predVi = ml.attack_type || ml.prediction_vi || "Chưa xác định";
  const conf = ml.confidence || ml.confidence_pct || 95;
  const risk = ml.risk_score || 50;
  const isAlarm = ml.is_critical_alarm || ml.alert_level === "CRITICAL";

  const featureCards = [
    { label: "1. Thời lượng phiên", key: "duration_seconds", unit: "giây", desc: "Thời gian attacker tương tác", val: f.duration_seconds },
    { label: "2. Tổng sự kiện", key: "total_events", unit: "events", desc: "Tổng packet/action ghi nhận", val: f.total_events },
    { label: "3. Tổng số câu lệnh", key: "total_commands_count", unit: "lệnh", desc: "Lệnh thực thi trong terminal", val: f.total_commands_count },
    { label: "4. Mật khẩu sai (Failed)", key: "failed_login_count", unit: "lần", desc: "Số lần dò sai mật khẩu", val: f.failed_login_count },
    { label: "5. Tỉ lệ đăng nhập sai", key: "failed_login_ratio", unit: "ratio", desc: "Tỉ lệ thất bại / tổng số lần", val: f.failed_login_ratio },
    { label: "6. Đăng nhập thành công", key: "success_login_count", unit: "lần", desc: "Mở shell AI thành công", val: f.success_login_count },
    { label: "7. Usernames độc nhất", key: "unique_usernames_count", unit: "users", desc: "Số tài khoản bị dò quét", val: f.unique_usernames_count },
    { label: "8. Mật khẩu độc nhất", key: "unique_passwords_count", unit: "pass", desc: "Từ điển mật khẩu attacker dùng", val: f.unique_passwords_count },
    { label: "9. Entropy Username", key: "username_entropy", unit: "bits", desc: "Độ ngẫu nhiên tên đăng nhập", val: f.username_entropy },
    { label: "10. Entropy Password", key: "password_entropy", unit: "bits", desc: "Độ phức tạp mật khẩu", val: f.password_entropy },
    { label: "11. Mục tiêu Root", key: "is_root_targeted", unit: f.is_root_targeted ? "CÓ (1)" : "KHÔNG (0)", desc: "Nhắm vào đặc quyền cao nhất", val: f.is_root_targeted ? 1 : 0 },
    { label: "12. Tỉ lệ lệnh độc nhất", key: "unique_commands_ratio", unit: "ratio", desc: "Lặp lệnh bot vs lệnh thủ công", val: f.unique_commands_ratio },
    { label: "13. Delay giữa các lệnh", key: "avg_inter_command_delay", unit: "giây", desc: "Tốc độ gõ: Bot (<0.5s) vs Người", val: f.avg_inter_command_delay },
    { label: "14. Tải mã độc (Exploit)", key: "file_download_count", unit: "lệnh", desc: "wget, curl, tftp, dropper...", val: f.file_download_count }
  ];

  $("event-detail").innerHTML = `
    <div style="background:#0d1624;border:1px solid ${isAlarm ? '#ef4444' : '#1e2c3e'};border-radius:8px;padding:16px;margin-bottom:16px;">
      <div style="display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:10px;">
        <div>
          <span style="font-size:11px;color:var(--muted);text-transform:uppercase;letter-spacing:1px;">KẾT QUẢ SUY DIỄN XGBOOST (VÒNG LẶP 2)</span>
          <h2 style="margin:4px 0 0;color:${isAlarm ? '#f87171' : 'var(--cyan)'};font-size:20px;">${esc(predVi)}</h2>
        </div>
        <div style="display:flex;gap:12px;align-items:center;">
          <div style="text-align:right;">
            <div style="font-size:11px;color:var(--muted);">ĐỘ TIN CẬY ML</div>
            <strong style="font-size:18px;color:#fff;">${conf}%</strong>
          </div>
          <div style="text-align:right;">
            <div style="font-size:11px;color:var(--muted);">MỨC ĐỘ RỦI RO</div>
            <strong style="font-size:18px;color:${risk >= 80 ? 'var(--red)' : 'var(--orange)'};">${risk}/100</strong>
          </div>
        </div>
      </div>
      <p style="margin:12px 0 0;color:#94a3b8;font-size:12px;border-top:1px dashed #1e2c3e;padding-top:10px;">
        💡 <strong>Giải thích quyết định:</strong> Vector 14 đặc trưng được trích xuất từ chuỗi sự kiện phiên kết hợp mô hình XGBoost. 
        ${f.file_download_count > 0 ? "Phát hiện lệnh tải tệp độc hại hoặc khai thác RCE (wget/curl/chmod) -> Kích hoạt cảnh báo đỏ Exploit." : "Không có dấu hiệu tải mã độc trực tiếp; phân loại dựa trên tần suất đăng nhập và độ trễ lệnh."}
      </p>
    </div>

    <h3 style="margin:16px 0 8px;font-size:13px;color:var(--muted);letter-spacing:0.5px;">VECTOR 14 ĐẶC TRƯNG AN NINH MẠNG THEO THIẾT KẾ</h3>
    <div class="features-grid">
      ${featureCards.map(item => `
        <div class="feature-item" style="${item.key === 'file_download_count' && item.val > 0 ? 'border-color:#ef4444;background:#260d10;' : ''}">
          <div class="feature-label">${esc(item.label)}</div>
          <div class="feature-value">${esc(item.val)} <small style="font-size:11px;font-weight:400;color:var(--muted);">${esc(item.unit)}</small></div>
          <div class="feature-desc">${esc(item.desc)}</div>
        </div>
      `).join("")}
    </div>
  `;
}

function renderAiTerminalTab(d) {
  const hasAi = Boolean(d.command_output && d.command_output.trim());
  const cmd = d.command || d.message || "—";
  const output = d.command_output || "No terminal output recorded.";

  $("event-detail").innerHTML = `
    <div class="terminal-box" style="margin-bottom:16px;">
      <div class="terminal-bar">
        <span>⚡ Attacker Terminal Session · ${esc(d.source_ip || "Unknown IP")}</span>
        <button class="secondary-btn btn-sm" onclick="copyText('${esc(cmd)}')">Copy Command</button>
      </div>
      <div class="terminal-body">
        <div style="color:var(--green);margin-bottom:6px;">root@beelzebub:~# <span style="color:#fff;font-weight:bold;">${esc(cmd)}</span></div>
        <div style="white-space:pre-wrap;color:#b6c2d0;font-family:'DM Mono',monospace;line-height:1.4;">${esc(output)}</div>
      </div>
    </div>

    <div class="detail-grid">
      <div class="detail-card"><span class="detail-label">TIMESTAMP</span><span class="detail-val mono">${esc(d.timestamp)}</span></div>
      <div class="detail-card"><span class="detail-label">SOURCE ADDRESS</span><span class="detail-val mono">${esc(d.source_ip)}:${esc(d.source_port || "—")}</span></div>
      <div class="detail-card"><span class="detail-label">PROTOCOL</span><span class="detail-val mono">${esc(d.protocol ? d.protocol.toUpperCase() : "SSH")}</span></div>
      <div class="detail-card"><span class="detail-label">STATUS</span><span class="detail-val">${statusBadge(d.event_status)}</span></div>
      <div class="detail-card"><span class="detail-label">SESSION ID</span><span class="detail-val mono">${esc(d.session_id || "—")}</span></div>
      <div class="detail-card"><span class="detail-label">USERNAME</span><span class="detail-val mono">${esc(d.username || "—")}</span></div>
    </div>
  `;
}

function renderSessionViewTab() {
  if (!currentSessionData || !currentSessionData.events || !currentSessionData.events.length) {
    $("event-detail").innerHTML = `<div class="empty">Không có sự kiện nào cùng Session ID.</div>`;
    return;
  }
  const evs = currentSessionData.events;
  $("event-detail").innerHTML = `
    <div style="margin-bottom:12px;display:flex;justify-content:space-between;align-items:center;">
      <span style="color:var(--muted);font-size:12px;">Phiên gồm ${evs.length} sự kiện liên kết</span>
      <button class="primary-btn btn-sm" onclick="showSessionMlModal('${esc(evs[0].session_id)}')">🧠 Xem 14 Đặc trưng ML của phiên</button>
    </div>
    <div class="table-wrap">
      <table>
        <thead>
          <tr>
            <th>TIME</th>
            <th>STATUS</th>
            <th>COMMAND / EVENT</th>
            <th>RESPONSE</th>
          </tr>
        </thead>
        <tbody>
          ${evs.map(e => `
            <tr>
              <td class="mono">${esc(fmtTime(e.timestamp))}</td>
              <td>${statusBadge(e.event_status)}</td>
              <td class="mono" style="font-weight:600;color:#fff;">${esc(e.command || e.message || "—")}</td>
              <td class="mono muted" style="max-width:250px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;">${esc(e.command_output || "—")}</td>
            </tr>
          `).join("")}
        </tbody>
      </table>
    </div>
  `;
}

function renderJsonTab(d) {
  const jsonStr = JSON.stringify(d.raw_json || d, null, 2);
  $("event-detail").innerHTML = `
    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px;">
      <span style="font-size:11px;color:var(--muted);">RAW NORMALIZED JSON</span>
      <button class="secondary-btn btn-sm" onclick="copyRawJson()">📋 Copy JSON</button>
    </div>
    <pre class="json-code" style="background:#090e17;border:1px solid var(--border);border-radius:6px;padding:12px;overflow:auto;max-height:480px;font-family:'DM Mono',monospace;color:#7dd3fc;">${esc(jsonStr)}</pre>
  `;
}

function copyRawJson() {
  if (currentEventData) {
    const jsonStr = JSON.stringify(currentEventData.raw_json || currentEventData, null, 2);
    navigator.clipboard.writeText(jsonStr).then(() => toast("Đã sao chép JSON!"));
  }
}

function copyText(str) {
  navigator.clipboard.writeText(str).then(() => toast("Đã sao chép!"));
}

window.copyText = copyText;
window.copyRawJson = copyRawJson;
window.showDetail = showDetail;
window.showSessionMlModal = showSessionMlModal;
window.switchModalTab = switchModalTab;
window.filterByIp = (ip) => {
  $("ip-filter").value = ip;
  switchView("events");
  page = 0;
  loadEvents();
};

function switchView(view) {
  currentView = view;
  document.querySelectorAll(".view").forEach(el => el.classList.add("hidden"));
  $("view-" + view)?.classList.remove("hidden");
  document.querySelectorAll(".nav-item").forEach(el => el.classList.toggle("active", el.dataset.view === view));
  $("page-title").textContent = ({
    overview: "Overview",
    events: "Security Events",
    "ml-sessions": "ML Threat Detection (Vòng Lặp 2)",
    sources: "Attacker Sources"
  })[view] || "Overview";

  if (view === "events") loadEvents();
  if (view === "ml-sessions") loadMlSessions();
  if (view === "sources") loadSources();
}

document.querySelectorAll(".nav-item").forEach(b => b.addEventListener("click", () => switchView(b.dataset.view)));
document.querySelectorAll("[data-goto]").forEach(b => b.addEventListener("click", () => switchView(b.dataset.goto)));
$("refresh-btn")?.addEventListener("click", () => refreshAll(true));
$("apply-filters")?.addEventListener("click", () => { page = 0; loadEvents(); });
$("clear-filters")?.addEventListener("click", () => {
  $("search-input").value = "";
  $("protocol-filter").value = "";
  $("status-filter").value = "";
  $("ip-filter").value = "";
  page = 0;
  loadEvents();
});
$("prev-page")?.addEventListener("click", () => { if (page > 0) { page--; loadEvents(); } });
$("next-page")?.addEventListener("click", () => { if ((page + 1) * pageSize < currentTotal) { page++; loadEvents(); } });
$("search-input")?.addEventListener("keydown", e => { if (e.key === "Enter") { page = 0; loadEvents(); } });

$("close-modal")?.addEventListener("click", () => $("modal").classList.add("hidden"));
$("modal")?.addEventListener("click", e => { if (e.target === $("modal")) $("modal").classList.add("hidden"); });
$("modal-copy-btn")?.addEventListener("click", copyRawJson);

// Tab switching inside modal
document.querySelectorAll(".modal-tab").forEach(tabBtn => {
  tabBtn.addEventListener("click", () => {
    switchModalTab(tabBtn.dataset.tab);
  });
});

async function refreshAll(showToast = false) {
  try {
    const health = await api("/api/health");
    let statusText = "File Watcher & ML Engine Active";
    let isConnected = true;
    if (health.container_name && health.docker_container_found) {
      statusText = `Connected (${health.container_name})`;
    } else if (health.log_files_found && health.log_files_found.length > 0) {
      statusText = `File log active (${health.log_files_found[0].split("/").pop()})`;
    }
    $("sensor-status").textContent = statusText;
    const pulseEl = document.querySelector(".pulse");
    if (pulseEl) pulseEl.style.background = isConnected ? "var(--green)" : "var(--red)";

    await Promise.all([loadStats(), loadLatest(), loadFilters()]);
    if (currentView === "events") await loadEvents();
    if (currentView === "ml-sessions") await loadMlSessions();
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

// Khởi động
refreshAll();
checkAlarmLoop();
setInterval(() => refreshAll(false), 8000);
setInterval(() => checkAlarmLoop(), 3500);
