const $ = (id) => document.getElementById(id);
let currentView = "overview";
let page = 0;
const pageSize = 100;
let currentTotal = 0;

function esc(value) {
  return String(value ?? "").replace(/[&<>"']/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
}
function fmtTime(value) {
  if (!value) return "—";
  const d = new Date(value);
  return Number.isNaN(d.getTime()) ? value : d.toLocaleString([], {month:"short",day:"2-digit",hour:"2-digit",minute:"2-digit",second:"2-digit",hour12:false});
}
function statusClass(s) {
  const v = String(s || "").toLowerCase();
  if (v.includes("interaction")) return "interaction";
  if (v.includes("end") || v.includes("close")) return "end";
  if (v.includes("start")) return "";
  return "other";
}
function statusBadge(s) {
  const v = s || "Unknown";
  return `<span class="status ${statusClass(v)}">${esc(v)}</span>`;
}
async function api(url) {
  const r = await fetch(url);
  if (!r.ok) throw new Error(`API ${r.status}`);
  return r.json();
}
function toast(message) {
  $("toast").textContent = message;
  $("toast").classList.add("show");
  setTimeout(() => $("toast").classList.remove("show"), 2200);
}
function eventRow(e, extended=false) {
  const what = e.command || e.message || e.request_uri || e.service_description || "—";
  return `<tr>
    <td class="mono">${esc(fmtTime(e.timestamp))}</td>
    <td><span class="mono source-ip">${esc(e.source_ip || "—")}</span>${e.source_port ? `<div class="muted">port ${esc(e.source_port)}</div>` : ""}</td>
    <td>${esc(e.protocol || "Unknown")}</td>
    <td title="${esc(what)}">${esc(what.length > 72 ? what.slice(0,69)+"…" : what)}</td>
    ${extended ? `<td>${esc(e.username || "—")}</td>` : ""}
    <td>${statusBadge(e.event_status)}</td>
    <td><button class="text-button" onclick="showDetail(${Number(e.id)})">Inspect ↗</button></td>
  </tr>`;
}
async function loadStats() {
  const s = await api("/api/stats");
  $("metric-total").textContent = Number(s.total_events).toLocaleString();
  $("metric-24h").textContent = Number(s.events_24h).toLocaleString();
  $("metric-ips").textContent = Number(s.unique_ips).toLocaleString();
  $("metric-sessions").textContent = Number(s.sessions).toLocaleString();
  $("nav-event-count").textContent = Number(s.total_events).toLocaleString();
  $("last-updated").textContent = "Updated " + new Date().toLocaleTimeString([], {hour:"2-digit",minute:"2-digit",second:"2-digit"});
  const protocols = s.protocols || [];
  $("protocol-chart").innerHTML = protocols.length ? protocols.map((x,i) => {
    const max = Math.max(...protocols.map(y=>y.value),1);
    return `<div class="bar-row"><span class="bar-label">${esc(x.label)}</span><div class="bar-track"><div class="bar-fill" style="width:${Math.max(2,x.value/max*100)}%;opacity:${1-i*.05}"></div></div><span class="bar-value">${x.value}</span></div>`;
  }).join("") : `<div class="empty">No protocol data yet</div>`;
  const timeline = s.timeline || [];
  if (!timeline.length) $("timeline").innerHTML = `<div class="empty">Waiting for events…</div>`;
  else {
    const map = new Map(timeline.map(x=>[x.hour,x.count]));
    const now = new Date();
    const slots = [];
    for(let i=23;i>=0;i--){const d=new Date(now.getTime()-i*3600000); const key=d.toISOString().slice(0,13); slots.push({key,label:d.getHours().toString().padStart(2,"0"),count:map.get(key)||0});}
    const max = Math.max(...slots.map(x=>x.count),1);
    $("timeline").innerHTML = slots.map(x=>`<div class="timeline-col" title="${esc(x.key)}: ${x.count} events"><div class="timeline-bar-wrap"><div class="timeline-bar" style="height:${Math.max(x.count?4:1,x.count/max*100)}%"></div></div><small>${x.label}</small></div>`).join("");
  }
  $("top-ips").innerHTML = s.top_ips.length ? s.top_ips.map(x=>`<div class="ip-row"><div><div class="mono source-ip">${esc(x.ip)}</div><div class="muted">${esc(fmtTime(x.last_seen))}</div></div><span class="ip-count">${x.count} events</span></div>`).join("") : `<div class="empty">No source IPs yet</div>`;
  const statuses = s.statuses || [], maxStatus = Math.max(...statuses.map(x=>x.value),1);
  $("status-list").innerHTML = statuses.length ? statuses.map(x=>`<div class="bar-row"><span class="bar-label">${esc(x.label)}</span><div class="bar-track"><div class="bar-fill" style="width:${x.value/maxStatus*100}%;background:linear-gradient(90deg,#6555a9,#9b8cff)"></div></div><span class="bar-value">${x.value}</span></div>`).join("") : `<div class="empty">No status data yet</div>`;
}
async function loadLatest() {
  const d = await api("/api/events?limit=8");
  $("latest-body").innerHTML = d.items.length ? d.items.map(e=>eventRow(e)).join("") : `<tr><td colspan="6" class="empty">No events received yet. Generate a test connection to the honeypot.</td></tr>`;
}
async function loadFilters() {
  const d = await api("/api/filters");
  $("protocol-filter").innerHTML = `<option value="">All protocols</option>` + d.protocols.map(x=>`<option>${esc(x)}</option>`).join("");
  $("status-filter").innerHTML = `<option value="">All statuses</option>` + d.statuses.map(x=>`<option>${esc(x)}</option>`).join("");
}
async function loadEvents() {
  const params = new URLSearchParams({limit:pageSize,offset:page*pageSize,q:$("search-input").value.trim(),protocol:$("protocol-filter").value,status:$("status-filter").value,ip:$("ip-filter").value.trim()});
  const d = await api("/api/events?"+params.toString());
  currentTotal = d.total;
  $("events-body").innerHTML = d.items.length ? d.items.map(e=>eventRow(e,true)).join("") : `<tr><td colspan="7" class="empty">No matching events.</td></tr>`;
  $("event-total-tag").textContent = `${d.total.toLocaleString()} events`;
  const start = d.total ? page*pageSize+1 : 0, end = Math.min((page+1)*pageSize,d.total);
  $("pagination-label").textContent = `Showing ${start}–${end} of ${d.total.toLocaleString()} events`;
  $("prev-page").disabled = page === 0;
  $("next-page").disabled = (page+1)*pageSize >= d.total;
}
async function loadSources() {
  const s = await api("/api/stats");
  $("sources-body").innerHTML = s.top_ips.length ? s.top_ips.map(x=>`<tr><td class="mono source-ip">${esc(x.ip)}</td><td class="mono">${x.count}</td><td class="mono">${esc(fmtTime(x.last_seen))}</td><td><button class="text-button" onclick="filterByIp('${esc(x.ip).replace(/'/g,"\\'")}')">View events ↗</button></td></tr>`).join("") : `<tr><td colspan="4" class="empty">No source IPs recorded yet.</td></tr>`;
}
async function showDetail(id) {
  try {
    const e = await api(`/api/events/${id}`);
    if (e.error) throw new Error("Event not found");
    const fields = [
      ["Timestamp",e.timestamp],["Source IP",e.source_ip],["Source port",e.source_port],["Protocol",e.protocol],
      ["Session ID",e.session_id],["Status",e.event_status],["Message",e.message],["Username",e.username],
      ["Command",e.command],["Command output",e.command_output],["Service",e.service_description],
      ["HTTP method",e.http_method],["Request URI",e.request_uri],["User agent",e.user_agent],["Body",e.body]
    ];
    $("event-detail").innerHTML = `<div class="detail-grid">${fields.map(([k,v])=>`<div class="detail-field"><label>${esc(k)}</label><div>${esc(v || "—")}</div></div>`).join("")}</div><div class="raw-block">${esc(JSON.stringify(e.raw_json,null,2))}</div>`;
    $("modal").classList.remove("hidden");
  } catch(err) { toast("Could not load event details"); }
}
window.showDetail = showDetail;
window.filterByIp = (ip) => { $("ip-filter").value=ip; switchView("events"); page=0; loadEvents(); };
function switchView(view) {
  currentView = view;
  document.querySelectorAll(".view").forEach(el=>el.classList.add("hidden"));
  $("view-"+view).classList.remove("hidden");
  document.querySelectorAll(".nav-item").forEach(el=>el.classList.toggle("active",el.dataset.view===view));
  $("page-title").textContent = ({overview:"Overview",events:"Security events",sources:"Attacker sources"})[view];
  if(view==="events") loadEvents();
  if(view==="sources") loadSources();
}
document.querySelectorAll(".nav-item").forEach(b=>b.addEventListener("click",()=>switchView(b.dataset.view)));
document.querySelectorAll("[data-goto]").forEach(b=>b.addEventListener("click",()=>switchView(b.dataset.goto)));
$("refresh-btn").addEventListener("click",()=>refreshAll(true));
$("apply-filters").addEventListener("click",()=>{page=0;loadEvents();});
$("clear-filters").addEventListener("click",()=>{$("search-input").value="";$("protocol-filter").value="";$("status-filter").value="";$("ip-filter").value="";page=0;loadEvents();});
$("prev-page").addEventListener("click",()=>{if(page>0){page--;loadEvents();}});
$("next-page").addEventListener("click",()=>{if((page+1)*pageSize<currentTotal){page++;loadEvents();}});
$("search-input").addEventListener("keydown",e=>{if(e.key==="Enter"){page=0;loadEvents();}});
$("close-modal").addEventListener("click",()=>$("modal").classList.add("hidden"));
$("modal").addEventListener("click",e=>{if(e.target===$("modal"))$("modal").classList.add("hidden");});
async function refreshAll(showToast=false) {
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
    await Promise.all([loadStats(),loadLatest(),loadFilters()]);
    if(currentView==="events") await loadEvents();
    if(currentView==="sources") await loadSources();
    if(showToast) toast("Dashboard refreshed");
  } catch(e) {
    $("sensor-status").textContent = "API unavailable";
    const pulseEl = document.querySelector(".pulse");
    if (pulseEl) pulseEl.style.background = "var(--red)";
    if(showToast) toast("Could not reach dashboard API");
  }
}
refreshAll();
setInterval(()=>refreshAll(false),10000);
