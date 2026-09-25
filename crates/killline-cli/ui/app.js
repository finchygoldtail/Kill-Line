// Kill Line dashboard. Plain JS, no dependencies, works offline.
// Agent-controlled strings (paths, process names, argv) are only ever
// inserted as text, never as HTML.
"use strict";

const $ = (id) => document.getElementById(id);

function h(tag, attrs, ...kids) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v === undefined || v === null || v === false) continue;
    if (k === "class") el.className = v;
    else if (k === "style") el.style.cssText = v; // CSSOM, allowed by the CSP
    else if (k.startsWith("on")) el.addEventListener(k.slice(2), v);
    else if (k === "dataset") Object.assign(el.dataset, v);
    else el.setAttribute(k, v === true ? "" : v);
  }
  for (const kid of kids.flat()) {
    if (kid === null || kid === undefined || kid === false) continue;
    el.append(kid instanceof Node ? kid : document.createTextNode(String(kid)));
  }
  return el;
}

// ---------- token & API ----------
let TOKEN = "";
try {
  const fromHash = location.hash.slice(1);
  if (/^[0-9a-f]{32}$/.test(fromHash)) {
    TOKEN = fromHash;
    sessionStorage.setItem("killline-token", TOKEN);
    history.replaceState(null, "", location.pathname); // keep the token out of screenshots
  } else {
    TOKEN = sessionStorage.getItem("killline-token") || "";
  }
} catch (_) { /* storage may be unavailable */ }

async function api(path, opts = {}) {
  const res = await fetch("/api/" + path, {
    method: opts.method || "GET",
    headers: Object.assign({ "X-KillLine-Token": TOKEN }, opts.body ? { "Content-Type": "application/json" } : {}),
    body: opts.body ? JSON.stringify(opts.body) : undefined,
  });
  let data = null;
  try { data = await res.json(); } catch (_) { /* empty */ }
  if (res.status === 401) { $("locked").hidden = false; throw new Error("locked"); }
  if (!res.ok) throw new Error((data && data.error) || `Request failed (${res.status})`);
  return data;
}

let toastTimer = null;
function toast(msg) {
  const t = $("toast");
  t.textContent = msg;
  t.hidden = false;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => (t.hidden = true), 4000);
}

// ---------- helpers ----------
const STATUS_WORD = { GREEN: "CONTAINED", AMBER: "ANOMALOUS", RED: "BOUNDARY BREACH", GREY: "MONITORING DEGRADED" };
const RESPONSE_TEXT = { alert: "Alert only", freeze: "Freeze on violation", terminate: "Terminate on violation" };

function timeOf(ts) {
  const d = new Date(ts);
  if (isNaN(d)) return "";
  return d.toLocaleTimeString([], { hour12: false }) + "." + String(d.getMilliseconds()).padStart(3, "0");
}
function dateTimeOf(ts) {
  const d = new Date(ts);
  return isNaN(d) ? "" : d.toLocaleString([], { hour12: false });
}
function fmt(n) { return Number(n || 0).toLocaleString(); }

function outcomeText(o) {
  if (!o) return { text: "Not observed", cls: "" };
  if (o.result === "succeeded") return { text: "SUCCEEDED — the boundary was actually crossed", cls: "res-ok" };
  if (o.result === "in_progress") return { text: "Connection started; completion not observed", cls: "" };
  const refused = [1, 13, 30].includes(o.errno);
  return refused
    ? { text: `Refused by the OS (${o.error}) — the sandbox held this time`, cls: "res-held" }
    : { text: `Failed (${o.error})`, cls: "" };
}

function pill(status, live) {
  return h("span", { class: `pill s-${status}${live ? " live" : ""}` }, h("span", { class: "led" }), status);
}

// ---------- state ----------
let sessions = [];
let selected = null;
let lastSession = null;
let tab = "timeline";
let knownViolations = new Map();

// ---------- sessions rail ----------
async function loadSessions() {
  sessions = await api("sessions");
  $("session-count").textContent = sessions.length;
  const list = $("sessions");
  list.replaceChildren(
    ...sessions.map((s) =>
      h("li", {},
        h("button", {
          type: "button",
          class: "sess" + (s.session_id === selected ? " on" : ""),
          style: `--c: var(--${({ GREEN: "green", AMBER: "amber", RED: "red", GREY: "grey" })[s.effective_status]})`,
          onclick: () => select(s.session_id),
        },
          h("span", { class: "bar" }),
          h("span", {},
            h("div", { class: "name" }, s.agent),
            h("div", { class: "meta" }, s.target.replace(/^container:/, "⧉ ").replace(/ \(.*\)$/, ""), " · ", s.live ? "live" : s.runtime)),
          pill(s.effective_status, s.live))))
  );
  $("sessions-empty").hidden = sessions.length > 0;
  $("welcome").hidden = sessions.length > 0;
  if (!selected && sessions.length) select(sessions[0].session_id);

  // Announce new violations on any live session.
  for (const s of sessions) {
    const prev = knownViolations.get(s.session_id);
    if (prev !== undefined && s.violations > prev && s.last_violation) {
      toast(`Kill Line triggered: ${s.agent} — ${s.last_violation.boundary}`);
    }
    knownViolations.set(s.session_id, s.violations);
  }
}

function select(id) {
  selected = id;
  lastTimelineKey = "";
  $("detail").hidden = false;
  $("welcome").hidden = true;
  document.querySelectorAll(".sess").forEach((b) => b.classList.remove("on"));
  refreshDetail();
  loadSessions();
}

// ---------- detail ----------
async function refreshDetail() {
  if (!selected) return;
  const s = await api("sessions/" + encodeURIComponent(selected));
  lastSession = s;
  const st = s.effective_status;
  const colour = ({ GREEN: "--green", AMBER: "--amber", RED: "--red", GREY: "--grey" })[st];
  document.body.style.setProperty("--state", `var(${colour})`);
  document.body.className = `state-${st}`;
  $("st-agent").textContent = `Agent · ${s.agent}`;
  $("st-word").textContent = st;
  $("st-sub").textContent = STATUS_WORD[st] + (s.frozen ? " · AGENT FROZEN" : "");
  $("st-meaning").textContent = s.status_meaning + (s.live ? "" : s.ended ? " Monitoring has ended." : "");
  $("st-target").textContent = s.target;
  $("st-policy").textContent = s.policy;
  $("st-session").textContent = s.session_id;
  $("st-response").textContent = RESPONSE_TEXT[s.response_mode] || s.response_mode;
  $("st-reasons").replaceChildren(...(s.effective_reasons || []).map((r) => h("li", {}, r)));
  $("n-runtime").textContent = s.runtime;
  $("n-proc").textContent = fmt(s.processes_seen);
  $("n-files").textContent = fmt(s.files_accessed);
  $("n-net").textContent = fmt(s.network_attempts);
  $("n-viol").textContent = fmt(s.violations);
  $("n-anom").textContent = fmt(s.anomalies);
  $("n-viol").parentElement.classList.toggle("alert", s.violations > 0);

  const live = s.live;
  $("controls").hidden = !live;
  $("btn-freeze").hidden = s.frozen;
  $("btn-resume").hidden = !s.frozen;

  const v = s.last_violation;
  $("breach").hidden = !v;
  if (v) {
    $("br-time").textContent = dateTimeOf(v.timestamp);
    $("br-boundary").textContent = v.boundary;
    $("br-expected").textContent = v.expected || "—";
    $("br-actual").textContent = v.summary;
    $("br-process").textContent = v.process;
    const o = outcomeText(v.outcome);
    $("br-result").textContent = o.text;
    $("br-result").className = o.cls;
    $("br-rule").textContent = v.policy_rule || "—";
    $("br-expl").textContent = v.explanation;
    $("btn-view-incident").hidden = !(s.incidents && s.incidents.length);
  }
  $("inc-count").textContent = (s.incidents || []).length;
  await refreshBreachList(s);
  renderCoverage(s.coverage || []);

  if (tab === "timeline") await refreshTimeline();
  if (tab === "incidents") await refreshIncidents();
}

// ---------- timeline ----------
let lastTimelineKey = "";
function collapse(events) {
  // Fold runs of allowed file accesses by one process in one directory.
  const out = [];
  let i = 0;
  const key = (e) =>
    e.verdict === "allowed" && e.observation && e.observation.type === "open"
      ? `${e.process && e.process.pid}|${e.observation.path.replace(/\/[^/]*$/, "")}`
      : null;
  while (i < events.length) {
    const k = key(events[i]);
    let j = i + 1;
    if (k) while (j < events.length && key(events[j]) === k) j++;
    if (j - i >= 4) {
      out.push({ collapsed: true, first: events[i], last: events[j - 1], n: j - i, dir: k.split("|")[1] });
    } else {
      for (let x = i; x < j; x++) out.push(events[x]);
    }
    i = j;
  }
  return out;
}

function evRow(e) {
  if (e.collapsed) {
    return h("li", { class: "ev collapsed" },
      h("span", { class: "t" }, timeOf(e.first.timestamp)),
      h("span", { class: "m" }),
      h("span", { class: "proc" }, e.first.process ? `${e.first.process.comm} ${e.first.process.pid}` : ""),
      h("span", { class: "what" }, `… ${e.n} file accesses under ${e.dir}/`));
  }
  const oc = e.outcome;
  const tag = oc && oc.result === "failed" ? (oc.error || "").split(" ")[0] : oc && oc.result === "in_progress" ? "in progress" : "";
  const row = h("li", { class: `ev v-${e.verdict}` },
    h("span", { class: "t" }, timeOf(e.timestamp)),
    h("span", { class: "m", title: e.verdict }),
    h("span", { class: "proc" }, e.process ? `${e.process.comm} ${e.process.pid}` : "killline"),
    h("span", { class: "what" }, e.summary, tag ? h("small", {}, tag) : null));
  if (e.verdict === "violation" || e.verdict === "anomaly") {
    row.append(h("span", { class: "expl" }, e.explanation));
    for (const c of e.correlations || []) row.append(h("span", { class: "corr" }, c.summary));
  }
  return row;
}

async function refreshTimeline() {
  const filter = $("filter").value;
  const data = await api(`sessions/${encodeURIComponent(selected)}/timeline?filter=${filter}&limit=600`);
  const key = `${selected}|${filter}|${data.total}`;
  if (key === lastTimelineKey) return;
  lastTimelineKey = key;
  const tl = $("timeline");
  const rows = collapse(data.events).map(evRow);
  tl.replaceChildren(...(rows.length ? rows : [h("li", { class: "empty-row" }, "No events yet.")]));
  $("tl-count").textContent = `${fmt(data.matching)} shown of ${fmt(data.total)} recorded`;
  if ($("follow").checked) tl.scrollTop = tl.scrollHeight;
}

// ---------- all breaches ----------
function resultChip(o) {
  if (o && o.result === "succeeded") return h("span", { class: "chip crossed" }, "Crossed");
  if (o && o.result === "failed" && [1, 13, 30].includes(o.errno)) return h("span", { class: "chip held" }, "Sandbox held");
  if (o && o.result === "failed") return h("span", { class: "chip failed" }, "Failed");
  return h("span", { class: "chip failed" }, o && o.result === "in_progress" ? "In progress" : "Not observed");
}
let breachKey = "";
async function refreshBreachList(s) {
  const n = (s.incidents || []).length;
  $("all-breaches").hidden = n < 2;
  const key = s.session_id + "|" + n;
  if (n < 2 || key === breachKey) return;
  breachKey = key;
  const all = (await api("incidents")).filter((i) => i.session_id === s.session_id);
  // Crossed boundaries first: they are the ones the sandbox did not stop.
  const rank = (i) => (i.trigger.outcome && i.trigger.outcome.result === "succeeded" ? 0 : 1);
  all.sort((a, b) => rank(a) - rank(b) || a.incident_id.localeCompare(b.incident_id));
  $("breach-list").replaceChildren(
    ...all.map((i) =>
      h("li", {},
        h("button", { type: "button", class: "brow", onclick: () => openIncident(i.incident_id) },
          resultChip(i.trigger.outcome),
          h("span", { class: "b" }, i.boundary),
          h("span", { class: "a" }, i.actual))))
  );
}

// ---------- incidents ----------
async function refreshIncidents() {
  const all = await api("incidents");
  const mine = all.filter((i) => i.session_id === selected).reverse();
  $("incidents").replaceChildren(
    ...(mine.length
      ? mine.map((i) =>
          h("li", {},
            h("button", { type: "button", class: "inc", onclick: () => openIncident(i.incident_id) },
              h("span", { class: "id" }, i.incident_id),
              h("span", { class: "when" }, dateTimeOf(i.created)),
              h("span", { class: "desc" }, `${i.boundary} · ${i.actual} · ${outcomeText(i.trigger.outcome).text}`))))
      : [h("li", { class: "empty-row" }, "No incidents for this session.")])
  );
}

function treeText(nodes, depth = 0) {
  let s = "";
  for (const n of nodes || []) {
    const exe = n.exe || n.comm;
    const args = (n.argv || []).slice(1).join(" ");
    s += `${"  ".repeat(depth)}${depth ? "└─ " : ""}${n.pid}  ${exe}${args ? " " + args : ""}${n.exited ? "  (exited)" : ""}\n`;
    s += treeText(n.children, depth + 1);
  }
  return s;
}

async function openIncident(id) {
  const d = await api("incidents/" + encodeURIComponent(id));
  const inc = d.incident;
  $("inc-title").textContent = inc.incident_id;
  const o = outcomeText(inc.trigger.outcome);
  const trigRow = evRow(d.trigger);
  const body = $("inc-body");
  body.replaceChildren(
    h("div", { class: "breach" },
      h("div", { class: "breach-head" },
        h("span", { class: "breach-title" }, "KILL LINE TRIGGERED"),
        h("span", { class: "breach-time mono" }, dateTimeOf(inc.trigger.timestamp))),
      h("div", { class: "breach-grid" },
        h("div", {}, h("span", {}, "Boundary"), h("b", {}, inc.boundary)),
        h("div", {}, h("span", {}, "Expected"), h("b", {}, inc.expected || "—")),
        h("div", {}, h("span", {}, "Actual"), h("b", { class: "mono" }, inc.actual)),
        h("div", {}, h("span", {}, "Process"), h("b", { class: "mono" }, inc.process || "—")),
        h("div", {}, h("span", {}, "Result"), h("b", { class: o.cls }, o.text)),
        h("div", {}, h("span", {}, "Rule"), h("b", { class: "mono" }, inc.policy_rule || "—"))),
      h("p", { class: "breach-expl" }, inc.explanation),
      ...(inc.trigger.correlations || []).map((c) => h("p", { class: "breach-expl", style: "color: var(--amber)" }, "↳ " + c.summary)),
      ...(inc.response || []).map((r) => h("p", { class: "breach-expl" }, "Response: " + r))),
    h("h3", {}, "What happened before the breach"),
    h("ol", { class: "timeline scroll", id: "inc-timeline" },
      ...collapse(d.before.filter((e) => e.action !== "monitor.coverage_gap")).slice(-40).map(evRow),
      trigRow,
      ...collapse(d.after).map(evRow)),
    h("h3", {}, "Process tree"),
    h("pre", { class: "tree" }, treeText(d.process_tree) || "(empty)"),
    h("h3", {}, "Evidence bundle"),
    h("div", { class: `integrity ${d.checksums_ok ? "ok" : "bad"}` },
      d.checksums_ok ? "All checksums match. The bundle has not been modified." : `Modified since it was written: ${d.modified_files.join(", ")}`),
    h("p", { class: "mono muted" }, d.bundle_dir),
    h("div", { class: "files" }, ...d.files.map((f) => h("span", {}, f))),
    h("ul", { class: "notes" }, ...(inc.notes || []).map((n) => h("li", {}, n)))
  );
  $("drawer").hidden = false;
  $("drawer-close").focus();
  // Bring the breach into view inside the pre-breach timeline.
  const tl = $("inc-timeline");
  tl.scrollTop = Math.max(0, trigRow.offsetTop - tl.offsetTop - tl.clientHeight + trigRow.offsetHeight + 60);
}

function renderCoverage(cov) {
  $("coverage").replaceChildren(
    ...(cov.length ? cov : []).map((c) =>
      h("li", { class: (c.active ? "" : "off") + (c.critical ? " crit" : "") },
        h("span", { class: "d" }),
        h("span", {}, c.name, h("small", {}, c.active ? (c.detail || "Active") : c.detail || "Unavailable"))))
  );
}

// ---------- controls ----------
let pendingAction = null;
const ACTION_TEXT = {
  freeze: "Freeze the agent? Its processes stop but keep their state so you can inspect them.",
  resume: "Resume the frozen agent?",
  terminate: "Terminate the agent? This kills its processes (or the container) immediately.",
  stop: "Stop monitoring? The agent keeps running but will no longer be watched.",
};
document.querySelectorAll("#controls [data-action]").forEach((b) =>
  b.addEventListener("click", () => {
    pendingAction = b.dataset.action;
    $("confirm-text").textContent = ACTION_TEXT[pendingAction];
    $("confirm").hidden = false;
    $("confirm-yes").focus();
  })
);
$("confirm-no").addEventListener("click", () => { $("confirm").hidden = true; pendingAction = null; });
$("confirm-yes").addEventListener("click", async () => {
  const action = pendingAction;
  $("confirm").hidden = true;
  pendingAction = null;
  try {
    await api(`sessions/${encodeURIComponent(selected)}/control`, { method: "POST", body: { action } });
    toast(`Requested: ${action}. The monitor will act within a second.`);
  } catch (e) { toast(e.message); }
});
$("btn-view-incident").addEventListener("click", () => {
  if (lastSession && lastSession.incidents && lastSession.incidents.length) openIncident(lastSession.incidents.at(-1));
});
$("drawer-close").addEventListener("click", () => ($("drawer").hidden = true));
$("drawer").addEventListener("click", (e) => { if (e.target === $("drawer")) $("drawer").hidden = true; });
document.addEventListener("keydown", (e) => {
  if (e.key === "Escape") { $("drawer").hidden = true; $("start-dialog").hidden = true; }
});

// ---------- tabs ----------
document.querySelectorAll(".tab").forEach((t) =>
  t.addEventListener("click", () => {
    tab = t.dataset.tab;
    document.querySelectorAll(".tab").forEach((x) => x.classList.toggle("on", x === t));
    for (const p of ["timeline", "incidents", "coverage"]) $("tab-" + p).hidden = p !== tab;
    lastTimelineKey = "";
    refreshDetail();
  })
);
$("filter").addEventListener("change", () => { lastTimelineKey = ""; refreshTimeline(); });

// ---------- start monitoring ----------
let templates = [];
async function openStart() {
  $("start-error").hidden = true;
  $("start-dialog").hidden = false;
  try {
    if (!templates.length) templates = await api("templates");
    $("template").replaceChildren(...templates.map((t) => h("option", { value: t.name }, t.name)));
    const preferred = ["no-network", "windows-no-network"].find((n) => templates.some((t) => t.name === n));
    if (preferred) $("template").value = preferred;
    onTemplate();
    const c = await api("containers");
    const sel = $("container");
    const haveContainers = c.available && c.containers.length > 0;
    // Default to what can actually be watched: without running containers
    // (or without Docker at all, as on most Windows PCs) that is a process.
    setKind(haveContainers ? "container" : "pid");
    if (haveContainers) {
      sel.replaceChildren(...c.containers.map((x) => h("option", { value: x.name }, `${x.name}  —  ${x.image}  (${x.status})`)));
      $("container-hint").textContent = "Kill Line watches every process in this container, including ones started later with docker exec.";
    } else {
      sel.replaceChildren(h("option", { value: "" }, c.available ? "No running containers" : "Docker is not available"));
      $("container-hint").textContent = c.available ? "Start your agent's container first, or watch a process instead." : "Watch a process instead, or install and start Docker.";
    }
  } catch (e) { $("start-error").textContent = e.message; $("start-error").hidden = false; }
  ($("kind-pid").checked ? $("pid") : $("container")).focus();
}
function setKind(kind) {
  $("kind-pid").checked = kind === "pid";
  $("kind-container").checked = kind !== "pid";
  $("pick-pid").hidden = kind !== "pid";
  $("pick-container").hidden = kind === "pid";
}
function onTemplate() {
  const t = templates.find((x) => x.name === $("template").value);
  if (!t) return;
  $("template-desc").textContent = t.description || "";
  $("policy-text").value = t.text;
  validatePolicy();
}
let validateTimer = null;
async function validatePolicy() {
  try {
    const r = await api("validate", { method: "POST", body: { policy_text: $("policy-text").value } });
    $("diags").replaceChildren(
      ...r.diagnostics.filter((d) => d.level !== "info").map((d) => h("li", { class: d.level }, `${d.level.toUpperCase()}: ${d.message}`)),
      r.valid ? h("li", { class: "info" }, "Policy is valid.") : null
    );
    $("start-go").disabled = !r.valid;
  } catch (e) { /* shown on submit */ }
}
$("template").addEventListener("change", onTemplate);
$("policy-text").addEventListener("input", () => { clearTimeout(validateTimer); validateTimer = setTimeout(validatePolicy, 400); });
document.querySelectorAll("input[name=kind]").forEach((r) =>
  r.addEventListener("change", () => setKind($("kind-pid").checked ? "pid" : "container"))
);
$("btn-start").addEventListener("click", openStart);
$("btn-start-2").addEventListener("click", openStart);
$("start-cancel").addEventListener("click", () => ($("start-dialog").hidden = true));
$("start-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  $("start-error").hidden = true;
  const body = { policy_text: $("policy-text").value, response: $("response").value };
  if ($("kind-pid").checked) {
    const pid = parseInt($("pid").value, 10);
    if (!(pid > 0)) { $("start-error").textContent = "Enter a process ID (a positive number)."; $("start-error").hidden = false; return; }
    body.pid = pid;
  } else {
    body.container = $("container").value;
    if (!body.container) { $("start-error").textContent = "Choose a running container."; $("start-error").hidden = false; return; }
  }
  $("start-go").disabled = true;
  $("start-go").textContent = "Starting…";
  try {
    const r = await api("monitor", { method: "POST", body });
    $("start-dialog").hidden = true;
    toast(`Monitoring ${r.target}`);
    selected = r.session_id;
    await loadSessions();
    select(r.session_id);
  } catch (err) {
    $("start-error").textContent = err.message;
    $("start-error").hidden = false;
  } finally {
    $("start-go").disabled = false;
    $("start-go").textContent = "Start monitoring";
  }
});

// ---------- boot ----------
async function boot() {
  if (!TOKEN) { $("locked").hidden = false; return; }
  try {
    const o = await api("overview");
    $("host").textContent = `${o.hostname} · Linux ${o.kernel} · v${o.version}${o.ebpf_built ? "" : " · eBPF missing"}`;
    await loadSessions();
  } catch (e) {
    if (e.message !== "locked") toast(e.message);
    return;
  }
  setInterval(() => loadSessions().catch(() => {}), 2000);
  setInterval(() => refreshDetail().catch(() => {}), 1500);
}
boot();
