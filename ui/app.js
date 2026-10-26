/* PenAgent Console — vanilla JS, no build step, no framework.
 * Talks directly to a running Component 3 (executor) and Component 6
 * (report) over fetch(). Nothing here is sent anywhere but the base URLs
 * you configure; the token is kept only in this browser's localStorage. */
"use strict";

const LS_KEY = "penagent-console-config-v1";
const POLL_MS = 4000;

const state = {
  cfg: { c3: "", c6: "", c1: "", token: "" },
  view: "audits",     // "audits" | "baselines"
  audits: [],
  selected: null,
  selectedTarget: null,
  tab: "explore",
  pollHandle: null,
  graphCache: {},      // target_id -> {nodes}, fetched once per target
  guidedChains: null,  // loaded once from data/guided-chains.json
  guidedProgress: {},  // audit_id -> next step index
  guidedRunning: false,
  resultsCache: null,  // loaded once from data/results.json
  comparisonCache: null, // loaded once from data/comparison.json
  exploreCache: null,  // loaded once from data/explore.json
  exploreSelected: {}, // target_id -> currently selected op_id in the Exploration view
};

// ---------- small utilities ----------

function escapeHtml(value) {
  return String(value ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}

function fmtTime(seconds) {
  if (!seconds) return "—";
  return new Date(seconds * 1000).toLocaleString();
}

function badge(text, cls) {
  return `<span class="badge badge-${escapeHtml(cls)}">${escapeHtml(text)}</span>`;
}

function severityClass(sev) {
  return `sev-${(sev || "low").toLowerCase()}`;
}

function toast(message, kind) {
  const stack = document.getElementById("toastStack") || (() => {
    const s = document.createElement("div");
    s.id = "toastStack";
    s.className = "toast-stack";
    document.body.appendChild(s);
    return s;
  })();
  const t = document.createElement("div");
  t.className = `toast ${kind || ""}`;
  t.textContent = message;
  stack.appendChild(t);
  setTimeout(() => t.remove(), 5000);
}

// ---------- API ----------

async function api(base, path, opts = {}) {
  if (!base) throw new Error("not configured");
  const headers = Object.assign({ "Content-Type": "application/json" }, opts.headers || {});
  if (state.cfg.token) headers.Authorization = "Bearer " + state.cfg.token;
  const response = await fetch(base.replace(/\/$/, "") + path, Object.assign({}, opts, { headers }));
  let body = null;
  try { body = await response.json(); } catch { /* no body */ }
  if (!response.ok) {
    const detail = body && body.detail ? body.detail : response.statusText;
    throw new Error(`${response.status} ${detail}`);
  }
  return body;
}

const c3 = (path, opts) => api(state.cfg.c3, path, opts);
const c6 = (path, opts) => api(state.cfg.c6, path, opts);
const c1 = (path, opts) => api(state.cfg.c1, path, opts);   // SIS: unauthenticated by design, token sent is simply ignored

// ---------- config / connection ----------

const DEFAULT_CFG = { c3: "http://127.0.0.1:9003", c6: "http://127.0.0.1:9005", c1: "http://127.0.0.1:9001", token: "" };

function loadConfig() {
  try {
    const saved = JSON.parse(localStorage.getItem(LS_KEY) || "{}");
    state.cfg = Object.assign({}, DEFAULT_CFG, saved);
  } catch {
    state.cfg = Object.assign({}, DEFAULT_CFG);
  }
  document.getElementById("c3Url").value = state.cfg.c3;
  document.getElementById("c6Url").value = state.cfg.c6;
  document.getElementById("c1Url").value = state.cfg.c1;
  document.getElementById("token").value = state.cfg.token;
}

function saveConfig() {
  state.cfg = {
    c3: document.getElementById("c3Url").value.trim(),
    c6: document.getElementById("c6Url").value.trim(),
    c1: document.getElementById("c1Url").value.trim(),
    token: document.getElementById("token").value.trim(),
  };
  try { localStorage.setItem(LS_KEY, JSON.stringify(state.cfg)); } catch { /* storage unavailable; config still works for this session */ }
}

async function testConnection() {
  const statusEl = document.getElementById("connStatus");
  statusEl.innerHTML = '<span class="dot dot-unknown"></span>Connecting…';
  try {
    const [h3, h6] = await Promise.all([
      fetch(state.cfg.c3.replace(/\/$/, "") + "/health").then((r) => r.json()),
      fetch(state.cfg.c6.replace(/\/$/, "") + "/health").then((r) => r.json()),
    ]);
    if (h3.status === "healthy" && h6.status === "healthy") {
      statusEl.innerHTML = '<span class="dot dot-ok"></span>Connected (C3 + C6 healthy)';
      return true;
    }
    throw new Error("unhealthy");
  } catch (err) {
    statusEl.innerHTML = '<span class="dot dot-bad"></span>Not reachable';
    return false;
  }
}

// ---------- audits sidebar ----------

async function refreshAuditList() {
  const list = document.getElementById("auditList");
  try {
    const data = await c3("/v1/audits");
    state.audits = data.audits || [];
  } catch (err) {
    list.innerHTML = `<li class="audit-empty">${escapeHtml(err.message)}</li>`;
    return;
  }
  if (!state.audits.length) {
    list.innerHTML = '<li class="audit-empty">No audits yet. Create one below.</li>';
    return;
  }
  list.innerHTML = state.audits.map((a) => `
    <li class="audit-item ${a.id === state.selected ? "selected" : ""}" data-audit="${escapeHtml(a.id)}">
      <span class="audit-item-id">${escapeHtml(a.id)}</span>
      <span class="audit-item-meta">
        <span>${escapeHtml(a.target)}</span>
        <span>·</span>
        <span>${escapeHtml(a.state)}</span>
        ${a.halted ? '<span class="badge badge-CONFIRMED_VULNERABILITY">halted</span>' : ""}
      </span>
    </li>`).join("");
  list.querySelectorAll(".audit-item").forEach((el) => {
    el.addEventListener("click", () => selectAudit(el.dataset.audit));
  });
}

async function createAudit(ev) {
  ev.preventDefault();
  const id = document.getElementById("newAuditId").value.trim();
  const target = document.getElementById("newAuditTarget").value.trim();
  try {
    await c3("/v1/audits", { method: "POST", body: JSON.stringify({ audit_id: id, target_id: target, acknowledged_authorization: true }) });
    toast(`Audit "${id}" created`, "ok");
    document.getElementById("newAuditForm").reset();
    await refreshAuditList();
    selectAudit(id);
  } catch (err) {
    toast(`Could not create audit: ${err.message}`, "err");
  }
}

// ---------- audit detail ----------

function selectAudit(id) {
  state.selected = id;
  state.selectedTarget = null;
  state.tab = "explore";
  if (state.pollHandle) clearInterval(state.pollHandle);
  refreshAuditList();
  renderMain();
  state.pollHandle = setInterval(() => { if (state.selected) renderTabBody(); }, POLL_MS);
}

function auditHeaderBadges(audit) {
  const badges = [`<span class="badge badge-neutral">${escapeHtml(audit.state)}</span>`];
  if (audit.halted) badges.push(badge("halted", "CONFIRMED_VULNERABILITY"));
  if (audit.cancelled) badges.push(badge("cancelled", "neutral"));
  return badges.join(" ");
}

async function renderMain() {
  const main = document.getElementById("main");
  if (!state.selected) {
    main.innerHTML = `<div class="empty-state"><h1>No audit selected</h1><p>Pick an audit from the left, or create one.</p></div>`;
    return;
  }
  let audit;
  try {
    audit = await c3(`/v1/audits/${encodeURIComponent(state.selected)}`);
  } catch (err) {
    main.innerHTML = `<div class="empty-state"><h1>Could not load audit</h1><p>${escapeHtml(err.message)}</p></div>`;
    return;
  }
  state.selectedTarget = audit.target;
  main.innerHTML = `
    <div class="audit-header">
      <div>
        <h1>${escapeHtml(audit.id)}</h1>
        <div class="audit-sub">target: ${escapeHtml(audit.target)} · created ${fmtTime(audit.created)} · ${audit.probes} probe(s)</div>
      </div>
      <div class="badges">${auditHeaderBadges(audit)}</div>
    </div>
    <div class="tabs">
      <button class="tab" data-tab="explore">Explore</button>
      <button class="tab" data-tab="evidence">Evidence</button>
      <button class="tab" data-tab="approvals">Approvals<span class="count" id="approvalsCount"></span></button>
      <button class="tab" data-tab="report">Report</button>
      <button class="tab" data-tab="state">Session state</button>
    </div>
    <div id="tabBody"></div>
  `;
  main.querySelectorAll(".tab").forEach((btn) => btn.addEventListener("click", () => { state.tab = btn.dataset.tab; renderTabBody(); }));
  renderTabBody();
}

async function renderTabBody() {
  const body = document.getElementById("tabBody");
  if (!body) return;
  document.querySelectorAll(".tab").forEach((btn) => btn.classList.toggle("active", btn.dataset.tab === state.tab));
  const renderers = { explore: renderExploreTab, evidence: renderEvidenceTab, approvals: renderApprovalsTab, report: renderReportTab, state: renderStateTab };
  await renderers[state.tab](body);
}

// --- Explore tab: live endpoint map + activity feed ---

const CLASS_COLOR_VAR = {
  CONFIRMED_VULNERABILITY: "--confirmed", STRONG_SIGNAL: "--strong", WEAK_SIGNAL: "--weak",
  NEGATIVE: "--negative", ERROR_CRASH: "--error", pending: "--pending", unprobed: "--border",
};

async function fetchGraph(target) {
  if (state.graphCache[target]) return state.graphCache[target];
  const graph = await c1(`/v1/graph/${encodeURIComponent(target)}`);
  state.graphCache[target] = graph;
  return graph;
}

async function fetchGuidedChains() {
  if (state.guidedChains) return state.guidedChains;
  const response = await fetch("data/guided-chains.json");
  state.guidedChains = response.ok ? await response.json() : {};
  return state.guidedChains;
}

function resolveBinding(binding) {
  // __DYNAMIC__ markers (e.g. a registration email) get a fresh value per run,
  // same convention as demo/run_evaluation.py's guided_run.
  const copy = structuredClone(binding || {});
  if (copy.body?.email === "__DYNAMIC__") {
    copy.body.email = `ui-${Math.random().toString(16).slice(2, 10)}@test.local`;
  }
  return copy;
}

function runPanelHtml(chain, progress) {
  const done = progress >= chain.length;
  const step = chain[progress];
  return `
    <div class="card run-panel">
      <div class="card-title">Run against ${escapeHtml(state.selectedTarget)} — step ${Math.min(progress + 1, chain.length)}/${chain.length}</div>
      <div class="run-panel-row">
        <span class="run-step-label">${done ? '<span class="run-done">&check; Chain complete</span>' :
          `Next: <span class="mono">${escapeHtml(step.method)} ${escapeHtml(step.path)}</span> — ${escapeHtml(step.owasp_category)}`}</span>
        <button class="btn btn-primary btn-sm" id="runStepBtn" ${done || state.guidedRunning ? "disabled" : ""}>Run this step</button>
        <button class="btn btn-ghost btn-sm" id="runAllBtn" ${done || state.guidedRunning ? "disabled" : ""}>Run all remaining (paced)</button>
        <button class="btn btn-ghost btn-sm" id="resetRunBtn" title="Replay from the start (new probes, same target)">Reset</button>
      </div>
      <div class="run-log" id="runLog"></div>
    </div>`;
}

function logRun(message) {
  const log = document.getElementById("runLog");
  if (!log) return;
  const line = document.createElement("div");
  line.textContent = message;
  log.appendChild(line);
  log.scrollTop = log.scrollHeight;
}

async function runGuidedStep(chain) {
  const index = state.guidedProgress[state.selected] || 0;
  const step = chain[index];
  if (!step) return;
  state.guidedRunning = true;
  await renderTabBody();
  logRun(`→ running ${step.method} ${step.path} ...`);
  try {
    const outcome = await c3(`/v1/audits/${encodeURIComponent(state.selected)}/guided-step`, {
      method: "POST", body: JSON.stringify({ op: step.op, owasp_category: step.owasp_category, binding: resolveBinding(step.binding) }),
    });
    const r = outcome.result;
    if (r.status === "awaiting_approval") {
      logRun(`  ⏸ paused for Component 5 approval — resolve it in the Approvals tab, then click "Run this step" again`);
    } else {
      const cls = outcome.interpretation ? outcome.interpretation.classification : r.status;
      logRun(`  ← ${r.status} (HTTP ${r.status_code ?? "—"}) → ${cls}`);
      state.guidedProgress[state.selected] = index + 1;
    }
  } catch (err) {
    logRun(`  ✗ failed: ${err.message}`);
    toast(`Step failed: ${err.message}`, "err");
  }
  state.guidedRunning = false;
  await renderTabBody();
}

async function runGuidedChain(chain) {
  // Paced, sequential by design (mirrors demo/live_demo.py's cadence) -- each
  // step must complete and update state before the next one is dispatched.
  while ((state.guidedProgress[state.selected] || 0) < chain.length) {
    const before = state.guidedProgress[state.selected] || 0;
    await runGuidedStep(chain);
    const after = state.guidedProgress[state.selected] || 0;
    if (after === before) break; // stalled: awaiting approval, or the step failed
    await new Promise((resolve) => setTimeout(resolve, 2200));
  }
}

function layoutNodes(nodes, width, height) {
  const cx = width / 2, cy = height / 2, r = Math.min(width, height) / 2 - 70;
  return nodes.map((n, i) => {
    const angle = (i / Math.max(nodes.length, 1)) * 2 * Math.PI - Math.PI / 2;
    return { node: n, x: cx + r * Math.cos(angle), y: cy + r * Math.sin(angle), cx, cy };
  });
}

async function renderExploreTab(body) {
  let graph;
  try {
    graph = await fetchGraph(state.selectedTarget);
  } catch (err) {
    body.innerHTML = `<p class="empty-tab">Couldn't load the endpoint graph from C1 (${escapeHtml(err.message)}). `
      + `Make sure the "Spec graph (C1)" URL is set and this target has been ingested (<code>POST {c1}/v1/ingest</code>).</p>`;
    return;
  }
  let evidence;
  try {
    evidence = await c3(`/v1/audits/${encodeURIComponent(state.selected)}/evidence`);
  } catch (err) {
    evidence = { probes: [] };
  }
  // Latest known state per op: interpretation classification if present,
  // else the raw execution status (e.g. "awaiting_approval"), else "pending".
  const opState = {};
  const opLastProbe = {};
  for (const p of evidence.probes || []) {
    const r = p.result || {};
    if (!r.op) continue;
    opState[r.op] = p.interpretation ? p.interpretation.classification : (r.status || "pending");
    opLastProbe[r.op] = p;
  }

  const width = 560, height = 560;
  const positioned = layoutNodes(graph.nodes || [], width, height);
  const edges = positioned.map((p) => `<line x1="${p.cx}" y1="${p.cy}" x2="${p.x}" y2="${p.y}" class="explore-edge ${opState[p.node.id] ? 'explore-edge-active' : ''}"></line>`).join("");
  const nodes = positioned.map((p) => {
    const cls = opState[p.node.id];
    const colorVar = CLASS_COLOR_VAR[cls] || CLASS_COLOR_VAR.unprobed;
    const probed = Boolean(cls);
    return `
      <g class="explore-node ${probed ? 'explore-node-probed' : ''}" data-op="${escapeHtml(p.node.id)}" transform="translate(${p.x},${p.y})">
        <circle r="${probed ? 13 : 9}" style="fill:var(${colorVar})"></circle>
        <text y="24" text-anchor="middle" class="explore-label">${escapeHtml(p.node.method)}</text>
        <title>${escapeHtml(p.node.method)} ${escapeHtml(p.node.path)}${cls ? ' — ' + escapeHtml(cls) : ' — not yet probed'}</title>
      </g>`;
  }).join("");
  const probedCount = Object.keys(opState).length;

  const feedItems = (evidence.probes || []).slice().reverse().map((p) => {
    const r = p.result || {};
    const cls = p.interpretation ? p.interpretation.classification : (r.status || "pending");
    return `<div class="feed-item">
      <span class="feed-dot" style="background:var(${CLASS_COLOR_VAR[cls] || CLASS_COLOR_VAR.unprobed})"></span>
      <span class="mono feed-op">${escapeHtml(r.op || "?")}</span>
      <span class="feed-status">${escapeHtml(r.status_code ?? "")} ${escapeHtml(cls)}</span>
    </div>`;
  }).join("") || '<p class="empty-tab">No activity yet.</p>';

  // If this target has a pre-authored guided chain (dvws / srebench-api /
  // juice-shop), offer real one-click execution -- not just a watch view.
  const chains = await fetchGuidedChains();
  const chain = chains[state.selectedTarget];
  const runPanel = chain ? runPanelHtml(chain, state.guidedProgress[state.selected] || 0) : "";

  body.innerHTML = `
    ${runPanel}
    <div class="explore-layout">
      <div class="card explore-card">
        <div class="card-title">Endpoint map — ${probedCount}/${(graph.nodes || []).length} probed</div>
        <svg viewBox="0 0 ${width} ${height}" class="explore-svg">
          ${edges}
          <circle cx="${width / 2}" cy="${height / 2}" r="34" class="explore-hub"></circle>
          <text x="${width / 2}" y="${height / 2 + 5}" text-anchor="middle" class="explore-hub-label">${escapeHtml(state.selectedTarget || "")}</text>
          ${nodes}
        </svg>
        <div class="explore-legend">
          ${["CONFIRMED_VULNERABILITY", "STRONG_SIGNAL", "WEAK_SIGNAL", "NEGATIVE", "ERROR_CRASH"].map((c) =>
            `<span class="legend-item"><span class="legend-dot" style="background:var(${CLASS_COLOR_VAR[c]})"></span>${escapeHtml(c)}</span>`).join("")}
          <span class="legend-item"><span class="legend-dot" style="background:var(--border)"></span>not yet probed</span>
        </div>
      </div>
      <div class="card explore-feed">
        <div class="card-title">Live activity</div>
        <div class="feed">${feedItems}</div>
      </div>
    </div>
  `;

  if (chain) {
    document.getElementById("runStepBtn")?.addEventListener("click", () => runGuidedStep(chain));
    document.getElementById("runAllBtn")?.addEventListener("click", () => runGuidedChain(chain));
    document.getElementById("resetRunBtn")?.addEventListener("click", () => {
      state.guidedProgress[state.selected] = 0;
      void renderTabBody();
    });
  }
}

// --- Evidence tab ---

async function renderEvidenceTab(body) {
  let evidence;
  try {
    evidence = await c3(`/v1/audits/${encodeURIComponent(state.selected)}/evidence`);
  } catch (err) {
    body.innerHTML = `<p class="empty-tab">${escapeHtml(err.message)}</p>`;
    return;
  }
  const transitions = (evidence.transitions || []).map((t) => `<span class="step">${escapeHtml(t.data.state)}</span>`).join('<span class="arrow">&rarr;</span>');
  const probes = evidence.probes || [];
  const items = probes.length
    ? probes.map((p) => {
        const r = p.result || {};
        const interp = p.interpretation;
        const cls = interp ? interp.classification : "WEAK_SIGNAL";
        return `
        <div class="tl-item tl-${escapeHtml(cls)}">
          <div class="card">
            <div class="card-title">
              <span class="mono">${escapeHtml((p.probe_id || "").slice(0, 12))}</span>
              ${interp ? badge(interp.classification, interp.classification) : badge(r.status || "unknown", r.status || "awaiting_approval")}
            </div>
            <div class="card-row">
              <span>op <b>${escapeHtml(r.op || "—")}</b></span>
              <span>HTTP <b>${escapeHtml(r.status_code ?? "—")}</b></span>
              <span>status <b>${escapeHtml(r.status || "—")}</b></span>
              ${r.latency_ms ? `<span>latency <b>${Math.round(r.latency_ms)}ms</b></span>` : ""}
            </div>
            ${interp ? `<p>${escapeHtml(interp.reasoning_summary)}</p>
              <div class="kv">
                <dt>observed</dt><dd>${escapeHtml(interp.observed_behavior)}</dd>
                <dt>next action</dt><dd class="mono">${escapeHtml(interp.next_action)}</dd>
              </div>` : `<p class="muted">${r.error ? escapeHtml(r.error) : "not yet interpreted"}</p>`}
          </div>
        </div>`;
      }).join("")
    : '<p class="empty-tab">No probes recorded yet.</p>';
  body.innerHTML = `
    <div class="card">
      <div class="card-title">State machine transitions</div>
      <div class="transitions">${transitions || '<span class="muted">none yet</span>'}</div>
    </div>
    <div class="timeline">${items}</div>
  `;
}

// --- Approvals tab ---

async function renderApprovalsTab(body) {
  let data;
  try {
    data = await c3(`/v1/audits/${encodeURIComponent(state.selected)}/approvals`);
  } catch (err) {
    body.innerHTML = `<p class="empty-tab">${escapeHtml(err.message)}</p>`;
    return;
  }
  const approvals = data.approvals || [];
  const countEl = document.getElementById("approvalsCount");
  const pendingCount = approvals.filter((a) => a.status === "pending").length;
  if (countEl) countEl.textContent = pendingCount ? ` ${pendingCount}` : "";
  if (!approvals.length) {
    body.innerHTML = '<p class="empty-tab">Nothing has needed human approval on this audit yet.</p>';
    return;
  }
  body.innerHTML = approvals.map((a) => {
    const d = a.description || {};
    const pending = a.status === "pending";
    return `
    <div class="card">
      <div class="card-title">
        <span class="mono">${escapeHtml(d.method || "")} ${escapeHtml(d.path || "")}</span>
        ${badge(a.status, a.status)}
      </div>
      <div class="card-row">
        <span>category <b>${escapeHtml(d.owasp_category || "—")}</b></span>
        <span>risk <b>${escapeHtml(d.risk_classification || "—")}</b></span>
        <span>requested <b>${fmtTime(a.requested)}</b></span>
      </div>
      <p>${escapeHtml(d.motivation || "")}</p>
      ${d.prior_evidence ? `<p class="muted">Prior evidence: ${escapeHtml(d.prior_evidence)}</p>` : ""}
      <p class="muted">${escapeHtml(d.expected_outcome || "")}</p>
      ${pending ? `
        <form class="stack-sm" data-probe="${escapeHtml(a.probe_id)}" style="margin-top:12px">
          <label class="field"><span>Reason (optional for approve, recommended for deny)</span><input type="text" class="reason"></label>
          <div style="display:flex; gap:8px">
            <button type="button" class="btn btn-approve decide" data-decision="approve">Approve &amp; execute</button>
            <button type="button" class="btn btn-deny decide" data-decision="deny">Deny</button>
          </div>
        </form>` : a.decided_by ? `<p class="muted">Decided by ${escapeHtml(a.decided_by)} at ${fmtTime(a.decided)}${a.reason ? ": " + escapeHtml(a.reason) : ""}</p>` : ""}
    </div>`;
  }).join("");
  body.querySelectorAll(".decide").forEach((btn) => btn.addEventListener("click", () => decideApproval(btn)));
}

async function decideApproval(btn) {
  const form = btn.closest("form");
  const probeId = form.dataset.probe;
  const decision = btn.dataset.decision;
  const reason = form.querySelector(".reason").value.trim() || undefined;
  form.querySelectorAll("button").forEach((b) => (b.disabled = true));
  try {
    await c3(`/v1/audits/${encodeURIComponent(state.selected)}/approvals/${encodeURIComponent(probeId)}`, {
      method: "POST", body: JSON.stringify({ decision, reason }),
    });
    toast(`Probe ${decision}d`, decision === "approve" ? "ok" : "err");
  } catch (err) {
    toast(`Decision failed: ${err.message}`, "err");
  }
  renderTabBody();
}

// --- Report tab ---

function findingCard(f) {
  return `
  <div class="card">
    <div class="severity-bar"><span style="width:100%;background:var(--sev-${escapeHtml((f.severity || "low"))})"></span></div>
    <div class="card-title">
      <span>${escapeHtml(f.title)}</span>
      <span>${badge(f.severity, `sev-${f.severity}`)} ${badge(f.classification, f.classification)}</span>
    </div>
    <div class="card-row">
      <span>CVSS <b>${f.cvss_score}</b></span>
      <span class="mono">${escapeHtml(f.cvss_vector)}</span>
      <span>confidence <b>${Math.round(f.confidence * 100)}%</b></span>
      <span>chain depth <b>${(f.probe_chain || []).length}</b></span>
    </div>
    <p>${escapeHtml(f.explanation)}</p>
    <div class="kv"><dt>remediation</dt><dd>${escapeHtml(f.remediation)}</dd></div>
  </div>`;
}

async function renderReportTab(body) {
  let report;
  try {
    report = await c6(`/v1/audits/${encodeURIComponent(state.selected)}/report`);
  } catch (err) {
    body.innerHTML = `<p class="empty-tab">${escapeHtml(err.message)}</p>`;
    return;
  }
  const summary = Object.entries(report.summary || {}).map(([k, v]) => `${badge(v, k)} <span class="mono">&times;${v}</span>`).join(" &nbsp; ");
  const findings = (report.findings || []).map(findingCard).join("") || '<p class="empty-tab">No CONFIRMED/STRONG findings yet.</p>';
  const observations = (report.observations || []).map((o) => `
    <div class="card"><div class="card-title">${escapeHtml(o.method || "")} ${escapeHtml(o.path || "")} ${badge("WEAK_SIGNAL", "WEAK_SIGNAL")}</div><p>${escapeHtml(o.reasoning_summary)}</p></div>`).join("");
  const issues = (report.operational_issues || []).map((o) => `
    <div class="card"><div class="card-title">${escapeHtml(o.method || "")} ${escapeHtml(o.path || "")} ${badge("ERROR_CRASH", "ERROR_CRASH")}</div><p>${escapeHtml(o.reasoning_summary)}</p></div>`).join("");
  const pdfUrl = `${state.cfg.c6.replace(/\/$/, "")}/v1/audits/${encodeURIComponent(state.selected)}/report.pdf`;
  body.innerHTML = `
    <div class="card">
      <div class="card-title">
        <span>Summary (${report.probes_executed} probes)</span>
        <a class="btn btn-ghost btn-sm" id="downloadPdf" href="#" title="Fetches the PDF with your auth token, since a plain link can't carry it">&#8681; Download PDF report</a>
      </div>
      <div>${summary || '<span class="muted">no interpreted probes yet</span>'}</div>
    </div>
    <h3>Findings</h3>${findings}
    ${observations ? `<h3>Observations</h3>${observations}` : ""}
    ${issues ? `<h3>Operational issues</h3>${issues}` : ""}
  `;
  document.getElementById("downloadPdf").addEventListener("click", async (ev) => {
    ev.preventDefault();
    try {
      const response = await fetch(pdfUrl, { headers: { Authorization: "Bearer " + state.cfg.token } });
      if (!response.ok) throw new Error(`${response.status}`);
      const blob = await response.blob();
      const url = URL.createObjectURL(blob);
      window.open(url, "_blank");
      setTimeout(() => URL.revokeObjectURL(url), 30000);
    } catch (err) {
      toast(`Could not fetch PDF: ${err.message}`, "err");
    }
  });
}

// --- State tab ---

async function renderStateTab(body) {
  let session;
  try {
    session = await c3(`/v1/audits/${encodeURIComponent(state.selected)}/state`);
  } catch (err) {
    body.innerHTML = `<p class="empty-tab">${escapeHtml(err.message)}</p>`;
    return;
  }
  const sections = Object.entries(session.values || {}).map(([category, entries]) => {
    const rows = Object.entries(entries).map(([k, v]) => `<dt>${escapeHtml(k)}</dt><dd class="mono">${escapeHtml(JSON.stringify(v))}</dd>`).join("");
    return `<div class="card"><div class="card-title">${escapeHtml(category)}</div><dl class="kv">${rows || '<dd class="muted">empty</dd>'}</dl></div>`;
  }).join("");
  body.innerHTML = sections || '<p class="empty-tab">No session state recorded yet.</p>';
}

// ---------- Baselines & Results view ----------

const BASELINE_LABELS = {
  "gemma3-4b": "Gemma 3 4B", "llama3.2-3b": "Llama 3.2 3B", "phi3-latest": "Phi-3 3.8B",
  "gemma2-2b": "Gemma 2 2B", "qwen-latest": "Qwen2 4B", "gemma3-1b-it-qat": "Gemma 3 1B",
};
const TARGET_LABELS = { dvws: "DVWS", "srebench-api": "SREBench-API", "juice-shop": "Juice Shop" };

function pct(value) {
  return value == null ? "—" : `${Math.round(value * 100)}%`;
}

function metricBarRow(label, value, colorVar) {
  const width = Math.max(0, Math.min(1, value || 0)) * 100;
  return `<div class="bar-row">
    <span>${escapeHtml(label)}</span>
    <div class="bar-track"><div class="bar-fill" style="width:${width}%;background:var(${colorVar})"></div></div>
    <span class="mono">${pct(value)}</span>
  </div>`;
}

async function fetchResults() {
  if (state.resultsCache) return state.resultsCache;
  const response = await fetch("data/results.json");
  state.resultsCache = response.ok ? await response.json() : { penagent: {}, baseline: {} };
  return state.resultsCache;
}

function resultsTableRows(target, results) {
  const pa = results.penagent[target] || {};
  const rows = [];
  if (pa.autonomous) rows.push(["PenAgent (autonomous)", pa.autonomous]);
  if (pa.guided) rows.push(["PenAgent (guided)", pa.guided]);
  for (const [model, byTarget] of Object.entries(results.baseline)) {
    const entry = byTarget[target];
    if (entry) rows.push([`${BASELINE_LABELS[model] || model} (baseline)`, entry.metrics]);
  }
  return rows;
}

function renderResultsTable(target, results) {
  const rows = resultsTableRows(target, results);
  const body = rows.map(([label, m]) => `
    <tr>
      <td>${escapeHtml(label)}</td>
      <td>${pct(m.true_positive_rate)}</td>
      <td>${pct(m.false_positive_rate)}</td>
      <td>${m.cvss_score_accuracy == null ? "—" : pct(m.cvss_score_accuracy)}</td>
      <td>${m.avg_exploit_chain_depth ?? "—"}</td>
      <td>${m.time_to_first_finding_seconds == null ? "—" : `${m.time_to_first_finding_seconds.toFixed(2)}s`}</td>
      <td>${m.confirmed_findings}/${m.total_ground_truth}</td>
    </tr>`).join("");
  return `
    <div class="result-table-wrap">
      <table class="result-table">
        <thead><tr><th>Run</th><th>TPR</th><th>FPR</th><th>CVSS acc.</th><th>Avg. chain depth</th><th>Time to 1st finding</th><th>Confirmed / ground truth</th></tr></thead>
        <tbody>${body}</tbody>
      </table>
    </div>`;
}

function renderTargetCard(target, results) {
  const pa = results.penagent[target] || {};
  const bars = [];
  if (pa.autonomous) bars.push(["PenAgent (autonomous)", pa.autonomous.true_positive_rate, true]);
  if (pa.guided) bars.push(["PenAgent (guided)", pa.guided.true_positive_rate, true]);
  for (const [model, byTarget] of Object.entries(results.baseline)) {
    const entry = byTarget[target];
    if (entry) bars.push([`${BASELINE_LABELS[model] || model}`, entry.metrics.true_positive_rate, false]);
  }
  // Only one categorical distinction matters here -- PenAgent vs. baseline --
  // so that's the only thing color encodes, rather than 8 cycled hues for 8 bars.
  const barHtml = bars.map(([label, value, isPenAgent]) => metricBarRow(label, value, isPenAgent ? "--pending" : "--text-faint")).join("");
  return `
    <div class="card">
      <div class="card-title">${escapeHtml(TARGET_LABELS[target] || target)} — true positive rate</div>
      <div class="bars">${barHtml}</div>
      ${renderResultsTable(target, results)}
    </div>`;
}

async function fetchComparison() {
  if (state.comparisonCache) return state.comparisonCache;
  const response = await fetch("data/comparison.json");
  state.comparisonCache = response.ok ? await response.json() : { rows: [] };
  return state.comparisonCache;
}

function comparisonBarChart(rows, metricKey, metricLabel) {
  const sorted = rows.slice().sort((a, b) => (b.metrics[metricKey] ?? 0) - (a.metrics[metricKey] ?? 0));
  const bars = sorted.map((r) => metricBarRow(
    r.is_penagent ? `★ ${r.label}` : r.label,
    r.metrics[metricKey], r.is_penagent ? "--pending" : "--text-faint",
  )).join("");
  return `
    <div class="comparison-chart">
      <div class="explore-section-title">${escapeHtml(metricLabel)} — ranked</div>
      <div class="bars">${bars}</div>
    </div>`;
}

function comparisonTableHtml(rows) {
  const sorted = rows.slice().sort((a, b) => (b.metrics.f1_score ?? 0) - (a.metrics.f1_score ?? 0));
  const body = sorted.map((r) => `
    <tr class="${r.is_penagent ? "row-highlight" : ""}">
      <td>${r.is_penagent ? "&#9733; " : ""}${escapeHtml(r.label)}</td>
      <td>${r.params_b ? `${r.params_b}B` : "—"}</td>
      <td>${pct(r.metrics.precision)}</td>
      <td>${pct(r.metrics.recall)}</td>
      <td><b>${pct(r.metrics.f1_score)}</b></td>
      <td>${r.metrics.cvss_score_accuracy == null ? "—" : pct(r.metrics.cvss_score_accuracy)}</td>
      <td>${r.avg_wall_clock_seconds != null ? `${r.avg_wall_clock_seconds}s` : "live HTTP, no LLM call"}</td>
    </tr>`).join("");
  return `
    <div class="table-toolbar">
      <button class="btn btn-ghost btn-sm csv-download-btn" data-table-id="comparisonTable" data-filename="penagent-comparison.csv">&#8681; CSV</button>
    </div>
    <div class="result-table-wrap">
      <table class="result-table" id="comparisonTable">
        <thead><tr><th>Approach</th><th>Model size</th><th>Precision</th><th>Recall</th><th>F1</th><th>CVSS acc.</th><th>Avg. time</th></tr></thead>
        <tbody>${body}</tbody>
      </table>
    </div>`;
}

async function renderComparisonSection() {
  let comparison;
  try {
    comparison = await fetchComparison();
  } catch {
    return "";
  }
  const rows = comparison.rows || [];
  if (!rows.length) return "";
  const best = rows.slice().sort((a, b) => (b.metrics.f1_score ?? 0) - (a.metrics.f1_score ?? 0))[0];
  return `
    <div class="card">
      <div class="card-title">Head-to-head: PenAgent vs. 6 local LLM baselines, averaged across all 3 targets</div>
      <p class="muted" style="margin-bottom:var(--space-4)">Same OpenAPI spec given to every baseline model (1B–4.3B parameters,
        real sizes from <code>ollama show</code>), reasoning only, no execution — isolating what PenAgent's
        execution-and-verification loop actually buys over text-only inference.</p>
      <div class="xgraph-wrap" style="grid-template-columns:1fr 1fr">
        ${comparisonBarChart(rows, "f1_score", "F1 score")}
        ${comparisonBarChart(rows, "precision", "Precision (share of CONFIRMED findings that were real)")}
      </div>
      ${comparisonTableHtml(rows)}
      <div class="callout" style="margin-top:var(--space-4)">
        <b>${escapeHtml(best.label)} has the highest F1 score</b> (${pct(best.metrics.f1_score)}) of all ${rows.length}
        approaches compared, with ${pct(best.metrics.precision)} precision — every <code>CONFIRMED_VULNERABILITY</code>
        it reports passed a real HTTP request against a configured security predicate. The baseline models reason over
        the identical spec with no execution at all: their raw true-positive rate is sometimes competitive, but
        model size doesn't predict reliability — the largest baseline here (Qwen2, 4B) has the <i>lowest</i>
        precision of all six, well below the smallest (Gemma 3, 1B). Precision is what execution buys; that's
        the gap this chart measures, not a scanner feature race against Burp or ZAP.
      </div>
    </div>`;
}

async function renderBaselinesView() {
  const main = document.getElementById("main");
  let results;
  try {
    results = await fetchResults();
  } catch (err) {
    main.innerHTML = `<div class="empty-state"><h1>Could not load results</h1><p>${escapeHtml(err.message)}</p></div>`;
    return;
  }
  const targets = Object.keys(results.penagent);
  const cards = targets.map((t) => renderTargetCard(t, results)).join("");
  const comparisonSection = await renderComparisonSection();
  main.innerHTML = `
    <div class="view-header">
      <h1>Baselines &amp; Results</h1>
      <p class="muted">PenAgent (autonomous discovery vs. ground-truth-guided execution) against six local-model
        PentestGPT-style baselines (Ollama, 1B–4.3B parameters, prompt-only reasoning, no execution), on DVWS,
        SREBench-API and Juice Shop. "Autonomous" and "guided" are never the same number — see
        <code>docs/RESULTS.md</code> for the full methodology.</p>
    </div>
    ${comparisonSection}
    ${cards}
    <div class="callout">
      These are n=1 runs on real benchmark images, not averaged across repeated trials, and do not include
      Burp/ZAP scanner baselines. Treat this as a reproducible demonstration of the pipeline, not a
      statistically powered claim — see <code>docs/RESULTS.md</code> for the full caveats before citing these numbers.
    </div>
  `;
}

// ---------- Exploration view: full real-route run against Juice Shop / DVWS ----------

const EXPLORE_TARGET_LABELS = { "juice-shop": "Juice Shop", dvws: "DVWS" };
const STATUS_BUCKET = {
  protected: { label: "Protected (401/403)", icon: "&#10003;", colorVar: "--negative" },
  exposed: { label: "Exposed to anonymous (2xx)", icon: "&#9650;", colorVar: "--weak" },
  crash: { label: "Target crashed (5xx)", icon: "&#10007;", colorVar: "--error" },
  other: { label: "Other", colorVar: "--pending" },
};

async function fetchExplore() {
  if (state.exploreCache) return state.exploreCache;
  const response = await fetch("data/explore.json");
  state.exploreCache = response.ok ? await response.json() : {};
  return state.exploreCache;
}

function statusChartHtml(buckets, total) {
  const segs = Object.entries(buckets).filter(([, n]) => n > 0).map(([key, n]) => {
    const meta = STATUS_BUCKET[key];
    const pct = total ? (n / total) * 100 : 0;
    return `<div class="status-bar-seg" style="width:${pct}%;background:var(${meta.colorVar})" title="${escapeHtml(meta.label)}: ${n}">${pct >= 8 ? n : ""}</div>`;
  }).join("");
  const legend = Object.entries(buckets).filter(([, n]) => n > 0).map(([key, n]) => {
    const meta = STATUS_BUCKET[key];
    return `<span class="status-legend-item"><span class="status-legend-swatch" style="background:var(${meta.colorVar})">${meta.icon || ""}</span>${escapeHtml(meta.label)} — ${n}</span>`;
  }).join("");
  return `
    <div class="status-chart">
      <div class="status-chart-title">What ${total} real HTTP requests actually got back</div>
      <div class="status-bar-track">${segs}</div>
      <div class="status-legend">${legend}</div>
    </div>`;
}

function challengeCardHtml(data) {
  if (!data) return "";
  const items = data.solved.map((c) => `
    <div class="challenge-item">
      <span class="check">&#10003;</span>
      <span>${escapeHtml(c.name)}</span>
      <span class="difficulty-dots">${"&#9733;".repeat(c.difficulty || 1)}</span>
      <span class="cat">${escapeHtml(c.category)}</span>
    </div>`).join("");
  return `
    <div class="challenge-card">
      <div class="challenge-card-title">Juice Shop's own challenge tracker: ${data.total_solved} of ${data.total_challenges} solved —
        confirmed by the target itself (<code>GET /api/Challenges</code>), not PenAgent's own grading</div>
      <div class="challenge-list">${items}</div>
    </div>`;
}

function opStatusBucket(statusCode) {
  if (statusCode == null) return "other";
  if (statusCode === 401 || statusCode === 403) return "protected";
  if (statusCode >= 500) return "crash";
  if (statusCode < 300) return "exposed";
  return "other";
}

function opTableRowsHtml(outcomes) {
  return outcomes.map((o) => {
    const bucket = STATUS_BUCKET[opStatusBucket(o.status_code)];
    return `<tr class="clickable-row" data-op="${escapeHtml(o.op)}">
      <td class="mono">${escapeHtml(o.method)} ${escapeHtml(o.path)}</td>
      <td>${escapeHtml(o.category)}</td>
      <td>${escapeHtml(o.status)}</td>
      <td><span class="status-legend-swatch" style="background:var(${bucket.colorVar})"></span> ${escapeHtml(o.status_code ?? "—")}</td>
    </tr>`;
  }).join("");
}

function opOutcomeTableHtml(targetId, outcomes) {
  const rows = opTableRowsHtml(outcomes);
  const tableId = `opTable-${targetId}`;
  return `
    <details>
      <summary class="muted" style="cursor:pointer;font-size:12.5px;margin-bottom:8px">Full op-by-op table (${outcomes.length} requests) — click a row for detail, a column header to sort</summary>
      <div class="table-toolbar">
        <input type="text" class="table-filter" id="opFilter-${escapeHtml(targetId)}" placeholder="Filter by path, category or status…">
        <button class="btn btn-ghost btn-sm csv-download-btn" data-table-id="${tableId}" data-filename="penagent-${escapeHtml(targetId)}-exploration.csv">&#8681; CSV</button>
      </div>
      <div class="result-table-wrap">
        <table class="result-table" id="${tableId}" data-table-target="${escapeHtml(targetId)}">
          <thead><tr>
            <th data-sort="path" class="sortable">Operation</th>
            <th data-sort="category" class="sortable">Category</th>
            <th data-sort="status" class="sortable">Executor status</th>
            <th data-sort="status_code" class="sortable">HTTP code</th>
          </tr></thead>
          <tbody id="opTableBody-${escapeHtml(targetId)}">${rows}</tbody>
        </table>
      </div>
    </details>`;
}

function wireOpTableRowClicks(targetId) {
  document.querySelectorAll(`#opTableBody-${targetId} tr.clickable-row`).forEach((el) => {
    el.addEventListener("click", () => selectExploreOp(targetId, el.dataset.op));
  });
}

function sortOpTable(targetId, key) {
  const data = state.exploreCache[targetId];
  state.exploreSort = state.exploreSort || {};
  const current = state.exploreSort[targetId];
  const dir = current && current.key === key ? -current.dir : 1;
  state.exploreSort[targetId] = { key, dir };
  const sorted = data.op_outcomes.slice().sort((a, b) => {
    const av = a[key] ?? "", bv = b[key] ?? "";
    if (av < bv) return -dir;
    if (av > bv) return dir;
    return 0;
  });
  const tbody = document.getElementById(`opTableBody-${targetId}`);
  if (tbody) tbody.innerHTML = opTableRowsHtml(sorted);
  wireOpTableRowClicks(targetId);
  const filterInput = document.getElementById(`opFilter-${targetId}`);
  if (filterInput && filterInput.value) filterInput.dispatchEvent(new Event("input"));
  document.querySelectorAll(`table[data-table-target="${targetId}"] th[data-sort]`).forEach((th) => {
    th.classList.toggle("sort-active", th.dataset.sort === key);
    th.classList.toggle("sort-desc", th.dataset.sort === key && dir === -1);
  });
}

function methodChipsHtml(breakdown) {
  const order = ["GET", "POST", "PUT", "PATCH", "DELETE"];
  const keys = Object.keys(breakdown).sort((a, b) => order.indexOf(a) - order.indexOf(b));
  const chips = keys.map((m) => `<span class="method-chip">${escapeHtml(m)}<b>${breakdown[m]}</b></span>`).join("");
  return `<div class="method-chips">${chips}</div>`;
}

function categoryBarsHtml(breakdown) {
  const rows = Object.entries(breakdown).sort((a, b) => b[1].protected + b[1].exposed + b[1].crash - (a[1].protected + a[1].exposed + a[1].crash))
    .map(([category, buckets]) => {
      const total = buckets.protected + buckets.exposed + buckets.crash + buckets.other;
      const segs = Object.entries(buckets).filter(([, n]) => n > 0).map(([key, n]) => {
        const meta = STATUS_BUCKET[key];
        return `<div class="category-bar-seg" style="width:${(n / total) * 100}%;background:var(${meta.colorVar})" title="${escapeHtml(meta.label)}: ${n}"></div>`;
      }).join("");
      return `<div class="category-bar-row">
        <span>${escapeHtml(category)}</span>
        <div class="category-bar-track">${segs}</div>
        <span class="mono muted">${total}</span>
      </div>`;
    }).join("");
  return `
    <div class="explore-section-title">Status by resource area</div>
    <div class="category-bars">${rows}</div>`;
}

function layoutExploreGraphNodes(outcomes, width, height) {
  const cx = width / 2, cy = height / 2, r = Math.min(width, height) / 2 - 56;
  return outcomes.map((o, i) => {
    const angle = (i / outcomes.length) * 2 * Math.PI - Math.PI / 2;
    return { o, x: cx + r * Math.cos(angle), y: cy + r * Math.sin(angle), cx, cy };
  });
}

function exploreGraphHtml(targetId, outcomes, selectedOp) {
  const width = 480, height = 480;
  const positioned = layoutExploreGraphNodes(outcomes, width, height);
  const edges = positioned.map((p) => {
    const bucket = STATUS_BUCKET[opStatusBucket(p.o.status_code)];
    return `<line x1="${p.cx}" y1="${p.cy}" x2="${p.x}" y2="${p.y}" class="explore-edge" style="stroke:var(${bucket.colorVar});opacity:0.3"></line>`;
  }).join("");
  const nodes = positioned.map((p) => {
    const bucket = STATUS_BUCKET[opStatusBucket(p.o.status_code)];
    const selected = p.o.op === selectedOp;
    return `
      <g class="explore-node xgraph-node ${selected ? "node-selected" : ""}" data-op="${escapeHtml(p.o.op)}" transform="translate(${p.x},${p.y})">
        <circle r="${selected ? 12 : 8}" style="fill:var(${bucket.colorVar})"></circle>
        <title>${escapeHtml(p.o.method)} ${escapeHtml(p.o.path)} — HTTP ${p.o.status_code ?? "—"}</title>
      </g>`;
  }).join("");
  const legend = ["protected", "exposed", "crash"].map((key) => {
    const meta = STATUS_BUCKET[key];
    return `<span class="legend-item"><span class="legend-dot" style="background:var(${meta.colorVar})"></span>${escapeHtml(meta.label)}</span>`;
  }).join("");
  return `
    <div class="card explore-card" data-graph-target="${escapeHtml(targetId)}">
      <div class="card-title">Endpoint map — click any node</div>
      <svg viewBox="0 0 ${width} ${height}" class="explore-svg">
        ${edges}
        <circle cx="${width / 2}" cy="${height / 2}" r="30" class="explore-hub"></circle>
        <text x="${width / 2}" y="${height / 2 + 4}" text-anchor="middle" class="explore-hub-label">${escapeHtml(EXPLORE_TARGET_LABELS[targetId] || targetId)}</text>
        ${nodes}
      </svg>
      <div class="explore-legend">${legend}</div>
    </div>`;
}

function opDetailHtml(outcome, finding) {
  const bucket = STATUS_BUCKET[opStatusBucket(outcome.status_code)];
  const findingBlock = finding ? `
      <div class="op-detail-row">
        ${badge(finding.classification, finding.classification)}
        ${badge(finding.severity, "sev-" + finding.severity)}
        <span class="muted">CVSS ${finding.cvss_score} · <span class="mono">${escapeHtml(finding.cvss_vector)}</span></span>
      </div>
      <p class="op-detail-explain">${escapeHtml(finding.explanation)}</p>
      <div class="op-detail-remediation"><b>Remediation:</b> ${escapeHtml(finding.remediation)}</div>`
    : `<p class="op-detail-explain muted">${outcome.error ? escapeHtml(outcome.error)
        : "No STRONG/CONFIRMED finding on this op — either correctly protected, or PenAgent's classifier called it WEAK_SIGNAL (deliberately generic, non-curated expectations here give it no basis to confirm anything on its own)."}</p>`;
  return `
    <div class="op-detail-title">${escapeHtml(outcome.method)} ${escapeHtml(outcome.path)}</div>
    <div class="op-detail-row">
      ${badge(outcome.category, "neutral")}
      <span class="status-legend-item"><span class="status-legend-swatch" style="background:var(${bucket.colorVar})">${bucket.icon || ""}</span>${escapeHtml(bucket.label)}</span>
      <span class="muted">executor: <b>${escapeHtml(outcome.status)}</b></span>
      <span class="muted">HTTP <b>${escapeHtml(outcome.status_code ?? "—")}</b></span>
    </div>
    ${findingBlock}`;
}

function selectExploreOp(targetId, opId) {
  const data = state.exploreCache[targetId];
  const outcome = data.op_outcomes.find((o) => o.op === opId);
  if (!outcome) return;
  state.exploreSelected = state.exploreSelected || {};
  state.exploreSelected[targetId] = opId;
  const finding = (data.direct_findings || []).find((f) => (f.request_summary[0] || {}).op === opId);
  const panel = document.getElementById(`opDetail-${targetId}`);
  if (panel) panel.innerHTML = opDetailHtml(outcome, finding);
  document.querySelectorAll(`[data-graph-target="${targetId}"] .xgraph-node`).forEach((el) => {
    const isSelected = el.dataset.op === opId;
    el.classList.toggle("node-selected", isSelected);
    el.querySelector("circle").setAttribute("r", isSelected ? "12" : "8");
  });
  document.querySelectorAll(`table[data-table-target="${targetId}"] tr.clickable-row`).forEach((el) => {
    el.classList.toggle("row-selected", el.dataset.op === opId);
  });
}

function renderExploreTargetCard(targetId, data) {
  const total = data.op_outcomes.length;
  const directFindings = data.direct_findings || [];
  const autoFindings = data.autonomous_findings || [];
  const findingsHtml = directFindings.length
    ? directFindings.map(findingCard).join("")
    : '<p class="empty-tab">PenAgent\'s own classifier called every probe WEAK_SIGNAL here — deliberately generic, non-curated expectations (no "this exact field is the violation" hints), so it has no basis to confirm anything on its own. See the challenge tracker above for an independent signal.</p>';
  const selectedOp = (state.exploreSelected || {})[targetId];
  return `
    <div class="explore-target-card">
      <div class="explore-target-head">
        <h2>${escapeHtml(EXPLORE_TARGET_LABELS[targetId] || targetId)}</h2>
        <span class="muted">${data.ops_authorized} real routes authorized · ${data.direct_probes} executed directly · ${data.autonomous_probes} reached by zero-hint autonomous discovery</span>
      </div>
      <div class="stat-row">
        <div class="stat-tile"><div class="stat-value">${data.ops_authorized}</div><div class="stat-label">real routes authorized</div></div>
        <div class="stat-tile"><div class="stat-value">${data.direct_probes}</div><div class="stat-label">probes executed</div></div>
        <div class="stat-tile"><div class="stat-value">${directFindings.length}</div><div class="stat-label">STRONG/CONFIRMED findings</div></div>
        <div class="stat-tile"><div class="stat-value">${autoFindings.length}</div><div class="stat-label">found with zero hints (C1→C2→C3)</div></div>
      </div>
      ${statusChartHtml(data.status_buckets, total)}
      ${methodChipsHtml(data.method_breakdown)}
      ${categoryBarsHtml(data.category_breakdown)}
      <div class="xgraph-wrap">
        ${exploreGraphHtml(targetId, data.op_outcomes, selectedOp)}
        <div class="op-detail-panel" id="opDetail-${escapeHtml(targetId)}">
          ${selectedOp ? opDetailHtml(data.op_outcomes.find((o) => o.op === selectedOp), (directFindings).find((f) => (f.request_summary[0] || {}).op === selectedOp))
            : '<div class="op-detail-empty">Click a node in the map, or a row in the table below, to see the full request detail.</div>'}
        </div>
      </div>
      ${challengeCardHtml(data.current_solved)}
      <h3>Findings</h3>
      ${findingsHtml}
      ${opOutcomeTableHtml(targetId, data.op_outcomes)}
    </div>`;
}

function wireExploreClicks(targetId) {
  document.querySelectorAll(`[data-graph-target="${targetId}"] .xgraph-node`).forEach((el) => {
    el.addEventListener("click", () => selectExploreOp(targetId, el.dataset.op));
  });
  wireOpTableRowClicks(targetId);
  document.querySelectorAll(`table[data-table-target="${targetId}"] th[data-sort]`).forEach((th) => {
    th.addEventListener("click", () => sortOpTable(targetId, th.dataset.sort));
  });
  const filterInput = document.getElementById(`opFilter-${targetId}`);
  if (filterInput) {
    filterInput.addEventListener("input", () => {
      const q = filterInput.value.toLowerCase();
      document.querySelectorAll(`#opTableBody-${targetId} tr`).forEach((tr) => {
        tr.style.display = tr.textContent.toLowerCase().includes(q) ? "" : "none";
      });
    });
  }
}

async function renderExplorationView() {
  const main = document.getElementById("main");
  let explore;
  try {
    explore = await fetchExplore();
  } catch (err) {
    main.innerHTML = `<div class="empty-state"><h1>Could not load exploration data</h1><p>${escapeHtml(err.message)}</p></div>`;
    return;
  }
  const targets = Object.keys(explore);
  if (!targets.length) {
    main.innerHTML = `<div class="empty-state"><h1>No exploration run yet</h1>
      <p class="muted">Run <code>python -m demo.explore_run --output reports/explore</code>, then
      <code>python -m demo.export_ui_data</code>, to populate this view.</p></div>`;
    return;
  }
  main.innerHTML = `
    <div class="view-header">
      <h1>Exploration</h1>
      <p class="muted">PenAgent let loose on every real route each target actually exposes — not a curated
        benchmark subset, and nothing here is scored against hidden ground truth. "Direct run" means every
        authorized op was executed once with a plain, generic input (a guessed ID, a classic SQLi probe on
        login, an extra <code>role</code> field on registration) — standard first-pass pentest technique,
        not inside knowledge of the target. "Zero-hint autonomous" is real C1 spec ingestion → C2 hypothesis
        generation → C3 execution with no human-supplied input at all — the honest ceiling of unaided discovery
        today (see <code>docs/RESULTS.md</code>).</p>
    </div>
    ${targets.map((t) => renderExploreTargetCard(t, explore[t])).join("")}
  `;
  targets.forEach(wireExploreClicks);
}

// ---------- top-nav view switching & quickstart ----------

function emptyStateHtml() {
  return `
    <div class="empty-state">
      <h1>Welcome to the PenAgent Console</h1>
      <p>Connect to your running services on the left, then pick an audit to watch it work, or create a new one
         against <code>dvws</code>, <code>srebench-api</code> or <code>juice-shop</code> (if wired in — see
         <code>docs/WALKTHROUGH.md</code>) to watch the agent actually explore a real target.</p>
      <div class="quickstart">
        <button class="btn btn-primary quickstart-btn" data-target="dvws">Quick-start: explore DVWS</button>
        <button class="btn btn-primary quickstart-btn" data-target="juice-shop">Quick-start: explore Juice Shop</button>
      </div>
      <p class="muted">Or click <b>Exploration</b> above to see PenAgent let loose on every real route Juice Shop and
         DVWS expose, or <b>Baselines &amp; Results</b> for the scored evaluation against local LLM baselines.</p>
    </div>`;
}

function setView(view) {
  state.view = view;
  document.querySelectorAll(".topnav-btn").forEach((btn) => btn.classList.toggle("active", btn.dataset.view === view));
  const sidebar = document.getElementById("sidebar");
  if (view === "baselines") {
    sidebar.style.display = "none";
    void renderBaselinesView();
  } else if (view === "exploration") {
    sidebar.style.display = "none";
    void renderExplorationView();
  } else {
    sidebar.style.display = "";
    if (state.selected) void renderMain();
    else document.getElementById("main").innerHTML = emptyStateHtml();
  }
}

async function quickstart(targetId) {
  if (!state.cfg.c3 || !(await testConnection())) {
    toast("Connect to Executor (C3) and Report (C6) on the left first", "err");
    return;
  }
  const id = `${targetId}-quickstart-${Date.now().toString(36)}`;
  try {
    await c3("/v1/audits", { method: "POST", body: JSON.stringify({ audit_id: id, target_id: targetId, acknowledged_authorization: true }) });
    toast(`Audit "${id}" created against ${targetId}`, "ok");
    await refreshAuditList();
    selectAudit(id);
  } catch (err) {
    toast(`Could not start: ${err.message}`, "err");
  }
}

document.querySelectorAll(".topnav-btn").forEach((btn) => btn.addEventListener("click", () => setView(btn.dataset.view)));
document.getElementById("main").addEventListener("click", (ev) => {
  const quickstartBtn = ev.target.closest(".quickstart-btn");
  if (quickstartBtn) void quickstart(quickstartBtn.dataset.target);
  const csvBtn = ev.target.closest(".csv-download-btn");
  if (csvBtn) downloadTableCsv(csvBtn.dataset.tableId, csvBtn.dataset.filename);
});

function downloadTableCsv(tableId, filename) {
  const table = document.getElementById(tableId);
  if (!table) return;
  const csv = [...table.querySelectorAll("tr")].map((tr) =>
    [...tr.children].map((cell) => `"${cell.textContent.trim().replaceAll('"', '""')}"`).join(",")).join("\n");
  const blob = new Blob([csv], { type: "text/csv" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  a.click();
  setTimeout(() => URL.revokeObjectURL(url), 5000);
  toast(`Downloaded ${filename}`, "ok");
}

// ---------- wiring ----------

document.getElementById("connForm").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  saveConfig();
  if (await testConnection()) {
    await refreshAuditList();
  }
});
document.getElementById("refreshAudits").addEventListener("click", refreshAuditList);
document.getElementById("newAuditForm").addEventListener("submit", createAudit);

// ---------- theme toggle ----------

function applyTheme(theme) {
  document.documentElement.dataset.theme = theme;
  const btn = document.getElementById("themeToggle");
  if (btn) btn.textContent = theme === "dark" ? "☀" : "☾";
}

function loadTheme() {
  let saved = null;
  try { saved = localStorage.getItem("penagent-console-theme"); } catch { /* storage unavailable */ }
  applyTheme(saved || (window.matchMedia?.("(prefers-color-scheme: dark)").matches ? "dark" : "light"));
}

document.getElementById("themeToggle").addEventListener("click", () => {
  const next = document.documentElement.dataset.theme === "dark" ? "light" : "dark";
  applyTheme(next);
  try { localStorage.setItem("penagent-console-theme", next); } catch { /* storage unavailable; theme still applies for this session */ }
});

loadTheme();
loadConfig();
testConnection().then((ok) => { if (ok) refreshAuditList(); });
