"use strict";

// When served by the backend (http://127.0.0.1:8000/ui/) use same-origin requests.
// When opened from another server (e.g. VS Code Live Server) call the backend directly.
const API_BASE = window.API_BASE || (location.port === "8000" ? "" : "http://127.0.0.1:8000");

const $ = (id) => document.getElementById(id);
const state = { baseline: null, busy: false };
const ACTION_BUTTONS = ["btn-analyze", "btn-explain", "btn-recommend", "btn-rescan", "btn-assistant",
  "load-safe", "load-vulnerable"];

// ---------------------------------------------------------------- DOM helpers (textContent only: no XSS)
function el(tag, opts = {}, children = []) {
  const node = document.createElement(tag);
  if (opts.cls) node.className = opts.cls;
  if (opts.text !== undefined) node.textContent = opts.text;
  for (const child of [].concat(children)) if (child) node.append(child);
  return node;
}
const sevClass = (s) => "sev-" + String(s).toLowerCase();
const badge = (s) => el("span", { cls: "badge " + sevClass(s), text: s });
function clear(node) { node.replaceChildren(); return node; }

function showError(message) { $("error-text").textContent = message; $("error-banner").hidden = false; }
function hideError() { $("error-banner").hidden = true; }

function setBusy(busy, label) {
  state.busy = busy;
  $("loading").hidden = !busy;
  if (label) $("loading-text").textContent = label;
  ACTION_BUTTONS.forEach((id) => { $(id).disabled = busy; });
}

async function api(path, method = "GET", body = null) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 180000);
  let res;
  try {
    res = await fetch(API_BASE + path, {
      method,
      headers: body ? { "Content-Type": "application/json" } : {},
      body: body ? JSON.stringify(body) : undefined,
      signal: controller.signal,
    });
  } catch (err) {
    throw new Error(err.name === "AbortError" ? "The request timed out."
      : "Cannot reach the backend. Make sure it is running on http://127.0.0.1:8000.");
  } finally { clearTimeout(timer); }
  let data = null;
  try { data = await res.json(); } catch (_) { /* non-JSON body */ }
  if (!res.ok) {
    const msg = data && data.error && data.error.message ? data.error.message : `Request failed (HTTP ${res.status}).`;
    throw new Error(msg);
  }
  return data;
}

async function run(label, task) {
  hideError();
  setBusy(true, label);
  try { await task(); } catch (err) { showError(err.message || String(err)); } finally { setBusy(false); }
}

// ---------------------------------------------------------------- tabs
function showTab(name) {
  document.querySelectorAll(".tab").forEach((t) => {
    const active = t.dataset.tab === name;
    t.classList.toggle("active", active);
    t.setAttribute("aria-selected", String(active));
  });
  document.querySelectorAll(".panel").forEach((p) => { p.hidden = p.id !== "panel-" + name; });
}

// ---------------------------------------------------------------- renderers
function renderSummary(summary) {
  const wrap = el("div", { cls: "summary" });
  const overall = summary.overall_risk;
  wrap.append(el("strong", { text: "Overall risk:" }),
    el("span", { cls: "badge " + (overall === "None detected" ? "sev-none" : sevClass(overall)), text: overall }));
  ["Critical", "High", "Medium", "Low"].forEach((lvl) => {
    wrap.append(el("span", { cls: "meta", text: `${lvl}: ${summary.counts[lvl] || 0}` }));
  });
  return wrap;
}

function renderFinding(f) {
  const where = f.line ? `line ${f.line}` : "line n/a";
  const item = el("div", { cls: "item " + sevClass(f.severity) });
  item.append(
    el("h3", {}, [badge(f.severity), " " + f.name]),
    el("div", { cls: "meta", text: `${where} · ${f.rule_id}${f.cwe ? " · " + f.cwe : ""}` }),
  );
  if (f.snippet) item.append(el("pre", { text: f.snippet }));
  if (f.explanation) item.append(el("p", {}, [el("strong", { text: "Why it matters: " }), f.explanation]));
  if (f.mitigation) item.append(el("p", {}, [el("strong", { text: "Mitigation: " }), f.mitigation]));
  return item;
}

function renderFindingsList(findings, container) {
  if (!findings.length) container.append(el("p", { cls: "empty", text: "No known insecure patterns were detected." }));
  findings.forEach((f) => container.append(renderFinding(f)));
}

function renderNotes(notes, container) {
  (notes || []).forEach((n) => container.append(el("p", { cls: "note", text: n })));
}

function renderAnalyze(data) {
  const panel = clear($("panel-findings"));
  panel.append(renderSummary(data.summary));
  renderNotes(data.notes, panel);
  renderFindingsList(data.findings, panel);
  panel.append(el("p", { cls: "note", text: data.limitations }));
}

function renderAIBox(ai, container) {
  const box = el("div", { cls: "item sev-low" });
  box.append(el("h3", { text: "AI explanation (local model)" }));
  if (ai.status === "ok") {
    box.append(el("pre", { text: ai.text }), el("p", { cls: "meta", text: "Unverified AI output." }));
  } else {
    box.append(el("p", { cls: "status-warn", text: ai.message || "AI is not available." }));
  }
  container.append(box);
}

function renderExplain(data) {
  const panel = clear($("panel-explain"));
  panel.append(renderSummary(data.summary), el("p", { text: data.static_explanation }));
  renderAIBox(data.ai, panel);
}

function renderRecommend(data) {
  const panel = clear($("panel-recommend"));
  panel.append(el("p", { cls: "note", text: data.notice }));
  if (!data.recommendations.length) panel.append(el("p", { cls: "empty", text: "Nothing to recommend: no findings." }));
  data.recommendations.forEach((r) => {
    const item = el("div", { cls: "item sev-low" });
    item.append(el("h3", {}, [r.title, el("span", { cls: "meta", text: `  ·  ${r.line ? "line " + r.line : "line n/a"}  ·  SUGGESTION (not verified)` })]));
    item.append(el("p", { text: r.advice }));
    if (r.suggested_line) item.append(el("div", { cls: "meta", text: "Suggested replacement for the flagged line:" }), el("pre", { text: r.suggested_line }));
    if (r.example_code) item.append(el("div", { cls: "meta", text: "Example:" }), el("pre", { text: r.example_code }));
    panel.append(item);
  });
  if (data.ai && data.ai.status !== "ok") panel.append(el("p", { cls: "status-warn", text: data.ai.message }));
  if (data.ai_suggestion) {
    const s = data.ai_suggestion;
    const box = el("div", { cls: "item sev-medium" });
    box.append(el("h3", { text: "AI suggestion (unverified)" }), el("pre", { text: s.text }), el("p", { cls: "note", text: s.note }));
    if (s.extracted_code_summary) {
      box.append(el("p", { text: `Static scan of the suggested code: ${s.extracted_code_summary.total} finding(s), overall risk ${s.extracted_code_summary.overall_risk}.` }));
    }
    panel.append(box);
  }
}

function renderRescan(data) {
  const panel = clear($("panel-rescan"));
  panel.append(el("p", {}, [el("strong", { text: "Before: " }), `${data.original_summary.total} finding(s), ${data.original_summary.overall_risk}   `,
    el("strong", { text: "After: " }), `${data.modified_summary.total} finding(s), ${data.modified_summary.overall_risk}`]));
  if (!data.modified_code_parses) panel.append(el("p", { cls: "status-bad", text: "The modified code is not valid Python, so no fix can be verified." }));
  panel.append(el("p", {}, [el("strong", { text: `Verified fixes: ${data.verified_count} of ${data.results.length}` })]));
  data.results.forEach((r) => {
    const label = r.status === "remains" ? ["Still present", "status-bad"] : r.verified ? ["Resolved & verified", "status-ok"] : ["Resolved, not verified", "status-warn"];
    const item = el("div", { cls: "item " + sevClass(r.severity) });
    item.append(el("h3", {}, [badge(r.severity), " " + r.name]),
      el("div", { cls: "meta", text: r.line ? `original line ${r.line}` : "" }),
      el("p", {}, [el("span", { cls: label[1], text: label[0] }), " — " + r.detail]));
    panel.append(item);
  });
  if (data.new_findings.length) {
    panel.append(el("h3", { text: "New findings in modified code" }));
    data.new_findings.forEach((f) => panel.append(renderFinding(f)));
  }
  renderNotes(data.notes, panel);
  panel.append(el("p", { cls: "note", text: data.verification_note }));
  const again = el("button", { text: "Use current code as new baseline" });
  again.addEventListener("click", () => { setBaseline($("code-input").value); });
  panel.append(again);
}

function setBaseline(code) {
  state.baseline = code;
  $("baseline-hint").textContent = "Baseline set. Edit the code above, then click Re-scan to compare against it.";
}

// ---------------------------------------------------------------- actions
const currentCode = () => $("code-input").value;
const currentLanguage = () => $("language").value;

function requireCode() {
  if (!currentCode().trim()) { showError("Please enter some code first."); return false; }
  return true;
}

$("btn-analyze").addEventListener("click", () => {
  if (!requireCode()) return;
  run("Analyzing code…", async () => {
    const code = currentCode();
    renderAnalyze(await api("/api/analyze", "POST", { code, language: currentLanguage() }));
    setBaseline(code);
    showTab("findings");
  });
});

$("btn-explain").addEventListener("click", () => {
  if (!requireCode()) return;
  run("Explaining code (local AI can take a while)…", async () => {
    renderExplain(await api("/api/explain", "POST", { code: currentCode(), language: currentLanguage() }));
    showTab("explain");
  });
});

$("btn-recommend").addEventListener("click", () => {
  if (!requireCode()) return;
  run("Preparing recommendations…", async () => {
    renderRecommend(await api("/api/recommend", "POST", { code: currentCode(), language: currentLanguage(), use_ai: false }));
    showTab("recommend");
  });
});

$("btn-rescan").addEventListener("click", () => {
  if (!requireCode()) return;
  if (state.baseline === null) { showError("Run Analyze Code first so there is a baseline to compare against."); return; }
  run("Re-scanning…", async () => {
    renderRescan(await api("/api/rescan", "POST", {
      original_code: state.baseline, modified_code: currentCode(), language: currentLanguage() }));
    showTab("rescan");
  });
});

$("btn-assistant").addEventListener("click", () => {
  const operation = $("assistant-op").value;
  const prompt = $("assistant-prompt").value.trim();
  const body = { operation, language: currentLanguage() };
  if (["explain", "debug", "improve"].includes(operation)) {
    if (!requireCode()) return;
    body.code = currentCode();
    if (prompt) body.prompt = prompt;
  } else {
    if (!prompt) { showError("Please enter a prompt for this operation."); return; }
    body.prompt = prompt;
    if (currentCode().trim() && operation !== "question") body.code = currentCode();
  }
  run("Asking the local AI model…", async () => {
    const data = await api("/api/assistant", "POST", body);
    const out = clear($("assistant-output"));
    out.append(el("pre", { text: data.ai.text }));
    if (data.generated_code_findings.length) {
      out.append(el("p", { cls: "status-warn", text: `Static scan of the generated code found ${data.generated_code_findings.length} potential issue(s):` }));
      data.generated_code_findings.forEach((f) => out.append(renderFinding(f)));
    }
    out.append(el("p", { cls: "note", text: data.notice }));
  });
});

async function loadSample(name) {
  await run("Loading sample…", async () => {
    const data = await api("/api/samples/" + name);
    $("code-input").value = data.code;
    state.baseline = null;
    $("baseline-hint").textContent = "Sample loaded. Click Analyze Code to scan it.";
  });
}
$("load-safe").addEventListener("click", () => loadSample("safe"));
$("load-vulnerable").addEventListener("click", () => loadSample("vulnerable"));

document.querySelectorAll(".tab").forEach((t) => t.addEventListener("click", () => showTab(t.dataset.tab)));
$("error-close").addEventListener("click", hideError);

// Tab key inserts spaces inside the editor instead of leaving the field.
$("code-input").addEventListener("keydown", (e) => {
  if (e.key !== "Tab" || e.shiftKey) return;
  e.preventDefault();
  const ta = e.target, s = ta.selectionStart;
  ta.value = ta.value.slice(0, s) + "    " + ta.value.slice(ta.selectionEnd);
  ta.selectionStart = ta.selectionEnd = s + 4;
});

// ---------------------------------------------------------------- status pills
async function refreshStatus() {
  const apiPill = $("api-status"), aiPill = $("ai-status");
  try {
    const h = await api("/health?check_ai=true");
    apiPill.textContent = "API: online"; apiPill.className = "pill good";
    if (!h.ai.enabled) { aiPill.textContent = "AI: disabled"; aiPill.className = "pill"; }
    else if (h.ai.available) { aiPill.textContent = `AI: ready (${h.ai.model})`; aiPill.className = "pill good"; }
    else { aiPill.textContent = "AI: model offline (scanning still works)"; aiPill.className = "pill bad"; }
  } catch (err) {
    apiPill.textContent = "API: offline"; apiPill.className = "pill bad";
    aiPill.textContent = "AI: unknown"; aiPill.className = "pill";
    showError(err.message);
  }
}
refreshStatus();
