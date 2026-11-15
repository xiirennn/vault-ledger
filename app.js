/* ============================================================
   app.js — Vault Ledger UI logic (synced edition)
   ------------------------------------------------------------
   The password is the login: it derives the vault ID, which
   locates the encrypted vault file in the user's GitHub repo.
   The same password therefore opens the same vault on every
   device, and an existing password can never create a new
   vault — it always finds the one that exists.
   ============================================================ */
import {
  vaultIdForPassword, vaultIdForRecovery,
  buildVault, unwrapVault, encryptJSON, decryptJSON,
} from "./crypto.js";
import {
  syncEnabled, getToken, setToken, repoLabel,
  vaultPath, aliasPath, fetchRemote, putRemote,
} from "./sync.js";

/* ---------------- constants ---------------- */
const CATEGORIES = [
  { id: "food",          name: "FOOD",          color: "#34d399" },
  { id: "transport",     name: "TRANSPORT",     color: "#22d3ee" },
  { id: "housing",       name: "HOUSING",       color: "#6c85ec" },
  { id: "utilities",     name: "UTILITIES",     color: "#e879f9" },
  { id: "shopping",      name: "SHOPPING",      color: "#fbbf24" },
  { id: "health",        name: "HEALTH",        color: "#f87171" },
  { id: "entertainment", name: "ENTERTAINMENT", color: "#a3e635" },
  { id: "other",         name: "OTHER",         color: "#8b9bb8" },
];
const AUTO_LOCK_MS = 5 * 60 * 1000;
const MIN_NEW_PASSWORD = 10;

/* ---------------- state ---------------- */
let dek = null;            // CryptoKey while unlocked
let record = null;         // full vault record (ciphertext fields)
let data = null;           // decrypted { budget, currency, expenses: [] }
let vaultId = null;
let mode = "sync";         // "sync" | "readonly" | "offline" | "local"
let monthCursor = currentMonth();
let idleTimer = null;

function currentMonth() {
  const d = new Date();
  return `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, "0")}`;
}

const $ = (id) => document.getElementById(id);

function fmt(amount) {
  try {
    return new Intl.NumberFormat(undefined, {
      style: "currency", currency: data?.currency || "USD",
    }).format(amount);
  } catch {
    return `${(data?.currency || "USD")} ${amount.toFixed(2)}`;
  }
}
function uid() {
  return crypto.randomUUID ? crypto.randomUUID() : String(Date.now()) + Math.random().toString(16).slice(2);
}

/* ---------------- local cache (ciphertext only) ---------------- */
const cacheKey = (id) => `vl:cache:${id}`;
const aliasKey = (id) => `vl:alias:${id}`;
function cacheRecord() { localStorage.setItem(cacheKey(vaultId), JSON.stringify(record)); }
function readCache(id) {
  const raw = localStorage.getItem(cacheKey(id));
  return raw ? JSON.parse(raw) : null;
}

/* ============================================================
   LOCK SCREEN FLOWS
   ============================================================ */
const lockViews = ["view-unlock", "view-recovery", "view-setup", "view-reveal"];
function showLockView(id) {
  lockViews.forEach((v) => { $(v).hidden = v !== id; });
  $("lock-screen").style.display = "flex";
  $("app").hidden = true;
  const first = $(id).querySelector("input, button");
  if (first) first.focus();
}
function lockError(el, msg) {
  el.textContent = msg;
  el.hidden = false;
  const panel = el.closest(".lock-panel");
  panel.classList.remove("shake");
  void panel.offsetWidth;
  panel.classList.add("shake");
}

/* ---------- password login ---------- */
$("unlock-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const password = $("unlock-password").value;
  const btn = $("unlock-btn");
  btn.disabled = true;
  btn.textContent = "DECRYPTING…";
  try {
    await loginWithPassword(password);
  } finally {
    btn.disabled = false;
    btn.textContent = "OPEN VAULT";
    $("unlock-password").value = "";
  }
});

async function loginWithPassword(password) {
  const id = await vaultIdForPassword(password);
  let rec = null;

  if (syncEnabled()) {
    try {
      rec = await fetchRemote(vaultPath(id));
    } catch {
      rec = readCache(id); // network down → try local cache
      if (rec) return finishLogin(rec, id, password, "password", "offline");
      return lockError($("unlock-error"), "Can't reach GitHub and no cached vault on this device.");
    }
  } else {
    rec = readCache(id);
  }

  if (!rec) {
    // no vault for this password → this password may become a NEW vault
    if (password.length < MIN_NEW_PASSWORD) {
      return lockError($("unlock-error"), `No vault found. New vaults need at least ${MIN_NEW_PASSWORD} characters.`);
    }
    $("setup-password").value = password;
    $("setup-password2").value = "";
    $("setup-error").hidden = true;
    showLockView("view-setup");
    return;
  }

  // vault exists → the password must open it (never creates a second one)
  await finishLogin(rec, id, password, "password", syncEnabled() ? (getToken() ? "sync" : "readonly") : "local");
}

async function finishLogin(rec, id, secret, kind, loginMode) {
  const key = await unwrapVault(rec, secret, kind);
  if (!key) {
    const el = kind === "recovery" ? $("recovery-error") : $("unlock-error");
    return lockError(el, kind === "recovery" ? "Recovery key not recognized." : "Wrong password.");
  }
  dek = key;
  record = rec;
  vaultId = id;
  data = await decryptJSON(dek, record.data);
  mode = loginMode;
  cacheRecord();
  enterApp();
}

/* ---------- recovery-key login ---------- */
$("recovery-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const key = $("recovery-key").value;
  $("recovery-key").value = "";
  const aliasId = await vaultIdForRecovery(key);

  let alias = null;
  if (syncEnabled()) {
    try { alias = await fetchRemote(aliasPath(aliasId)); }
    catch {
      const cached = localStorage.getItem(aliasKey(aliasId));
      alias = cached ? JSON.parse(cached) : null;
      if (alias) {
        const rec = readCache(alias.vault);
        if (rec) return finishLogin(rec, alias.vault, key, "recovery", "offline");
      }
      return lockError($("recovery-error"), "Can't reach GitHub and no cached vault on this device.");
    }
  } else {
    const cached = localStorage.getItem(aliasKey(aliasId));
    alias = cached ? JSON.parse(cached) : null;
  }
  if (!alias) return lockError($("recovery-error"), "Recovery key not recognized.");

  let rec = null;
  if (syncEnabled()) {
    try { rec = await fetchRemote(vaultPath(alias.vault)); } catch { rec = readCache(alias.vault); }
  } else {
    rec = readCache(alias.vault);
  }
  if (!rec) return lockError($("recovery-error"), "Vault file not found.");

  localStorage.setItem(aliasKey(aliasId), JSON.stringify(alias));
  await finishLogin(rec, alias.vault, key, "recovery", syncEnabled() ? (getToken() ? "sync" : "readonly") : "local");
});

$("show-recovery").addEventListener("click", () => showLockView("view-recovery"));
$("back-to-password").addEventListener("click", () => showLockView("view-unlock"));
$("setup-back").addEventListener("click", () => showLockView("view-unlock"));

/* ---------- new vault setup ---------- */
$("setup-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const p1 = $("setup-password").value;
  const p2 = $("setup-password2").value;
  if (p1.length < MIN_NEW_PASSWORD) {
    return lockError($("setup-error"), `Password must be at least ${MIN_NEW_PASSWORD} characters.`);
  }
  if (p1 !== p2) {
    return lockError($("setup-error"), "Passwords do not match.");
  }
  $("setup-error").hidden = true;

  const initial = { budget: 0, currency: "USD", expenses: [] };
  const built = await buildVault(p1, initial);
  const id = await vaultIdForPassword(p1);

  dek = built.dek;
  record = built.record;
  vaultId = id;
  data = initial;

  // persist: remote if possible, cache always
  cacheRecord();
  const alias = { v: 1, vault: id };
  localStorage.setItem(aliasKey(built.aliasId), JSON.stringify(alias));
  if (syncEnabled() && getToken()) {
    mode = "sync";
    try {
      await putRemote(vaultPath(id), record, "Create vault");
      await putRemote(aliasPath(built.aliasId), alias, "Add recovery alias");
    } catch {
      mode = "readonly";
    }
  } else {
    mode = syncEnabled() ? "readonly" : "local";
  }

  $("recovery-display").textContent = built.recoveryKey;
  $("reveal-confirm").checked = false;
  $("reveal-done").disabled = true;
  showLockView("view-reveal");
});

$("copy-recovery").addEventListener("click", async () => {
  const text = $("recovery-display").textContent;
  try {
    await navigator.clipboard.writeText(text);
    $("copy-recovery").textContent = "COPIED";
    setTimeout(() => { $("copy-recovery").textContent = "COPY"; }, 1500);
  } catch {
    const range = document.createRange();
    range.selectNodeContents($("recovery-display"));
    const sel = getSelection();
    sel.removeAllRanges();
    sel.addRange(range);
  }
});

$("download-recovery").addEventListener("click", () => {
  const text = [
    "VAULT LEDGER — RECOVERY KEY",
    "Keep this file somewhere safe. Anyone with this key can decrypt your data.",
    "",
    $("recovery-display").textContent,
  ].join("\n");
  const blob = new Blob([text], { type: "text/plain" });
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = "vault-ledger-recovery-key.txt";
  a.click();
  URL.revokeObjectURL(a.href);
});

$("reveal-confirm").addEventListener("change", (e) => {
  $("reveal-done").disabled = !e.target.checked;
});
$("reveal-done").addEventListener("click", () => enterApp());

/* ============================================================
   APP
   ============================================================ */
function enterApp() {
  $("lock-screen").style.display = "none";
  $("app").hidden = false;
  monthCursor = currentMonth();
  fillCategorySelects();
  $("f-date").valueAsDate = new Date();
  applyMode();
  render();
  resetIdleTimer();
}

function applyMode() {
  const writable = mode === "sync" || mode === "local";
  // disable editing surfaces in read-only modes
  for (const el of $("add-form").querySelectorAll("input, select, button")) el.disabled = !writable;
  const led = $("sync-dot"), text = $("sync-text"), banner = $("sync-banner");
  const setLed = (cls, label) => {
    led.className = "led " + cls;
    text.textContent = label;
    $("sync-led").style.color = getComputedStyle(led).backgroundColor;
  };
  banner.hidden = true;

  if (mode === "sync") setLed("led-on", "SYNCED");
  else if (mode === "local") setLed("led-dim", "LOCAL MODE");
  else if (mode === "offline") {
    setLed("led-warn", "OFFLINE");
    banner.textContent = "OFFLINE — showing the cached vault from this device. Editing is disabled.";
    banner.hidden = false;
  } else { // readonly (sync configured, no token on this device)
    setLed("led-warn", "READ-ONLY");
    banner.textContent = "READ-ONLY — add your sync token in Settings to enable editing on this device.";
    banner.hidden = false;
  }
}

function lock() {
  dek = null; record = null; data = null; vaultId = null;
  clearTimeout(idleTimer);
  ["unlock-password", "recovery-key"].forEach((id) => { $(id).value = ""; });
  $("unlock-error").hidden = true;
  $("recovery-error").hidden = true;
  showLockView("view-unlock");
}
$("btn-lock").addEventListener("click", lock);

function resetIdleTimer() {
  clearTimeout(idleTimer);
  idleTimer = setTimeout(lock, AUTO_LOCK_MS);
}
["pointerdown", "keydown"].forEach((evt) =>
  document.addEventListener(evt, () => { if (dek) resetIdleTimer(); }, { passive: true })
);

/* ---------------- persistence ---------------- */
async function persist() {
  record.data = await encryptJSON(dek, data);
  cacheRecord();
  if (mode !== "sync") return;
  const led = $("sync-dot"), text = $("sync-text");
  led.className = "led led-warn";
  text.textContent = "SYNCING";
  try {
    await putRemote(vaultPath(vaultId), record, "Update vault");
    led.className = "led led-on";
    text.textContent = "SYNCED";
  } catch {
    led.className = "led led-err";
    text.textContent = "SYNC ERROR";
    const banner = $("sync-banner");
    banner.textContent = "SYNC ERROR — changes are cached on this device and will retry on your next save.";
    banner.hidden = false;
  }
}

/* ---------------- month filtering ---------------- */
function monthExpenses() {
  return data.expenses
    .filter((e) => e.date.startsWith(monthCursor))
    .sort((a, b) => (a.date < b.date ? 1 : a.date > b.date ? -1 : b.ts - a.ts));
}

/* ============================================================
   RENDER
   ============================================================ */
function render() {
  renderBudgetPanel();
  renderList();
  renderChart();
  renderPace();
}

function renderBudgetPanel() {
  const [y, m] = monthCursor.split("-").map(Number);
  $("month-label").textContent = new Date(y, m - 1, 1)
    .toLocaleDateString(undefined, { month: "short", year: "numeric" })
    .toUpperCase();

  const spent = monthExpenses().reduce((s, e) => s + e.amount, 0);
  const budget = data.budget || 0;
  const remaining = budget - spent;

  $("stat-spent").textContent = fmt(spent);
  $("stat-budget").textContent = fmt(budget);

  const remEl = $("stat-remaining");
  remEl.textContent = fmt(remaining);
  remEl.classList.toggle("over", remaining < 0);

  const fill = $("meter-fill");
  const caption = $("meter-caption");
  if (budget > 0) {
    const pct = (spent / budget) * 100;
    fill.style.width = `${Math.min(pct, 100)}%`;
    fill.className = "meter-fill" + (pct > 100 ? " over" : pct > 80 ? " warn" : "");
    $("meter").setAttribute("aria-valuenow", Math.round(Math.min(pct, 100)));
    caption.textContent = `${pct.toFixed(0)}% OF BUDGET USED`;
  } else {
    fill.style.width = "0%";
    fill.className = "meter-fill";
    caption.textContent = "SET A MONTHLY BUDGET IN SETTINGS";
  }
}

function renderList() {
  const list = $("expense-list");
  const items = monthExpenses();
  const writable = mode === "sync" || mode === "local";
  list.innerHTML = "";
  $("expense-count").textContent = String(items.length);
  $("expense-empty").hidden = items.length > 0;

  for (const e of items) {
    const cat = CATEGORIES.find((c) => c.id === e.category) || CATEGORIES.at(-1);
    const li = document.createElement("li");
    li.className = "expense-item";
    li.dataset.id = e.id;

    const catEl = document.createElement("span");
    catEl.className = "exp-cat";
    const dot = document.createElement("i");
    dot.style.background = cat.color;
    dot.style.color = cat.color;
    catEl.append(dot, document.createTextNode(cat.name));

    const main = document.createElement("div");
    main.className = "exp-main";
    const note = document.createElement("div");
    note.className = "exp-note";
    note.textContent = e.note || cat.name.charAt(0) + cat.name.slice(1).toLowerCase();
    const date = document.createElement("div");
    date.className = "exp-date";
    date.textContent = e.date;
    main.append(note, date);

    const amt = document.createElement("span");
    amt.className = "exp-amount";
    amt.textContent = fmt(e.amount);

    const actions = document.createElement("div");
    actions.className = "exp-actions";

    const editBtn = document.createElement("button");
    editBtn.type = "button";
    editBtn.className = "icon-btn";
    editBtn.disabled = !writable;
    editBtn.setAttribute("aria-label", `Edit ${note.textContent}`);
    editBtn.innerHTML = `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M17 3a2.83 2.83 0 1 1 4 4L7.5 20.5 2 22l1.5-5.5L17 3z"/></svg>`;
    editBtn.addEventListener("click", () => openEdit(e.id));

    const delBtn = document.createElement("button");
    delBtn.type = "button";
    delBtn.className = "icon-btn danger";
    delBtn.disabled = !writable;
    delBtn.setAttribute("aria-label", `Delete ${note.textContent}`);
    delBtn.innerHTML = `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M3 6h18M8 6V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2m3 0v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6"/></svg>`;
    let armed = false, disarm;
    delBtn.addEventListener("click", async () => {
      if (!armed) {
        armed = true;
        delBtn.classList.add("confirm");
        delBtn.setAttribute("aria-label", "Tap again to confirm delete");
        disarm = setTimeout(() => { armed = false; delBtn.classList.remove("confirm"); }, 3000);
        return;
      }
      clearTimeout(disarm);
      await deleteExpense(e.id);
    });

    actions.append(editBtn, delBtn);
    li.append(catEl, main, amt, actions);
    list.append(li);
  }
}

/* ---------------- donut chart ---------------- */
function polar(cx, cy, r, angleDeg) {
  const a = ((angleDeg - 90) * Math.PI) / 180;
  return [cx + r * Math.cos(a), cy + r * Math.sin(a)];
}
function donutSegment(cx, cy, rOuter, rInner, start, end) {
  const [x1, y1] = polar(cx, cy, rOuter, start);
  const [x2, y2] = polar(cx, cy, rOuter, end);
  const [x3, y3] = polar(cx, cy, rInner, end);
  const [x4, y4] = polar(cx, cy, rInner, start);
  const large = end - start > 180 ? 1 : 0;
  return [
    `M ${x1} ${y1}`,
    `A ${rOuter} ${rOuter} 0 ${large} 1 ${x2} ${y2}`,
    `L ${x3} ${y3}`,
    `A ${rInner} ${rInner} 0 ${large} 0 ${x4} ${y4}`,
    "Z",
  ].join(" ");
}

function renderChart() {
  const svg = $("donut");
  const legend = $("legend");
  svg.innerHTML = "";
  legend.innerHTML = "";

  const totals = new Map();
  for (const e of monthExpenses()) totals.set(e.category, (totals.get(e.category) || 0) + e.amount);
  const total = [...totals.values()].reduce((s, v) => s + v, 0);

  $("chart-empty").hidden = total > 0;
  $("donut-total").textContent = fmt(total);
  if (total <= 0) return;

  const rows = [...totals.entries()]
    .map(([id, amount]) => ({ cat: CATEGORIES.find((c) => c.id === id) || CATEGORIES.at(-1), amount }))
    .sort((a, b) => b.amount - a.amount);

  const GAP = 1.5;
  let angle = 0;
  const paths = [];
  for (const { cat, amount } of rows) {
    const span = (amount / total) * 360;
    const path = document.createElementNS("http://www.w3.org/2000/svg", "path");
    if (rows.length === 1) {
      path.setAttribute("d", donutSegment(100, 100, 92, 62, 0, 359.99));
    } else {
      path.setAttribute("d", donutSegment(100, 100, 92, 62, angle + GAP / 2, angle + span - GAP / 2));
    }
    path.setAttribute("fill", cat.color);
    path.dataset.cat = cat.id;
    const title = document.createElementNS("http://www.w3.org/2000/svg", "title");
    title.textContent = `${cat.name}: ${fmt(amount)}`;
    path.append(title);
    svg.append(path);
    paths.push(path);
    angle += span;
  }

  for (const { cat, amount } of rows) {
    const li = document.createElement("li");
    li.dataset.cat = cat.id;
    const dot = document.createElement("i");
    dot.style.background = cat.color;
    dot.style.color = cat.color;
    const name = document.createElement("span");
    name.className = "lg-name";
    name.textContent = cat.name;
    const amt = document.createElement("span");
    amt.className = "lg-amt";
    amt.textContent = fmt(amount);
    const pct = document.createElement("span");
    pct.className = "lg-pct";
    pct.textContent = `${((amount / total) * 100).toFixed(0)}%`;
    li.append(dot, name, amt, pct);
    legend.append(li);
  }

  function highlight(catId) {
    svg.classList.toggle("dim", !!catId);
    for (const p of paths) p.classList.toggle("active", p.dataset.cat === catId);
    for (const li of legend.children) li.classList.toggle("dimmed", !!catId && li.dataset.cat !== catId);
  }
  for (const li of legend.children) {
    li.addEventListener("pointerenter", () => highlight(li.dataset.cat));
    li.addEventListener("pointerleave", () => highlight(null));
    li.addEventListener("click", () => highlight(li.dataset.cat));
  }
  for (const p of paths) {
    p.addEventListener("pointerenter", () => highlight(p.dataset.cat));
    p.addEventListener("pointerleave", () => highlight(null));
  }
}

/* ---------------- daily pace chart ---------------- */
function renderPace() {
  const wrap = $("pace-chart");
  wrap.innerHTML = "";
  const [y, m] = monthCursor.split("-").map(Number);
  const days = new Date(y, m, 0).getDate();
  const byDay = new Array(days).fill(0);
  for (const e of monthExpenses()) byDay[Number(e.date.slice(8, 10)) - 1] += e.amount;
  const max = Math.max(...byDay, 0);
  const today = new Date();
  const isCurrent = monthCursor === currentMonth();

  byDay.forEach((v, i) => {
    const bar = document.createElement("div");
    bar.className = "pace-bar" + (v > 0 ? " has" : "") + (isCurrent && i + 1 === today.getDate() ? " today" : "");
    bar.style.height = `${v > 0 ? Math.max((v / max) * 100, 8) : 6}%`;
    bar.title = `${monthCursor}-${String(i + 1).padStart(2, "0")}: ${fmt(v)}`;
    wrap.append(bar);
  });
}

/* ============================================================
   CRUD
   ============================================================ */
function fillCategorySelects() {
  for (const id of ["f-category", "e-category"]) {
    const sel = $(id);
    sel.innerHTML = "";
    for (const c of CATEGORIES) {
      const opt = document.createElement("option");
      opt.value = c.id;
      opt.textContent = c.name;
      sel.append(opt);
    }
  }
}

$("add-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const amount = parseFloat($("f-amount").value);
  if (!Number.isFinite(amount) || amount <= 0) return;
  const entry = {
    id: uid(),
    amount: Math.round(amount * 100) / 100,
    category: $("f-category").value,
    date: $("f-date").value,
    note: $("f-note").value.trim(),
    ts: Date.now(),
  };
  data.expenses.push(entry);
  // clear + re-render before the async save so rapid consecutive
  // entries can never be wiped by a slow sync
  monthCursor = entry.date.slice(0, 7);
  $("f-amount").value = "";
  $("f-note").value = "";
  $("f-amount").focus();
  render();
  await persist();
});

async function deleteExpense(id) {
  data.expenses = data.expenses.filter((e) => e.id !== id);
  await persist();
  render();
}

function openEdit(id) {
  const e = data.expenses.find((x) => x.id === id);
  if (!e) return;
  $("e-id").value = e.id;
  $("e-amount").value = e.amount;
  $("e-category").value = e.category;
  $("e-date").value = e.date;
  $("e-note").value = e.note || "";
  $("edit-dialog").showModal();
  $("e-amount").focus();
}

$("edit-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const item = data.expenses.find((x) => x.id === $("e-id").value);
  if (!item) return;
  const amount = parseFloat($("e-amount").value);
  if (!Number.isFinite(amount) || amount <= 0) return;
  item.amount = Math.round(amount * 100) / 100;
  item.category = $("e-category").value;
  item.date = $("e-date").value;
  item.note = $("e-note").value.trim();
  await persist();
  $("edit-dialog").close();
  monthCursor = item.date.slice(0, 7);
  render();
});
$("edit-close").addEventListener("click", () => $("edit-dialog").close());

/* ---------------- month navigation ---------------- */
$("month-prev").addEventListener("click", () => { shiftMonth(-1); });
$("month-next").addEventListener("click", () => { shiftMonth(1); });
function shiftMonth(delta) {
  const [y, m] = monthCursor.split("-").map(Number);
  const d = new Date(y, m - 1 + delta, 1);
  monthCursor = `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, "0")}`;
  render();
}

/* ---------------- settings ---------------- */
$("btn-settings").addEventListener("click", () => {
  $("s-budget").value = data.budget || "";
  $("s-currency").value = data.currency || "USD";
  $("s-token").value = getToken() || "";
  $("sync-repo-label").textContent = syncEnabled()
    ? `Vault file: ${repoLabel()} (encrypted, publicly visible but unreadable).`
    : "Sync is not configured in src/config.js — running in local mode.";
  $("settings-dialog").showModal();
  $("s-budget").focus();
});
$("settings-close").addEventListener("click", () => $("settings-dialog").close());
$("settings-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const b = parseFloat($("s-budget").value);
  data.budget = Number.isFinite(b) && b >= 0 ? Math.round(b * 100) / 100 : 0;
  data.currency = $("s-currency").value;
  await persist();
  $("settings-dialog").close();
  render();
});

/* ---------------- sync token ---------------- */
$("token-save").addEventListener("click", async () => {
  const t = $("s-token").value.trim();
  if (!t) return;
  setToken(t);
  if (mode === "readonly") {
    mode = "sync";
    applyMode();
    render();
    await persist(); // push any cached changes
  }
  $("token-save").textContent = "SAVED";
  setTimeout(() => { $("token-save").textContent = "SAVE TOKEN"; }, 1500);
});
$("token-clear").addEventListener("click", () => {
  setToken(null);
  $("s-token").value = "";
  if (mode === "sync") {
    mode = "readonly";
    applyMode();
    render();
  }
});

/* close dialogs on backdrop click */
for (const dlg of document.querySelectorAll("dialog")) {
  dlg.addEventListener("click", (e) => {
    if (e.target === dlg) dlg.close();
  });
}

/* ---------------- boot ---------------- */
showLockView("view-unlock");
