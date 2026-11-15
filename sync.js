/* ============================================================
   sync.js — stores the encrypted vault file in a GitHub repo
   ------------------------------------------------------------
   Reads use the public raw file URL (the vault file is
   ciphertext, so public read access is safe).
   Writes use the GitHub Contents API with a fine-grained
   personal access token that the user enters once per device.
   The token stays in this browser's localStorage — it is never
   committed to the repo.
   ============================================================ */
import { SYNC, SYNC_ENABLED } from "./config.js";

const TOKEN_KEY = "vault-ledger:sync-token";

export function syncEnabled() {
  return SYNC_ENABLED;
}
export function getToken() {
  return localStorage.getItem(TOKEN_KEY);
}
export function setToken(token) {
  if (token) localStorage.setItem(TOKEN_KEY, token.trim());
  else localStorage.removeItem(TOKEN_KEY);
}
export function repoLabel() {
  return `${SYNC.owner}/${SYNC.repo}`;
}

export function vaultPath(vaultId) {
  return `vault/${vaultId}.json`;
}
export function aliasPath(aliasId) {
  return `vault/by-recovery/${aliasId}.json`;
}

/* ---------- read (public, no token needed) ---------- */
export async function fetchRemote(path) {
  const url = `https://raw.githubusercontent.com/${SYNC.owner}/${SYNC.repo}/${SYNC.branch}/${path}?t=${Date.now()}`;
  const res = await fetch(url);
  if (res.status === 404) return null;
  if (!res.ok) throw new Error(`fetch failed: ${res.status}`);
  return res.json();
}

/* ---------- write (token required) ---------- */
export async function putRemote(path, obj, message) {
  const token = getToken();
  if (!token) throw new Error("NO_TOKEN");

  const api = `https://api.github.com/repos/${SYNC.owner}/${SYNC.repo}/contents/${path}`;
  const headers = {
    Authorization: `Bearer ${token}`,
    Accept: "application/vnd.github+json",
    "X-GitHub-Api-Version": "2022-11-28",
  };

  // get the current file SHA (required to update an existing file)
  let sha;
  const head = await fetch(`${api}?ref=${SYNC.branch}&t=${Date.now()}`, { headers });
  if (head.ok) {
    sha = (await head.json()).sha;
  } else if (head.status !== 404) {
    throw new Error(`sha lookup failed: ${head.status}`);
  }

  const content = btoa(unescape(encodeURIComponent(JSON.stringify(obj))));
  const body = { message, content, branch: SYNC.branch };
  if (sha) body.sha = sha;

  const res = await fetch(api, { method: "PUT", headers, body: JSON.stringify(body) });
  if (!res.ok) throw new Error(`put failed: ${res.status}`);
}
