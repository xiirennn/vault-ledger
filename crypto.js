/* ============================================================
   crypto.js — vault encryption built on Web Crypto API
   ------------------------------------------------------------
   Scheme:
   · A random 256-bit AES-GCM data key (DEK) encrypts the data.
   · The DEK is wrapped (encrypted) twice: once with a key
     derived from the password, once with a key derived from the
     recovery key. Either secret can unwrap it.
   · The vault ID is derived from the password too, so the same
     password always finds the same vault file — on any device.
     An existing password can never create a second vault.
   · Key derivation: PBKDF2-SHA256 (600k iterations for the ID,
     310k for the key-encryption keys).
   · Only salts, IVs and ciphertext are ever stored or synced.
   ============================================================ */

const te = new TextEncoder();
const td = new TextDecoder();

const ID_ITERATIONS = 600_000;
const KEK_ITERATIONS = 310_000;
const ID_SALT = "vault-ledger/id/v1";

/* ---------- base64 helpers ---------- */
export function b64encode(buf) {
  const bytes = new Uint8Array(buf);
  let s = "";
  for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
  return btoa(s);
}
export function b64decode(b64) {
  const s = atob(b64);
  const bytes = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) bytes[i] = s.charCodeAt(i);
  return bytes;
}

/* ---------- vault ID (the "account locator") ---------- */
async function pbkdf2Bits(secret, salt, iterations) {
  const base = await crypto.subtle.importKey("raw", te.encode(secret), "PBKDF2", false, ["deriveBits", "deriveKey"]);
  return crypto.subtle.deriveBits(
    { name: "PBKDF2", salt: te.encode(salt), iterations, hash: "SHA-256" },
    base, 256
  );
}

function toHex(buf) {
  return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

/** Deterministic ID for a password — finds the vault file on any device. */
export async function vaultIdForPassword(password) {
  return toHex(await pbkdf2Bits(password, ID_SALT, ID_ITERATIONS));
}

/** Deterministic ID for a recovery key — finds the alias file. */
export async function vaultIdForRecovery(recoveryKey) {
  return toHex(await pbkdf2Bits("recovery:" + normalizeRecoveryKey(recoveryKey), ID_SALT, ID_ITERATIONS));
}

/* ---------- key derivation ---------- */
async function deriveKEK(secret, saltBytes) {
  const base = await crypto.subtle.importKey("raw", te.encode(secret), "PBKDF2", false, ["deriveKey"]);
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", salt: saltBytes, iterations: KEK_ITERATIONS, hash: "SHA-256" },
    base,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}

/* ---------- wrap / unwrap the data key ---------- */
async function wrapDEK(dekRaw, secret) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const kek = await deriveKEK(secret, salt);
  const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, kek, dekRaw);
  return { salt: b64encode(salt), iv: b64encode(iv), ct: b64encode(ct) };
}

async function unwrapDEK(slot, secret) {
  const kek = await deriveKEK(secret, b64decode(slot.salt));
  return crypto.subtle.decrypt(
    { name: "AES-GCM", iv: b64decode(slot.iv) },
    kek,
    b64decode(slot.ct)
  );
}

/* ---------- recovery key ---------- */
export function generateRecoveryKey() {
  const bytes = crypto.getRandomValues(new Uint8Array(16)); // 128 bits
  const hex = [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");
  return hex.match(/.{4}/g).join("-"); // xxxx-xxxx-… (8 groups)
}
export function normalizeRecoveryKey(input) {
  return input.trim().toLowerCase().replace(/[^0-9a-f]/g, "");
}

/* ---------- data encryption ---------- */
export async function encryptJSON(dek, obj) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, dek, te.encode(JSON.stringify(obj)));
  return { iv: b64encode(iv), ct: b64encode(ct) };
}

export async function decryptJSON(dek, payload) {
  const pt = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: b64decode(payload.iv) },
    dek,
    b64decode(payload.ct)
  );
  return JSON.parse(td.decode(pt));
}

/* ---------- vault API ---------- */

/**
 * Build a brand-new vault record. Returns { record, aliasId, recoveryKey, dek }.
 * Nothing is persisted here — the caller decides where records live.
 */
export async function buildVault(password, initialData) {
  const dek = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, true, ["encrypt", "decrypt"]);
  const dekRaw = await crypto.subtle.exportKey("raw", dek);

  const recoveryKey = generateRecoveryKey();
  const record = {
    v: 2,
    pw: await wrapDEK(dekRaw, password),
    rk: await wrapDEK(dekRaw, normalizeRecoveryKey(recoveryKey)),
    check: await encryptJSON(dek, { ok: "vault-ledger" }),
    data: await encryptJSON(dek, initialData),
  };
  const aliasId = await vaultIdForRecovery(recoveryKey);
  return { record, aliasId, recoveryKey, dek };
}

/**
 * Try to unwrap a vault record with a secret.
 * `kind` is "password" or "recovery". Returns DEK or null.
 */
export async function unwrapVault(record, secret, kind) {
  try {
    const normalized = kind === "recovery" ? normalizeRecoveryKey(secret) : secret;
    const slot = kind === "recovery" ? record.rk : record.pw;
    const dekRaw = await unwrapDEK(slot, normalized);
    const dek = await crypto.subtle.importKey("raw", dekRaw, { name: "AES-GCM" }, false, ["encrypt", "decrypt"]);
    const check = await decryptJSON(dek, record.check);
    if (!check || check.ok !== "vault-ledger") return null;
    return dek;
  } catch {
    return null;
  }
}
