// In-memory cache only (vaultless): tabId -> { domain, url, password, expiresAt }
const cache = new Map();

function normalizeDomain(urlStr) {
  try {
    const u = new URL(urlStr);
    if (u.protocol !== "https:") return "insecure";
    // TODO (production): use eTLD+1 (Public Suffix List) parsing
    return u.hostname.replace(/^www\./, "");
  } catch {
    return "unknown";
  }
}

function toBase64Url(bytes) {
  const bin = String.fromCharCode(...bytes);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function pickUniform(bytes, idxRef, n) {
  const max = Math.floor(256 / n) * n; // rejection sampling threshold
  while (idxRef.i < bytes.length) {
    const b = bytes[idxRef.i++];
    if (b < max) return b % n;
  }
  throw new Error("Not enough entropy bytes");
}

function encodeUniform(bytes, charset, length, idxRef) {
  const out = [];
  const N = charset.length;

  while (out.length < length) {
    const j = pickUniform(bytes, idxRef, N);
    out.push(charset[j]);
  }
  return out.join("");
}

function enforceComplexityUpdated(pw, entropyBytes, idxRef) {
  const lower = "abcdefghijklmnopqrstuvwxyz";
  const upper = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
  const digit = "0123456789";
  const sym = "!@#$%^&*()-_=+[]{};:,.?";

  const s = pw.split("");
  const L = s.length;
  if (L < 4) return pw;

  const needLower = !/[a-z]/.test(pw);
  const needUpper = !/[A-Z]/.test(pw);
  const needDigit = !/[0-9]/.test(pw);
  const needSym = !/[^A-Za-z0-9]/.test(pw);

  // Choose 4 distinct positions deterministically (NOT fixed 0/1/2/3)
  const used = new Set();
  const pos = [];
  while (pos.length < 4) {
    const p = pickUniform(entropyBytes, idxRef, L);
    if (!used.has(p)) {
      used.add(p);
      pos.push(p);
    }
  }

  let k = 0;
  if (needLower) s[pos[k++]] = lower[pickUniform(entropyBytes, idxRef, lower.length)];
  if (needUpper) s[pos[k++]] = upper[pickUniform(entropyBytes, idxRef, upper.length)];
  if (needDigit) s[pos[k++]] = digit[pickUniform(entropyBytes, idxRef, digit.length)];
  if (needSym) s[pos[k++]] = sym[pickUniform(entropyBytes, idxRef, sym.length)];

  return s.join("");
}

async function derivePassword({ master, domain, user, counter, length, mode }) {
  const enc = new TextEncoder();

  const masterKey = await crypto.subtle.importKey(
    "raw",
    enc.encode(master),
    "PBKDF2",
    false,
    ["deriveKey"]
  );

  const salt = enc.encode(`smd-nano|${domain}`);
  const hmacKey = await crypto.subtle.deriveKey(
    { name: "PBKDF2", salt, iterations: 200_000, hash: "SHA-256" },
    masterKey,
    { name: "HMAC", hash: "SHA-256", length: 256 },
    false,
    ["sign"]
  );

  const msg = enc.encode(`${domain}|${user || ""}|${counter}`);
  const sig = new Uint8Array(await crypto.subtle.sign("HMAC", hmacKey, msg));

  // Use sig as deterministic entropy stream
  const idxRef = { i: 0 };

  let pw = "";
  if (mode === "base64url") {
    // base64url is fine, but we still apply complexity fixups below
    pw = toBase64Url(sig).slice(0, length);
  } else {
    const charset =
      "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+[]{};:,.?";
    pw = encodeUniform(sig, charset, length, idxRef); // no modulo bias
  }

  pw = enforceComplexityUpdated(pw, sig, idxRef).slice(0, length);
  return pw;
}

async function getTabUrl(tabId) {
  const tab = await chrome.tabs.get(tabId);
  return tab?.url || "";
}

function now() {
  return Date.now();
}

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  (async () => {
    if (msg?.type === "SMDNANO_GENERATE") {
      const { master, tabId, url, domain, user, counter, length, mode } = msg;

      if (!master) return sendResponse({ ok: false, error: "Missing master secret" });
      if (!tabId || !url) return sendResponse({ ok: false, error: "Missing tab context" });

      const dom = normalizeDomain(url);
      if (dom !== domain || dom === "insecure" || dom === "unknown") {
        return sendResponse({ ok: false, error: "Refusing: insecure/unknown domain" });
      }

      const password = await derivePassword({ master, domain, user, counter, length, mode });

      // Short expiry to reduce clickjacking/TOCTOU risk (e.g., 20 seconds)
      const expiresAt = now() + 20_000;

      cache.set(tabId, { domain, url, password, expiresAt });

      return sendResponse({
        ok: true,
        password,
        ctx: { tabId, domain, url, expiresAt },
      });
    }

    if (msg?.type === "SMPNANO_FILL") {
      const { tabId } = msg;
      const entry = cache.get(tabId);

      if (!entry) return sendResponse({ ok: false, error: "Nothing to fill (expired/cleared)" });
      if (now() > entry.expiresAt) {
        cache.delete(tabId);
        return sendResponse({ ok: false, error: "Expired. Please generate again." });
      }

      const urlNow = await getTabUrl(tabId);
      const domNow = normalizeDomain(urlNow);

      // TOCTOU protection: same tab + same domain snapshot required
      if (domNow !== entry.domain) {
        cache.delete(tabId);
        return sendResponse({
          ok: false,
          error: `Refusing: context changed (was ${entry.domain}, now ${domNow})`,
        });
      }

      // Send fill to content script (one-time). Content script will refuse if iframe/non-https.
      await chrome.tabs.sendMessage(tabId, {
        type: "SMPNANO_FILL",
        password: entry.password,
        domain: entry.domain,
      });

      // One-time use: wipe immediately
      cache.delete(tabId);

      return sendResponse({ ok: true });
    }

    return sendResponse({ ok: false, error: "Unknown message" });
  })().catch((e) => sendResponse({ ok: false, error: e?.message || "Error" }));

  return true; // keep async channel open
});