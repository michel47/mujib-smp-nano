// In-memory cache only (vaultless): tabId -> { domain, url, password, expiresAt }
// This Map is short-lived and never persisted to disk, mitigating extraction risks.
const cache = new Map();
let acl = null;

// Persistence: One-time installation seeds to harden derivation against cross-install attacks.
chrome.runtime.onInstalled.addListener(async (details) => {
  if (details.reason === 'install') {
    await chrome.storage.local.set({
      installSeed: crypto.randomUUID(),
      userSeed: crypto.randomUUID()
    });
    console.log("[SW] Installation seeds generated and stored.");
  }
});

async function loadACL() {
  try {
    const resp = await fetch(chrome.runtime.getURL('policy.json'));
    acl = await resp.json();
  } catch (e) {
    console.error("Failed to load ACL:", e);
  }
}

function patternToRegex(pattern) {
  // If it looks like a regex (starts with ^), return it as is
  if (pattern.startsWith("^")) return new RegExp(pattern, 'i');
  
  const escaped = pattern.replace(/[.+^${}()|[\]\\]/g, '\\$&')
                         .replace(/\*/g, '.*')
                         .replace(/\?/g, '.');
  return new RegExp(`^${escaped}$`, 'i');
}

function checkAccess(url) {
  if (!acl) return true; // Default to allow if ACL fails to load

  const { mode, rules } = acl;
  const matches = (list) => list.some(p => patternToRegex(p).test(url));

  if (mode === "DENY+ALLOW+EXCEPT") {
    // Default: DENY
    let allowed = false;
    if (matches(rules.allow)) allowed = true;
    if (matches(rules.deny)) allowed = false;
    if (matches(rules.except)) allowed = true; // Final override
    return allowed;
  } else {
    // Default: ALLOW (ALLOW+DENY+EXCEPT)
    let allowed = true;
    if (matches(rules.deny)) allowed = false;
    if (matches(rules.allow)) allowed = true;
    if (matches(rules.except)) allowed = false; // Final override
    return allowed;
  }
}

function getSaltLabel(domain, url, isDecoy) {
  if (!acl) return isDecoy ? "smd-nano-decoy" : "smd-nano";

  if (acl.license_status === "EXPIRED") return "smd-nano-expired";

  // Check custom overrides (first match wins)
  for (const entry of acl.overrides) {
    if (patternToRegex(entry.pattern).test(domain) || patternToRegex(entry.pattern).test(url)) {
      return entry.salt;
    }
  }

  return isDecoy ? "smd-nano-decoy" : "smd-nano";
}

// Policy Engine: Centralized source of truth for security decisions
async function getPolicy(url) {
  if (!acl) await loadACL();
  const { mode, rules, overrides, license_status, license_expiry, created_at } = acl;
  
  const matches = (list) => list.some(p => patternToRegex(p).test(url));
  const domain = normalizeDomain(url);

  // 1. Determine Access (ALLOW vs DENY)
  let action = (mode === "DENY+ALLOW+EXCEPT") ? "DENY" : "ALLOW";
  if (mode === "DENY+ALLOW+EXCEPT") {
    if (matches(rules.allow)) action = "ALLOW";
    if (matches(rules.deny)) action = "DENY";
    if (matches(rules.except)) action = "ALLOW";
  } else {
    // ALLOW+DENY+EXCEPT
    if (matches(rules.deny)) action = "DENY";
    if (matches(rules.allow)) action = "ALLOW";
    if (matches(rules.except)) action = "DENY";
  }

  console.debug("[SW] Policy Evaluation:", { url, action, domain });

  // 2. Determine License Status & Trust
  const nowTime = Date.now();
  const expiryTime = new Date(license_expiry).getTime();
  const isExpired = license_status === "EXPIRED" || nowTime > expiryTime;
  
  const isTrusted = matches(acl.trusted_contexts);
  const trust = isTrusted ? "TRUSTED" : "UNTRUSTED";

  // 3. Determine Salt Label
  let salt = isTrusted ? "smd-nano" : "smd-nano-decoy";
  if (isExpired) {
    salt = "smd-nano-expired";
  } else {
    for (const entry of overrides) {
      if (patternToRegex(entry.pattern).test(domain) || patternToRegex(entry.pattern).test(url)) {
        salt = entry.salt;
        break;
      }
    }
  }

  // 4. Calculate Automated Counter: int( ((now - release)/(86400) + 89)/90 )
  const releaseTime = new Date(created_at).getTime();
  const daysSinceRelease = (nowTime - releaseTime) / (1000 * 60 * 60 * 24);
  const autoCounter = Math.floor((daysSinceRelease + 89) / 90) || 1;

  // Calculate Counter at Expiration
  const daysAtExpiry = (expiryTime - releaseTime) / (1000 * 60 * 60 * 24);
  const expirationCounter = Math.floor((daysAtExpiry + 89) / 90) || 1;


  return { action, trust, salt, domain, autoCounter, isExpired, expirationCounter };
}

function normalizeDomain(urlStr) {
  try {
    const u = new URL(urlStr);
    let domain = "unknown";
    if (u.protocol === "file:") {
      domain = u.pathname.split("/").pop() || "localfile";
    } else {
      domain = u.hostname.replace(/^www\./, "");
    }
    return domain;
  } catch (e) {
    return "unknown";
  }
}

function pickUniform(bytes, idxRef, n) {
  // Rejection sampling threshold: Ensures no character/position is statistically favored (no modulo bias).
  const max = Math.floor(256 / n) * n; 
  while (idxRef.i < bytes.length) {
    const b = bytes[idxRef.i++];
    if (b < max) return b % n;
  }
  throw new Error("Not enough entropy bytes");
}

function generateDeterministicUUID(sig, idxRef) {
  // UUID v4 format: xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx
  // where y is 8, 9, a, or b.
  const bytes = new Uint8Array(16);
  for (let i = 0; i < 16; i++) {
    bytes[i] = sig[idxRef.i++];
  }
  // Set version 4
  bytes[6] = (bytes[6] & 0x0f) | 0x40;
  // Set variant 10 (8, 9, a, or b)
  bytes[8] = (bytes[8] & 0x3f) | 0x80;

  const hex = Array.from(bytes).map(b => b.toString(16).padStart(2, '0'));
  return `${hex.slice(0, 4).join('')}-${hex.slice(4, 6).join('')}-${hex.slice(6, 8).join('')}-${hex.slice(8, 10).join('')}-${hex.slice(10, 16).join('')}`;
}

async function derivePassword({ master, domain, user, counter, length, mode, saltLabel, url }) {
  const enc = new TextEncoder();

  // 1. Derive site-specific base key (IKM) from master secret using PBKDF2.
  const masterKey = await crypto.subtle.importKey(
    "raw",
    enc.encode(master),
    "PBKDF2",
    false,
    ["deriveBits"]
  );

  const salt = enc.encode(`${saltLabel}|${domain}`);
  
  const ikm = await crypto.subtle.deriveBits(
    { name: "PBKDF2", salt, iterations: 200_000, hash: "SHA-256" },
    masterKey,
    256 // 32 bytes
  );

  // 2. Retrieve installation seeds to harden the derivation mix.
  const { installSeed, userSeed } = await chrome.storage.local.get(['installSeed', 'userSeed']);

  // 3. Expand entropy using HKDF.
  // We incorporate the seeds into the HKDF info block to ensure per-install uniqueness.
  const hkdfKey = await crypto.subtle.importKey("raw", ikm, "HKDF", false, ["deriveBits"]);
  const info = enc.encode(`${domain}|${user || ""}|${counter}|${installSeed || ''}|${userSeed || ''}`);
  const sig = new Uint8Array(await crypto.subtle.deriveBits(
    { name: "HKDF", hash: "SHA-256", salt: new Uint8Array(0), info },
    hkdfKey,
    1024 // 128 bytes
  ));

  const idxRef = { i: 0 };
  const L = length;

  if (mode === "uuid4") {
    return generateDeterministicUUID(sig, idxRef);
  }
  
  // 4. Merged Complexity Implementation
  const res = new Array(L);

  if (mode === "alpnumsym") {
    // Pre-select 4 distinct positions for required categories
    const pos = [];
    const used = new Set();
    while (pos.length < 4 && pos.length < L) {
      const p = pickUniform(sig, idxRef, L);
      if (!used.has(p)) {
        used.add(p);
        pos.push(p);
      }
    }

    const charsets = [
      "abcdefghijklmnopqrstuvwxyz",
      "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
      "0123456789",
      "!@#$%^&*()-_=+[]{};:,.?"
    ];

    // Fill mandatory positions first
    for (let k = 0; k < pos.length; k++) {
      const cs = charsets[k];
      res[pos[k]] = cs[pickUniform(sig, idxRef, cs.length)];
    }
  } else if (mode === "base64url") {
    // Special requirement: ensure at least one '-' or '_'
    const p = pickUniform(sig, idxRef, L);
    const spec = "-_";
    res[p] = spec[pickUniform(sig, idxRef, spec.length)];
  }

  const fullCharset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+[]{};:,.?";
  const b64Charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_";

  // Fill remaining positions uniformly
  for (let i = 0; i < L; i++) {
    if (res[i] === undefined) {
      const currentCharset = (mode === "base64url") ? b64Charset : fullCharset;
      res[i] = currentCharset[pickUniform(sig, idxRef, currentCharset.length)];
    }
  }

  return res.join("");
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
    if (msg?.type === "SMPNANO_GET_POLICY") {
      const policy = await getPolicy(msg.url);
      return sendResponse(policy);
    }

    if (msg?.type === "SMPNANO_PASTE_CLEARED") {
      chrome.runtime.sendMessage({ type: "SMPNANO_PASTE_CLEARED_RELAY" });
      return sendResponse({ ok: true });
    }

    if (msg?.type === "SMPNANO_RESET_MASTER_SECRET") {
      // Forward the event to the popup if it's open
      chrome.runtime.sendMessage({ type: "SMPNANO_RESET_MASTER_SECRET_RELAY" });
      return sendResponse({ ok: true });
    }

    if (msg?.type === "SMDNANO_GENERATE") {
      const { master, tabId, url, domain, user, counter, length, mode } = msg;

      const policy = await getPolicy(url);
      if (policy.action === "DENY") {
        return sendResponse({ ok: false, error: "Access Denied by Policy" });
      }
      if (policy.domain !== domain) {
        return sendResponse({ ok: false, error: "Context Mismatch: Domain changed" });
      }

      const password = await derivePassword({ 
        master, 
        domain: policy.domain, 
        user, 
        counter, 
        length, 
        mode, 
        saltLabel: policy.salt, 
        url 
      });

      const expiresAt = now() + 20_000;
      cache.set(tabId, { domain: policy.domain, url, password, user, trust: policy.trust, expiresAt });

      return sendResponse({
        ok: true,
        password,
        ctx: { tabId, domain: policy.domain, url, expiresAt, trust: policy.trust },
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
      const policyNow = await getPolicy(urlNow);

      // TOCTOU protection
      if (policyNow.domain !== entry.domain) {
        cache.delete(tabId);
        return sendResponse({
          ok: false,
          error: `Refusing: context changed (was ${entry.domain}, now ${policyNow.domain})`,
        });
      }

      // Send fill to content script with trust level
      chrome.tabs.sendMessage(tabId, {
        type: "SMPNANO_FILL",
        password: entry.password,
        username: entry.user,
        domain: entry.domain,
        trust: entry.trust
      }, (resp) => sendResponse(resp));

      return true;
    }

    return sendResponse({ ok: false, error: "Unknown message" });
  })().catch((e) => sendResponse({ ok: false, error: e?.message || "Error" }));

  return true; 
});