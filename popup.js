const $ = (id) => document.getElementById(id);

let lastPw = ""; // Short-lived in-memory display copy only
let lastCtx = null; // { tabId, domain, url, expiresAt, trust } - Used for TOCTOU verification
let currentEmoji = ""; // Visual hint for the generated password
let isLicenseExpired = false;

// Dynamic app info for header
let appTitle = "SMP Nano"; // Default
let appVersion = "v?.?.?";  // Default
let policyReleaseDate = "Unknown"; // Default


function getSiteContext(urlStr) {
  try {
    const u = new URL(urlStr);
    let domain = u.hostname.replace(/^www\./, "");
    
    // Support local mockup files
    if (u.protocol === "file:") {
      domain = u.pathname.split("/").pop() || "localfile";
    }

    console.debug("[Popup] getSiteContext:", { url: urlStr, domain, protocol: u.protocol });

    const phishing = phishingWarning(domain);
    
    let status = "ok";
    let message = null;
    
    // Security: Refuse non-HTTPS contexts by default (except localhost/file for mockups)
    if (u.protocol !== "https:" && u.hostname !== "localhost" && u.protocol !== "file:") {
      status = "insecure";
      message = "Insecure Protocol (HTTP)";
    } else if (phishing) {
      status = "suspicious";
      message = `PHISHING RISK: ${phishing}`;
    }

    return { domain, status, message, url: urlStr };
  } catch {
    return { domain: "unknown", status: "error", message: "Invalid URL", url: urlStr };
  }
}

async function getActiveTab() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  return tab || null;
}

function sendToSW(message) {
  return new Promise((resolve) => chrome.runtime.sendMessage(message, resolve));
}

function validateMasterSecret(master) {
  // Basic entropy check for the master secret
  if (master.length < 6) {
    return "Master secret must be at least 6 characters.";
  }
  if (!/[A-Za-z]/.test(master)) {
    return "Master secret should contain letters.";
  }
  if (!/[^A-Za-z]/.test(master)) {
    return "Master secret must contain numbers or special characters.";
  }
  return null;
}

function phishingWarning(domain) {
  if (!domain || domain === "unknown") return null;

  // Punycode warning (xn-- often used in IDN homograph attacks)
  if (domain.includes("xn--")) {
    return "Punycode/IDN detected";
  }

  // Very long domain warning
  if (domain.length > 40) {
    return "Unusually long hostname";
  }

  // Many hyphens can be suspicious in phishing URLs
  if ((domain.match(/-/g) || []).length >= 4) {
    return "Excessive hyphens";
  }

  return null;
}

const PASSMOJI_EMOJIS = [
  '🔑', '❤️', '💡', '🌟', '🍀', '🚀', '🌈', '🐶', '🍕', '🎉',
  '🎶', '🌍', '🔥', '💧', '⚡', '🌱', '🍎', '💰', '👑', '🗿'
];
const VISUALIZATION_SALT = 'bsu-password-v1-visual';

async function derivePassmoji(password) {
  if (!password) return '';
  const encoder = new TextEncoder();
  const data = encoder.encode(password + VISUALIZATION_SALT);
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  const hashBytes = new Uint8Array(hashBuffer);
  const emojiIndex = hashBytes[0] % PASSMOJI_EMOJIS.length;
  return PASSMOJI_EMOJIS[emojiIndex];
}

async function initAppHeader() {
  const manifest = chrome.runtime.getManifest();
  appTitle = manifest.name || appTitle;
  appVersion = `v${manifest.version || appVersion}`;

  const resp = await fetch(chrome.runtime.getURL('policy.json'));
  const acl = await resp.json();
  policyReleaseDate = acl.created_at ? new Date(acl.created_at).toLocaleDateString() : policyReleaseDate;

  $("appIcon").src = chrome.runtime.getURL('1f6e1g.svg');
  $("appTitle").textContent = appTitle;
  $("appVersion").textContent = appVersion;
  $("policyRelease").textContent = `Policy Date: ${policyReleaseDate}`;
}


async function mainInit() {
  // Initialize app header info
  await initAppHeader();

  const tab = await getActiveTab();
  const url = tab?.url || "";
  
  // Policy-Based Access Control: Ask Service Worker for the current page's policy
  const policy = await sendToSW({ type: "SMPNANO_GET_POLICY", url });
  
  if (policy.action === "DENY") {
    const configUrl = chrome.runtime.getURL('policy.json');
    $("out").innerHTML = `Access Denied: Site blocked by <a href="${configUrl}" target="_blank" style="color: #d93025; text-decoration: underline;">policy</a>.`;
    $("out").style.color = "#d93025";
    $("gen").disabled = true;
    return;
  }

  // Set the automated counter from policy
  $("ctr").value = policy.autoCounter;
  isLicenseExpired = policy.isExpired;
  
  // If expired, restrict counter to DECREASE only (set max to current value)
  if (isLicenseExpired) {
    $("ctr").max = policy.autoCounter;
    $("out").textContent = "LICENSE EXPIRED: Manual rotation restricted.";
    $("out").style.color = "#d93025";
  }

  $("siteLine").textContent = `Site: ${policy.domain}`;
  
  if (policy.trust === "UNTRUSTED") {
    $("out").textContent = "Untrusted Context [DECOY MODE]";
    $("out").style.color = "#d93025";
  }

  // Query content script for metadata
  if (tab?.id && policy.domain !== "unknown") {
    chrome.tabs.sendMessage(tab.id, { type: "SMPNANO_QUERY_CONTEXT" }, (resp) => {
      if (resp?.username) $("user").value = resp.username;
      if (resp?.pwFields && resp.pwFields.length > 0) {
        const fieldInfo = document.createElement("div");
        fieldInfo.className = "muted small";
        fieldInfo.style.marginTop = "4px";
        fieldInfo.id = "targetSummary";
        fieldInfo.textContent = "Targets: " + resp.pwFields.join(", ");
        $("siteLine").after(fieldInfo);

        // Adjust counter for new-password contexts if license is not expired
        const firstTargetHint = resp.pwFields[0];
        if (!isLicenseExpired && firstTargetHint && firstTargetHint.toLowerCase().includes("new-password")) {
          // Set counter to one above expirationCounter to ensure a fresh password
          $("ctr").value = Math.max(policy.autoCounter, policy.expirationCounter + 1);
        }

      } else {
        $("out").textContent = "No password fields detected.";
        $("gen").disabled = true;
      }
    }).catch(() => {
      $("gen").disabled = true;
      $("out").textContent = "Cannot run on this page.";
    });
  }
}

$("gen").addEventListener("click", async () => {
  const master = $("master").value;
  const err = validateMasterSecret(master);
  if (err) {
    $("out").textContent = err;
    return;
  }

  const tab = await getActiveTab();
  if (!tab?.id || !tab?.url) return;

  const policy = await sendToSW({ type: "SMPNANO_GET_POLICY", url: tab.url });
  const isDecoy = policy.trust === "UNTRUSTED";

  let initialStatusMessage = isDecoy ? "Generating Decoy…" : "Generating…";
  $("out").textContent = initialStatusMessage;

  // Capture targetHintDisplay from the highlight response
  let targetHintDisplay = "";
  try {
    const highlightResp = await chrome.tabs.sendMessage(tab.id, { type: "SMPNANO_HIGHLIGHT" });
    if (highlightResp?.hint) {
      targetHintDisplay = `Target: ${highlightResp.hint}`;
      // Temporarily update to show hint during async op
      $("out").textContent = `${initialStatusMessage}\n(${targetHintDisplay})`;
    }
  } catch (e) {
    console.warn("[Popup] Could not highlight field:", e);
  }

  console.log("[Popup] Requesting GENERATE from SW:", { domain: policy.domain, isDecoy });
  // Send derivation request to Service Worker
  const resp = await sendToSW({
    type: "SMDNANO_GENERATE",
    master,
    tabId: tab.id,
    url: tab.url,
    domain: policy.domain,
    user: $("user").value.trim(),
    counter: Math.max(1, Number($("ctr").value) || 1),
    length: Math.max(12, Math.min(64, Number($("len").value) || 20)),
    mode: $("mode").value
  });

  // Best-effort: clear master input immediately after generation to reduce memory persistence
  $("master").value = "";

  if (!resp?.ok) {
    console.error("[Popup] Generation failed:", resp?.error);
    $("out").textContent = `${resp?.error || "Failed"}`;
    $("copy").disabled = true;
    $("fill").disabled = true;
    lastPw = "";
    lastCtx = null;
    return;
  }

  console.log("[Popup] Generation success:", resp.ctx);
  lastPw = resp.password;
  lastCtx = resp.ctx;
  
  // Derive Passmoji (or use fixed indicator if expired)
  currentEmoji = isLicenseExpired ? "🚫" : await derivePassmoji(lastPw);

  $("siteLine").textContent = ""; 
  const label = document.createElement("b");
  label.textContent = isDecoy ? "Site (DECOY): " : "Site: ";
  $("siteLine").appendChild(label);
  $("siteLine").appendChild(document.createTextNode(lastCtx.domain));

  // Combine generation status with the target hint at the very end to avoid UI race conditions
  $("out").textContent = `${isDecoy ? "DECOY Password Generated" : "Password generated"} (${currentEmoji})${targetHintDisplay ? "\n(" + targetHintDisplay + ")" : ""}`;
  $("gen").textContent = "Generated";
  $("copy").disabled = false;
  $("fill").disabled = false;
  $("fill").textContent = `Fill ${currentEmoji}`; 
});


$("master").addEventListener("input", () => {
  $("gen").textContent = "Generate";
  currentEmoji = "";
  $("fill").textContent = "Fill";
});

$("copy").addEventListener("click", async () => {
  if ($("copy").textContent === "Clear") {
    // Manual clear: This works because it is a direct result of a user click.
    try {
      await navigator.clipboard.writeText("");
      $("copy").textContent = "Copy";
    } catch (e) {
      console.error("Manual clear failed:", e);
    }
    return;
  }

  if (!lastPw) return;
  
  try {
    await navigator.clipboard.writeText(lastPw);
    $("copy").textContent = "Clear";
    $("copy").title = "Click to wipe clipboard";
  } catch (e) {
    $("out").textContent = "Clipboard access denied. Please allow permissions.";
  }
});

$("fill").addEventListener("click", async () => {
  if (!lastCtx) return;

  console.log("[Popup] Requesting FILL for tab:", lastCtx.tabId);
  // Ask SW to fill using its cached password + context checks.
  const resp = await sendToSW({
    type: "SMPNANO_FILL",
    tabId: lastCtx.tabId,
  });

  if (!resp?.ok) {
    console.error("[Popup] Fill refused by SW:", resp?.error);
    $("out").textContent = `${resp?.error || "Fill refused"}`;
    lastPw = "";
    lastCtx = null;
    $("fill").disabled = true;
    return;
  }
  
  console.log("[Popup] Fill response received:", resp);

  // resp contains { ok: true, remaining: X, nextHint: "..." } from content.js
  if (resp.remaining > 0) {
    // If there are more fields (e.g. "Confirm Password"), update the button
    $("fill").textContent = `Fill ${resp.nextHint || "Next"} ${currentEmoji}`;
    $("out").textContent = `${resp.remaining} field(s) remaining...`;
  } else {
    // All done: Secure cleanup and close
    lastPw = "";
    lastCtx = null;
    currentEmoji = "";
    $("master").value = "";
    $("fill").disabled = true;
    $("copy").disabled = true;
    $("out").textContent = "All fields filled. Closing...";
    
    // Brief delay so user sees the "Success" state before it vanishes
    setTimeout(() => window.close(), 500);
  }
});

chrome.tabs.onActivated.addListener(() => {
  if (lastCtx) {
    $("out").textContent = "Tab changed after generation. Please generate again.";
    lastPw = "";
    lastCtx = null;
    $("fill").disabled = true;
  }
});

chrome.tabs.onUpdated.addListener((tabId, changeInfo) => {
  if (lastCtx && tabId === lastCtx.tabId && changeInfo.url) {
    $("out").textContent =
      "Page changed after generation. Please generate again.";
    lastPw = "";
    lastCtx = null;
    $("fill").disabled = true;
  }
});

$("peek").addEventListener("mouseover", () => {
  $("master").type = "text";
});

$("peek").addEventListener("mouseout", () => {
  $("master").type = "password";
});

// Also toggle on click for touch devices
$("peek").addEventListener("click", () => {
  const isPass = $("master").type === "password";
  $("master").type = isPass ? "text" : "password";
});

chrome.runtime.onMessage.addListener((msg) => {
  if (msg?.type === "SMPNANO_PASTE_CLEARED_RELAY") {
    console.log("[Popup] Clipboard auto-cleared after successful paste.");
    $("copy").textContent = "Copy";
    $("copy").title = "Clipboard cleared after paste";
  }
});

chrome.runtime.onMessage.addListener((msg) => {
  if (msg?.type === "SMPNANO_RESET_MASTER_SECRET_RELAY") {
    console.warn("[Popup] Master secret reset due to context change.");
    lastPw = "";
    lastCtx = null;
    currentEmoji = "";
    $("master").value = "";
    $("fill").disabled = true;
    $("copy").disabled = true;
    $("out").textContent = "Master secret reset due to new password context.";
  }
});

mainInit();
