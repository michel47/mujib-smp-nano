const $ = (id) => document.getElementById(id);

let lastPw = ""; // short-lived UI display/copy only
let lastCtx = null; // { tabId, domain, url, expiresAt }

function normalizeDomain(urlStr) {
  try {
    const u = new URL(urlStr);
    // Security: refuse non-https contexts by default
    if (u.protocol !== "https:") return "insecure";
    // Mujib: TODO (production): use eTLD+1 (Public Suffix List) parsing
    return u.hostname.replace(/^www\./, "");
  } catch {
    return "unknown";
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
  if (master.length < 8) {
    return "Master secret must be at least 8 characters.";
  }
  if (!/[A-Za-z]/.test(master)) {
    return "Master secret must contain letters.";
  }
  if (!/[0-9]/.test(master)) {
    return "Master secret must contain numbers.";
  }
  if (!/[^A-Za-z0-9]/.test(master)) {
    return "Master secret must contain a special character.";
  }
  return null;
}

function phishingWarning(domain) {
  if (!domain) return null;

  // punycode warning (xn-- often used in IDN attacks)
  if (domain.includes("xn--")) {
    return "Suspicious domain (punycode detected). Check carefully.";
  }

  // very long domain warning
  if (domain.length > 40) {
    return "Unusually long domain name. Verify carefully.";
  }

  // many hyphens can be suspicious
  if ((domain.match(/-/g) || []).length >= 4) {
    return "Domain contains many hyphens. Possible phishing.";
  }

  return null;
}

async function mainInit() {
  const tab = await getActiveTab();
  const url = tab?.url || "";
  const domain = normalizeDomain(url);
  const warn = phishingWarning(domain);
  if (warn) {
    $("out").textContent = warn + " Generation blocked.";
    return;
  }
  $("siteLine").textContent = `Site: ${domain}`;
  if (domain === "insecure" || domain === "unknown") {
    $("out").textContent = "Unsupported or insecure page. Open an https:// site.";
    $("gen").disabled = true;
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
  if (!tab?.id || !tab?.url) {
    $("out").textContent = "No active tab found.";
    return;
  }

  const url = tab.url;
  const domain = normalizeDomain(url);

  if (domain === "insecure" || domain === "unknown") {
    $("out").textContent = "Refusing to generate on insecure/unknown site.";
    return;
  }

  const user = $("user").value.trim();
  const counter = Math.max(1, Number($("ctr").value) || 1);
  const length = Math.max(12, Math.min(64, Number($("len").value) || 20));
  const mode = $("mode").value;

  $("out").textContent = "Generating…";

  // Send derivation request to service worker (keeps crypto out of popup UI)
  const resp = await sendToSW({
    type: "SMDNANO_GENERATE",
    master,
    tabId: tab.id,
    url,
    domain,
    user,
    counter,
    length,
    mode,
  });

  // Best-effort: clear master input immediately
  $("master").value = "";

  if (!resp?.ok) {
    $("out").textContent = `${resp?.error || "Generation failed"}`;
    $("copy").disabled = true;
    $("fill").disabled = true;
    lastPw = "";
    lastCtx = null;
    return;
  }

  lastPw = resp.password; // for UI display/copy only
  lastCtx = resp.ctx;     // { tabId, domain, url, expiresAt }

  //$("siteLine").textContent = `Site: ${lastCtx.domain}`;
  $("siteLine").innerHTML = `<b>Site:</b> ${lastCtx.domain}`;


  $("out").textContent = "Password generated";
  $("gen").textContent = "Generated";
  $("copy").disabled = false;
  $("fill").disabled = false;

});

$("master").addEventListener("input", () => {
  $("gen").textContent = "Generate";
});

$("copy").addEventListener("click", async () => {
  if (!lastPw) return;
  await navigator.clipboard.writeText(lastPw);

  // Optional security: auto-clear clipboard after 30s
  setTimeout(() => navigator.clipboard.writeText("").catch(() => {}), 30000);
});

$("fill").addEventListener("click", async () => {
  if (!lastCtx) return;

  // Ask SW to fill using its cached password + context checks.
  const resp = await sendToSW({
    type: "SMPNANO_FILL",
    tabId: lastCtx.tabId,
  });

  if (!resp?.ok) {
    $("out").textContent = `${resp?.error || "Fill refused"}`;
    return;
  }

  // Best-effort: wipe local copies after fill
  lastPw = "";
  lastCtx = null;
  $("fill").disabled = true;
  $("copy").disabled = true;
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

mainInit();