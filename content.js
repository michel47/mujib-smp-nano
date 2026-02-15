function isTopFrame() {
  try {
    return window.top === window;
  } catch {
    return false;
  }
}

function isHttps() {
  return location.protocol === "https:";
}

function findPasswordField() {
  //Mujib (Naive MVP): real sites may need heuristics, shadow DOM, multi-step flows, etc.
  return document.querySelector('input[type="password"]');
}

chrome.runtime.onMessage.addListener((msg) => {
  if (msg?.type !== "SMPNANO_FILL") return;

  // Clickjacking/iframe mitigation
  if (!isTopFrame()) return;

  // HTTPS-only fill
  if (!isHttps()) return;

  const pwField = findPasswordField();
  if (!pwField) {
  alert("No password field found on this page.");
    return;
  }

  pwField.focus();
  pwField.value = msg.password;

  pwField.dispatchEvent(new Event("input", { bubbles: true }));
  pwField.dispatchEvent(new Event("change", { bubbles: true }));
});
