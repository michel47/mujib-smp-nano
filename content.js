function isTopFrame() {
  try {
    return window.top === window;
  } catch {
    return false;
  }
}

function isHttps() {
  // Allow HTTPS, localhost (HTTP), or local files
  return location.protocol === "https:" || 
         location.hostname === "localhost" || 
         location.hostname === "127.0.0.1" ||
         location.protocol === "file:";
}

function findPasswordFields() {
  // Find all password fields on the page
  const fields = Array.from(document.querySelectorAll('input[type="password"]'));
  
  // Design Principle: Frictionless multi-step forms.
  // We identify "new" vs "current" passwords using autocomplete attributes.
  const newPasswordFields = fields.filter(f => {
    const ac = (f.getAttribute('autocomplete') || '').toLowerCase();
    // Skip if explicitly marked as current-password (previous password)
    return ac !== 'current-password';
  });

  // If we found specific "new" fields, prioritize them. 
  // Otherwise, fall back to all password fields.
  return newPasswordFields.length > 0 ? newPasswordFields : fields;
}

function findUsernameField() {
  // Heuristic: Find common username/email fields
  const allInputs = Array.from(document.querySelectorAll('input:not([type="password"]):not([type="hidden"]):not([type="submit"]):not([type="button"])'));
  
  // FILTER: Exclude anything that looks like a password field (even if type is toggled to text)
  const nonPasswordInputs = allInputs.filter(i => {
    const semanticCheck = (i.name + i.id + i.getAttribute('autocomplete') + i.placeholder).toLowerCase();
    return !semanticCheck.includes("password");
  });

  const pw = document.querySelector('input[type="password"]');
  
  let target;
  if (!pw) {
    target = nonPasswordInputs.find(i => /user|email|login|id/i.test(i.name || i.id || i.placeholder || '')) || nonPasswordInputs[0];
  } else {
    // Look for the closest input above the password field that isn't a password itself
    const rect = pw.getBoundingClientRect();
    target = nonPasswordInputs
      .filter(i => i.getBoundingClientRect().top < rect.top)
      .sort((a, b) => b.getBoundingClientRect().top - a.getBoundingClientRect().top)[0];
  }
  console.debug("[Content] findUsernameField identified:", target);
  return target;
}

// Listen for paste events on password fields to attempt a "Paste & Clear"
document.addEventListener("paste", async (e) => {
  if (e.target && e.target.type === "password") {
    // Wait briefly for the paste to complete
    setTimeout(async () => {
      try {
        await navigator.clipboard.writeText("");
        // Notify the extension that we cleared the clipboard
        chrome.runtime.sendMessage({ type: "SMPNANO_PASTE_CLEARED" });
      } catch (err) {
        // If it fails (no user activation), alert the user
        alert("Paste completed, but clipboard could not be auto-cleared. Please click 'Clear' in the SMP Nano popup.");
      }
    }, 100);
  }
}, true);

// Track the last field that had focus to detect context changes
let lastFocusedPasswordField = null;

document.addEventListener("focusin", (e) => {
  if (e.target && e.target.type === "password") {
    if (lastFocusedPasswordField) {
      const currentAc = (lastFocusedPasswordField.getAttribute('autocomplete') || '').toLowerCase();
      const nextAc = (e.target.getAttribute('autocomplete') || '').toLowerCase();

      // If switching from non-new-password to new-password, and not current-password -> signal reset
      // This is to catch cases where user might manually tab/click to a new-password field
      // without first filling a current-password.
      if (currentAc !== 'new-password' && nextAc === 'new-password') {
        console.log("[Content] Context switch to new-password detected. Signalling reset.");
        chrome.runtime.sendMessage({ type: "SMPNANO_RESET_MASTER_SECRET" });
      }
    }
    lastFocusedPasswordField = e.target;
  } else {
    lastFocusedPasswordField = null; // Clear if focus leaves password fields
  }
});


chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg?.type === "SMPNANO_QUERY_CONTEXT") {
    const userField = findUsernameField();
    const pwFields = Array.from(document.querySelectorAll('input[type="password"]')).map(f => {
      const ac = f.getAttribute('autocomplete');
      const name = f.name;
      const id = f.id;
      let hint = ac || "";
      if (name || id) hint += ` (${name || id})`;
      return hint.trim() || "password";
    });

    sendResponse({ 
      username: userField ? userField.value : "",
      pwFields: pwFields
    });
    return true;
  }

  if (msg?.type === "SMPNANO_HIGHLIGHT") {
    const allFields = Array.from(document.querySelectorAll('input[type="password"]'));
    const targetField = allFields.find(f => !f.value) || allFields[0]; // Highlight first empty or first password field
    let hint = "password";
    if (targetField) {
      const ac = targetField.getAttribute('autocomplete');
      const name = targetField.name;
      const id = targetField.id;
      
      hint = ac || "";
      if (name || id) {
        hint += ` (${name || id})`;
      }
      hint = hint.trim() || "password";

      targetField.focus();
      const originalOutline = targetField.style.outline;
      const originalTransition = targetField.style.transition;
      targetField.style.transition = "outline 0.2s ease-in-out";
      targetField.style.outline = "4px solid #34a853"; // Chrome Green
      setTimeout(() => {
        targetField.style.outline = originalOutline;
        setTimeout(() => { targetField.style.transition = originalTransition; }, 200);
      }, 1000);
    }
    sendResponse({ hint });
    return true;
  }

  if (msg?.type !== "SMPNANO_FILL") return false;

  // Clickjacking/iframe mitigation
  if (!isTopFrame()) {
    sendResponse({ ok: false, error: "Fill refused: Not in top-level frame." });
    return true;
  }

  // Security: The Service Worker now enforces the trust policy.
  if (!msg.trust) {
    sendResponse({ ok: false, error: "Fill refused: Context not vetted by policy engine." });
    return true;
  }

  console.log(`[Content] Filling password in ${msg.trust} context. Provided username: "${msg.username || ''}"`);

  // 1. Handle Username Filling if provided and field is empty
  const userField = findUsernameField();
  if (userField && msg.username && !userField.value) {
    console.log("[Content] Injecting username into field.");
    userField.focus();
    userField.value = msg.username;
    userField.dispatchEvent(new Event("input", { bubbles: true }));
    userField.dispatchEvent(new Event("change", { bubbles: true }));
  }

  // 2. Handle Password Filling: Smart Sequential Fill
  const allPasswordFieldInputs = Array.from(document.querySelectorAll('input[type="password"]'));
  let fieldsToFill = [];

  const firstEmptyField = allPasswordFieldInputs.find(f => f.value === '');
  if (firstEmptyField) {
    fieldsToFill.push(firstEmptyField);

    // If the next empty field has the same autocomplete attribute as the one just filled, fill it too
    // This handles "New Password" and "Confirm New Password" pairs.
    const firstAc = (firstEmptyField.getAttribute('autocomplete') || '').toLowerCase();
    if (firstAc) {
      const nextEmptyField = allPasswordFieldInputs
        .slice(allPasswordFieldInputs.indexOf(firstEmptyField) + 1)
        .find(f => f.value === '' && (f.getAttribute('autocomplete') || '').toLowerCase() === firstAc);
        
      if (nextEmptyField) {
          console.log("[Content] Detected confirmation field with matching autocomplete. Batch filling.");
          fieldsToFill.push(nextEmptyField);
      }
    }
  }

  if (fieldsToFill.length === 0) {
    console.warn("[Content] No empty password fields found to fill.");
    sendResponse({ ok: false, error: "No empty password fields found.", remaining: 0 });
    return true;
  }

  fieldsToFill.forEach(pwField => {
    pwField.focus();
    try {
      const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value').set;
      setter.call(pwField, msg.password);
    } catch (e) {
      pwField.value = msg.password;
    }
    pwField.dispatchEvent(new Event("input", { bubbles: true }));
    pwField.dispatchEvent(new Event("change", { bubbles: true }));
  });

  // Calculate remaining fields *after* this fill operation
  const remaining = allPasswordFieldInputs.filter(f => f.value === '').length;
  const nextField = allPasswordFieldInputs.find(f => f.value === ''); 
  const nextHint = nextField ? (nextField.getAttribute('autocomplete') || 'password') : null;

  console.log(`[Content] Fill complete. Remaining empty password fields: ${remaining}`);
  sendResponse({ ok: true, remaining, nextHint });
  return true; 
});
