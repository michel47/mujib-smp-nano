# SMP Nano Architecture & Data Flow

This document provides a technical overview of how SMP Nano derives and fills passwords without storing any sensitive information.

## 1. Component Overview

The extension is divided into four main components:

*   **Popup UI (`popup.html`, `popup.js`)**: The user interface where the master secret and site context (username, counter) are entered.
*   **Service Worker (`sw.js`)**: The secure background process that performs all cryptographic operations and maintains a short-lived in-memory cache.
*   **Content Script (`content.js`)**: A script injected into web pages to locate password fields and perform the final "fill" operation.
*   **Manifest (`manifest.json`)**: Defines permissions, background scripts, and content script injection rules.

## 2. Password Derivation Process

The core of SMP Nano is its deterministic derivation engine. When a user clicks "Generate", the following steps occur:

### Step A: Input Collection
`popup.js` collects the following inputs:
*   **Master Secret**: The user's private passphrase.
*   **Context**: The active tab's domain (normalized to remove `www.`), an optional username, a counter (for password rotation), and the desired length/mode.

### Step B: Key Derivation (PBKDF2)
The master secret is converted into a high-entropy base key using **PBKDF2-HMAC-SHA256**:
*   **Salt**: `smd-nano|{domain}`
*   **Iterations**: 200,000
*   This step ensures that even if a user's master secret is weak, it is computationally expensive to brute-force.

### Step C: Deterministic Entropy Generation (HMAC)
The PBKDF2 output is used as a key for an **HMAC-SHA-256** operation:
*   **Message**: `{domain}|{username}|{counter}`
*   **Result**: A 32-byte (256-bit) signature that serves as a unique, deterministic entropy stream for the specific site and user context.

### Step D: Password Generation & Complexity
The HMAC signature is used to select characters from a charset:
1.  **Uniform Sampling**: To avoid "modulo bias," the code uses rejection sampling. It draws bytes from the HMAC stream and only accepts those that fall within a range that can be evenly divided by the charset size.
2.  **Complexity Enforcement**: To satisfy website requirements, the algorithm ensures at least one uppercase, lowercase, digit, and special character are present. It uses the entropy stream to pick random (but deterministic) positions for these required characters.

## 3. The "Fill" Workflow & Security

SMP Nano uses a multi-stage process to move the generated password into the web page securely:

1.  **In-Memory Cache**: The Service Worker stores the generated password in a `Map` keyed by `tabId`. This cache is **short-lived** (expires in 20 seconds) and is **never persisted** to disk.
2.  **Context Verification (TOCTOU)**: When the user clicks "Fill", the Service Worker checks:
    *   Does the password still exist in the cache for this `tabId`?
    *   Is the current URL of the tab still the same as when the password was generated?
3.  **Secure Messaging**: If verified, the Service Worker sends the password to the `content.js` script in the active tab via `chrome.tabs.sendMessage`.
4.  **Injection**: `content.js` performs final checks:
    *   Is the page running over **HTTPS**?
    *   Is the script running in the **top-level frame** (not an iframe)?
5.  **DOM Interaction**: If all checks pass, it finds the first `<input type="password">` and injects the value, triggering `input` and `change` events to ensure the website's JavaScript recognizes the entry.
6.  **Cleanup**: The password is deleted from the Service Worker's cache immediately after a successful fill or upon timeout.

## 4. Security Measures Summary

| Feature | Implementation |
| :--- | :--- |
| **No Persistence** | No data is ever saved to `chrome.storage` or `localStorage`. |
| **Domain Separation** | The domain is included in both the PBKDF2 salt and the HMAC message, ensuring a breach on one site doesn't compromise others. |
| **Phishing Protection** | Warns on punycode domains and suspicious hostname patterns. |
| **Anti-Clickjacking** | Refuses to fill in iframes. |
| **Entropy Integrity** | Uses rejection sampling to ensure truly uniform character distribution. |
