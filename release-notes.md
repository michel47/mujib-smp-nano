# Release Notes: SMP Nano

## v1.0.1 (2026-02-17)
### ✨ New Features
*   **Policy-Based Access Control (PBAC)**: Centralized security decisions in the Service Worker using `policy.json`.
*   **Smart Sequential Fill**: Intelligent password injection that prioritizes empty fields and batches confirmation fields.
*   **Bidirectional Username Sync**: Automatically syncs usernames between the web page and the extension popup.
*   **"Paste & Clear" Security**: Automatically wipes the clipboard after pasting a password into a target field.
*   **Automated Counter Rotation**: Calculates counter values based on license release and expiry dates.
*   **Dynamic UI Header**: Displays app icon, version, and policy release date in the popup.
*   **Master Secret Toggle**: Added a "peek" icon (👁️) to temporarily reveal the master secret.

### 🛡️ Security & Robustness
*   **HKDF Entropy Expansion**: Supports generation of long passwords (up to 64 chars) without entropy exhaustion.
*   **DOM Hardening**: Uses prototype setters to bypass property shadowing by malicious scripts.
*   **Context-Aware Reset**: Automatically clears the master secret when navigating to sensitive `new-password` fields.
*   **Mockup Suite**: Included HTML templates for local verification of all fill scenarios.

---

## v1.0.0 (2026-02-15)
### Initial Release
*   **Vaultless Derivation**: PBKDF2-HMAC-SHA256 based password manager.
*   **Phishing Heuristics**: Basic detection for punycode and suspicious hostnames.
*   **Process Separation**: Core crypto moved to background service worker.
*   **Complexity Enforcement**: Deterministic injection of required character categories.
