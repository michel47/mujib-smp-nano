# Release Note: SMP Nano v1.0.0

## Summary of Improvements (Commit 4d54b6e)

This release significantly enhances the security architecture, phishing resistance, and user experience of the SMP Nano extension. Key improvements include:

### 🔐 Security & Cryptography
*   **Secure Process Separation**: Password derivation logic has been moved from the popup UI to a dedicated **Service Worker**, minimizing exposure of the master secret and generated passwords within the UI process.
*   **Uniform Entropy Distribution**: Replaced modulo-based character selection with **rejection sampling** (uniform charset encoding) to eliminate statistical bias in password generation.
*   **Enhanced Complexity Enforcement**: Complexity requirements (uppercase, lowercase, digits, symbols) are now enforced using **entropy-driven positions** rather than fixed locations, increasing the unpredictability of the generated strings.
*   **TOCTOU (Time-of-Check to Time-of-Use) Protection**: Password generation is now cryptographically bound to a specific tab and domain snapshot. The extension re-verifies these parameters before filling to prevent attacks involving rapid navigation or tab switching.
*   **Strict Context Controls**: Password filling is now restricted to **HTTPS-only** contexts and **top-level frames**, mitigating clickjacking and MitM risks.

### 🛡️ Phishing Resistance
*   **Domain Transparency**: The target domain is now prominently displayed in the UI during generation.
*   **Heuristic Warnings**: Implemented basic phishing detection, including warnings for punycode (IDN) domains and suspicious hostname patterns.
*   **Context Validation**: The extension now detects and warns the user if the tab or page URL changes after a password has been generated but before it is filled.

### ✨ User Experience
*   **Master Secret Validation**: Added real-time validation for the master secret to ensure it meets minimum length and complexity standards.
*   **Improved UI Feedback**: The "Generate" button now provides visual confirmation ("Generated") upon success, and informative alerts are shown if no password field is detected on the page.
*   **Privacy-First Display**: The generated password is no longer shown by default in the UI, reducing the risk of shoulder-surfing.
*   **Auto-Clear Clipboard**: Optional 30-second auto-clear for the clipboard after a copy operation.

---

## Technical Debt & Future Roadmap
*   **Public Suffix List (PSL)**: Future versions will transition to a full PSL-based domain normalization for more robust eTLD+1 identification.
*   **Field Heuristics**: Ongoing improvements to form-field detection for complex, modern web applications.
