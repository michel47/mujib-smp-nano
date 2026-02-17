# Code Review: SMP Nano (Vaultless Password Manager)

## Overview
SMP Nano is a Chrome extension designed as a "vaultless" password manager. Instead of storing passwords in a database, it derives them deterministically from a master secret and site-specific context (domain, username, counter).

## Security Architecture

### 1. Process Separation
The project effectively separates concerns across three layers:
*   **Popup (`popup.js`)**: Handles user interaction and basic input validation. It never performs the actual cryptographic derivation.
*   **Service Worker (`sw.js`)**: Acts as the secure core. It performs PBKDF2/HMAC operations and maintains a short-lived, in-memory cache of the generated password.
*   **Content Script (`content.js`)**: Responsible for interacting with the DOM to fill password fields. It only receives the password via a secure message from the service worker after multiple context checks.

### 2. Threat Mitigations
*   **HTTPS Enforcement**: The extension refuses to generate or fill passwords on non-HTTPS sites, protecting against MitM attacks.
*   **TOCTOU Protection**: The service worker re-verifies the active tab's URL immediately before filling to ensure the user hasn't navigated to a different site between generation and filling.
*   **Phishing Detection**: Includes heuristics to warn users about punycode (IDN) domains and suspicious domain patterns (excessive hyphens, unusual length).
*   **In-Memory Only**: Passwords and secrets are never persisted to `chrome.storage` or `localStorage`. The master secret is cleared from the UI immediately after use.

## Cryptographic Implementation

### Key Derivation
The derivation process is robust:
1.  **PBKDF2**: Uses 200,000 iterations of SHA-256 to derive a base key from the master secret.
2.  **HMAC-SHA-256**: Uses the PBKDF2 output as a key to sign a message containing the domain, username, and counter. This provides a high level of domain separation.

### Password Generation
*   **Uniform Sampling**: The `pickUniform` function uses rejection sampling to avoid modulo bias, ensuring that all characters in the charset have an equal probability of being chosen.
*   **Complexity Enforcement**: The `enforceComplexityUpdated` function deterministically ensures that generated passwords contain at least one lowercase letter, uppercase letter, digit, and symbol, satisfying common website requirements.

## Strengths
*   **Statelessness**: No sync, no cloud, no local database to be breached.
*   **Modern Crypto**: Correct use of the Web Crypto API (`SubtleCrypto`).
*   **Security-First Design**: Proactive measures against clickjacking, phishing, and context-switching attacks.

## Areas for Improvement

### 1. Domain Normalization
The current normalization (`hostname.replace(/^www\./, "")`) is insufficient. It does not correctly handle subdomains (e.g., `login.example.com` vs `example.com`) or complex TLDs (e.g., `example.co.uk`). 
*   **Recommendation**: Integrate a Public Suffix List (PSL) parser to consistently identify the eTLD+1.

### 2. Entropy Stream Length
HMAC-SHA-256 produces a 32-byte (256-bit) output. While sufficient for most passwords, a combination of a long requested password length (e.g., 64 chars) and many rejections during uniform sampling could theoretically exhaust the entropy stream.
*   **Recommendation**: Use HKDF to expand the 32-byte HMAC output into a longer deterministic stream if needed.

### 3. Password Field Detection
The current `document.querySelector('input[type="password"]')` is a naive approach. Many modern sites use complex DOM structures, shadow roots, or dynamically injected fields.
*   **Recommendation**: Implement more robust heuristics for field detection and add support for filling usernames.

### 4. UI/UX
The interface is functional but basic. 
*   **Recommendation**: Improve visual feedback (e.g., strength meter for master secret, clearer error messaging) and add a "view" toggle for the master secret input.

## Conclusion
SMP Nano is a well-architected, security-conscious utility that follows cryptographic best practices. Its vaultless nature eliminates a large class of risks associated with traditional password managers. With improved domain normalization and more robust form-filling logic, it would be a highly reliable tool for security-minded users.
