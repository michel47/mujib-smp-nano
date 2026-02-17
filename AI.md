# AI Coding Constitution: SMP Nano

This document defines the mandatory guidelines and design principles for any AI agent contributing to the SMP Nano project. Adherence ensures security, reliability, and maintainability.

## 1. Core Architectural Mandates

*   **Vaultless Principle**: Never persist sensitive data (master secrets, passwords) to `chrome.storage`, `localStorage`, or disk. All state must be in-memory and short-lived.
*   **Process Separation**: 
    *   **Popup**: UI interaction and input validation only.
    *   **Service Worker**: Cryptographic core and temporary cache.
    *   **Content Script**: DOM interaction and field injection.
*   **No Silent Failures**: If a page is insecure (HTTP) or suspicious (Phishing), do not simply disable the tool. Provide clear, color-coded feedback to the user and switch to **Decoy Mode**.
*   **Decoy Mode**: High-risk contexts must use a distinct salt (`smd-nano-decoy`) to ensure the generated password is deterministic but mathematically separate from the legitimate site's password.

## 2. Security & Cryptography Standards

*   **Web Crypto API Only**: Use `crypto.subtle` for all cryptographic operations. Never implement custom crypto logic or use insecure libraries.
*   **Key Hardening**: Use **PBKDF2-HMAC-SHA256** with at least 200,000 iterations for base key derivation.
*   **Entropy Expansion**: Use **HKDF** to expand short keys into larger entropy pools to prevent "entropy exhaustion" in long passwords.
*   **Uniformity**: Always use **rejection sampling** (e.g., `pickUniform`) to avoid modulo bias when selecting characters or positions.
*   **TOCTOU Protection**: Re-verify tab URL and domain snapshots immediately before password injection to prevent race-condition attacks.

## 3. Coding Style & Patterns

*   **Sanitization**: Never use `.innerHTML` for dynamic content. Use `.textContent` or `document.createTextNode` to prevent UI-spoofing and XSS within the extension.
*   **DOM Hardening**: When injecting values into page elements, use direct prototype setters (e.g., `Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value').set`) to bypass "property shadowing" by malicious page scripts.
*   **Domain Normalization**: Always strip `www.` and prepare for Public Suffix List (PSL) integration. Never treat the protocol as part of the salt.

## 4. Commenting & Documentation

*   **No Placeholders**: NEVER replace functional code with comment placeholders (e.g., `// ... logic here ...`). Every edit must result in fully operational code.
*   **No Simulation Code**: Do not inject mockup or simulation logic into the production files (`sw.js`, `content.js`, `popup.js`) unless explicitly requested for testing purposes.
*   **Preserve Context**: Never remove existing comments that explain design principles or architectural decisions.
*   **Explain the "Why"**: Comments should focus on the *security rationale* (e.g., "Using rejection sampling to avoid modulo bias") rather than just describing the code.
*   **Roadmap Tagging**: Use `// TODO (production):` to clearly mark areas where the current implementation is an MVP but requires future hardening (e.g., PSL integration).
*   **Educational Value**: Maintain a high standard of clarity in comments to ensure the codebase remains an accessible learning resource for secure extension development.

## 5. User Transparency

*   **Explicit Labels**: Clearly label generated passwords as "DECOY" when security heuristics are triggered.
*   **Feedback loops**: Alert the user if the tab or page context changes during the generation/fill workflow.
*   **No Hidden State**: Ensure the user can see exactly which domain the extension is targeting for derivation.

## 6. File Editing & VCS (RCS) Workflow

To prevent errors and maintain version control system (RCS) integrity:

*   **Checkout & Lock**: Before ANY modification, always acquire a lock using `getlock <file_path>` or `co -l <file_path>`. If the file already exists locally and is writable, rename it first (e.g., `mv <file_path> <file_path>.bak`) to bypass interactive prompts during checkout.
*   **Temporary Buffer Editing**: Always perform modifications in a temporary buffer. Do not directly edit the checked-out file.
*   **Atomic Update**: Once edits are finalized in the buffer, update the content of the checked-out file in a single operation (e.g., by copying the buffer content to the file).
*   **Commit**: After implementing changes, commit the updated file using `ci -w"aiagent" -m"<concise_and_clear_commit_message>" <file_path>`. **Ensure the commit message is properly quoted to avoid shell interpretation errors.** For example: `ci -w"aiagent" -m"Update AI.md: Add explicit RCS commit message format guideline." AI.md`.
