# Release Notes: SMP Nano v1.0.1

**Date:** February 17, 2026

**Summary of Changes:**

This release introduces significant improvements to security, policy management, user experience, and robustness. It incorporates advanced ACL rules, better handling of password fields, dynamic header information, and refined error reporting.

### **✨ New Features & Major Improvements:**

*   **Centralized Policy Engine (ACL)**:
    *   Implemented a robust policy engine in the Service Worker, driven by `policy.json` (formerly `accesslist.json`).
    *   Supports `DENY+ALLOW+EXCEPT` and `ALLOW+DENY+EXCEPT` modes for granular control.
    *   Allows URL pattern matching for `allow`, `deny`, `except` rules, and custom salt overrides (e.g., `'smd-nano-mockup'` for `localhost`, `'smd-nano-files'` for `file://`).
    *   Policy evaluation is now centralized and respected by Popup and Content Script, removing hard-coded exceptions.
    *   Introduced `trusted_contexts` to explicitly define secure environments.
*   **Intelligent Password Field Filling**:
    *   **Smart Sequential Fill**: Re-implemented the smart sequential fill logic. It now targets one field at a time unless it detects an identical confirmation field (e.g., "Confirm Password" with the same `autocomplete` attribute), in which case it fills both.
    *   **Username Consistency**: The logic for username extraction and synchronization is now fully operational.
    *   **Visual Decoration**: Briefly highlight the target field in Chrome Green (4px) during the fill operation to make it obvious to the user.
*   **Context-Aware Master Password Reset**:
    *   If the focus shifts from a non-`new-password` field to a `new-password` field, the extension automatically clears the master password field in the popup to ensure sensitive data is cleared when the context shifts to a critical password update.
*   **License Expiration & Counter Logic**:
    *   Automated counter calculation based on license creation and expiry dates (`created_at`, `license_expiry`).
    *   Restricts counter increment past expiration if `license_status` is "EXPIRED".
    *   Uses a dedicated `'smd-nano-expired'` salt for expired licenses.
    *   Generates a fixed Passmoji `🚫` for expired licenses.
    *   Sets counter to `expirationCounter + 1` for `new-password` fields when license is valid, promoting fresh passwords.
*   **Dynamic Header Information**: The popup now dynamically displays the app icon (`1f6e1g.svg`), title, version (from `manifest.json`), and policy creation date (from `policy.json`).
*   **Enhanced Clipboard Security**: Implemented "Paste & Clear" functionality. After pasting into a password field, the clipboard is automatically cleared. A manual "Clear" button remains for explicit user control.
*   **Improved Target Field Hinting**: The target field hint (e.g., `Target: new-password (reg_pass)`) is now more descriptive and displayed clearly with the generation status.

### **🚀 Improvements:**

*   **UI/UX Refinements**:
    *   Optimized Tab navigation (`tabindex`) for a smoother workflow: Username -> Master Secret -> Generate.
    *   Added a "peek" icon (👁️) to the master secret input to toggle visibility.
    *   Improved status messages and visual feedback.
    *   Passmoji is now integrated into the "Fill" button text.
*   **Code Quality & Safety**:
    *   Restored functional code in `content.js` and `popup.js` where placeholders were previously used.
    *   Enhanced debug logging in SW and Popup for better diagnostics.
    *   Refined `isHttps()` check in `content.js` to correctly include `localhost`, `127.0.0.1`, and `file://` protocols.
    *   Ensured proper async messaging handling in `content.js`.

### **✅ Bug Fixes:**

*   Fixed UI timing issue where target hint was overwritten.
*   Ensured `localhost` and `file://` URLs are correctly handled by the policy engine and don't lead to "Fill refused".
*   Corrected ACL evaluation logic to ensure `EXCEPT` rules properly override `DENY` rules in `DENY+ALLOW+EXCEPT` mode.
