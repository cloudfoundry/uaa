# Login Consent

The Login Consent feature displays a mandatory modal on the UAA login page. Users must accept the displayed terms/notice (or follow a decline link) before they can interact with the login form. This is **separate from** the OAuth approval/consent flow; it is a pre-login notice (e.g., terms of use or acceptable use policy) configured per identity zone.

**Important**: This is a **UI-only verified consent** mechanism. The consent acceptance is tracked client-side via cookies and is not verified or enforced on the server side during authentication. It serves as a notice/acknowledgment interface rather than a security control.

## Overview

- **Scope**: Configured per identity zone under `branding.loginConsent`.
- **Behavior**: When enabled, the login page shows a modal with a configurable title, HTML body text, an “Accept” button, and an optional “Decline” link. Consent state is remembered in a cookie for a configurable duration; if the consent text changes or the duration expires, the modal is shown again.
- **Implementation**: Server provides config and a content hash; the browser shows/hides the modal and sets a cookie (`UAA-Login-Consent`) with format `hash:timestamp` to avoid re-prompting until content or duration changes.
- **Verification Level**: **Client-side only** - consent acceptance is tracked via browser cookies and is not validated during server-side authentication flows.

---

## Configuration

Login consent is part of zone branding. Example (e.g. in `uaa.yml` or zone config API):

```yaml
branding:
  loginConsent:
    enabled: true
    title: "Notice and Consent"
    text: |
      <p>You are accessing a site that is provided for authorized use only.</p>
      <p>By using this site, you consent to the following conditions:</p>
      <ul>
        <li>You are responsible for compliance with all applicable laws and regulations.</li>
        <li>All communications are subject to routine monitoring and may be disclosed.</li>
      </ul>
    acceptButtonText: "I Accept"
    declineButtonText: "Decline"               # text for decline button when declineLink is provided
    declineLink: https://example.com/decline   # optional; if absent, a Cancel button is shown
    consentValidDuration: "15m"                # how long acceptance is remembered
```

### Configuration Fields

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | boolean | `false` | When `true`, the login consent modal is active for the zone. |
| `title` | string | `"Terms and Conditions"` | Modal heading. Has default value but must not be empty if explicitly set. |
| `text` | string | — | Body content; **HTML is allowed** (rendered with `th:utext`). Required when enabled. |
| `acceptButtonText` | string | `"I Agree"` | Label for the accept button. Has default value but must not be empty if explicitly set. |
| `declineButtonText` | string | `"Decline"` | Label for the decline button when `declineLink` is provided. Has default value but must not be empty if explicitly set. |
| `declineLink` | string | — | Optional. If set, must be a valid `http` or `https` URL; shown as a “Decline” link. If unset, a “Cancel” button is shown (modal can be re-shown on next load). |
| `consentValidDuration` | string | `"1d"` | How long acceptance is remembered. After this period, or if consent text changes, the modal is shown again. |

### Duration Format

`consentValidDuration` supports:

- **`0`** – Always show the modal (do not remember acceptance).
- **`<number><unit>`** – Remember acceptance for the given amount of time.  
  Units: `m` (minutes), `h` (hours), `d` (days), `w` (weeks), `y` (years).  
  Examples: `15m`, `12h`, `7d`, `1w`.

Invalid or missing duration falls back to 24 hours.

---

## Validation

`LoginConsentValidator` is used when zone configuration is saved (e.g. via `GeneralIdentityZoneConfigurationValidator`):

- If `loginConsent` is `null` or `enabled` is `false`, no validation is applied.
- When **enabled**:
  - `text` is **required** (no default value).
  - `title`, `acceptButtonText`, and `declineButtonText` must not be empty if explicitly set (they have default values).
  - If present, `declineLink` must be a valid HTTP/HTTPS URL.
  - If present, `consentValidDuration` must be `0` or a positive number followed by `m`, `h`, `d`, or `w`.

Errors are reported as part of zone config validation (e.g. `InvalidIdentityZoneConfigurationException`).

---

## Server-Side Behavior

### Model and placement

- **Model**: `org.cloudfoundry.identity.uaa.zone.LoginConsent` (under `model`).
- **Zone config**: `IdentityZoneConfiguration` → `BrandingInformation` → `LoginConsent` (`getLoginConsent()` / `setLoginConsent()`).

### LoginInfoEndpoint

When rendering the login page (HTML), `LoginInfoEndpoint` calls `addLoginConsentToModel(model)`:

1. Reads `zone.getConfig().getBranding().getLoginConsent()`.
2. If present and `enabled`:
   - Adds `loginConsent` (the config object) to the model.
   - Adds `loginConsentHash` via `LoginConsentHashUtil.calculateConsentHash(loginConsent)` (SHA-256 of `title|text`).
   - Adds `loginConsentDurationSeconds` via `LoginConsentHashUtil.parseDurationToSeconds(consentValidDuration)`.

These attributes are used by the login template and the client-side script.

### Consent hash

`LoginConsentHashUtil.calculateConsentHash(LoginConsent)`:

- Returns `null` if consent is `null` or disabled.
- Otherwise computes SHA-256 of `title + "|" + text` (empty string if null) and returns the hex string.
- Used to detect when consent text has changed so the modal can be shown again even if the cookie is still within its duration.

---

## Frontend Behavior

### Template (login.html)

- If `loginConsent != null`, the page includes:
  - `login-consent.css`
  - `consent.js`
- A modal element `#loginConsentModal` is rendered with:
  - `data-consent-hash`: current consent hash
  - `data-consent-duration`: duration in seconds (for cookie `max-age`)
  - Title from `loginConsent.title`, body from `loginConsent.text` (HTML), and buttons from `acceptButtonText` and `declineButtonText` (when `declineLink` is provided) or a Cancel button.

### Cookie

- **Name**: `UAA-Login-Consent`
- **Value**: `hash:timestamp` (e.g. `abc123...:1710000000`)
- **Path**: Same as the login page path (e.g. `/login` or `/uaa/login`).
- **Attributes**: `SameSite=Strict`, `Secure` on HTTPS. `max-age` set from `loginConsentDurationSeconds` when duration &gt; 0; no `max-age` when duration is 0.

### consent.js

- On `DOMContentLoaded`:
  - **Should show modal?**  
    Yes if: no modal element, or duration is `0`, or no cookie, or cookie value is not `hash:timestamp`, or stored hash ≠ current `data-consent-hash`, or `(now - timestamp) > consentDuration` (when duration &gt; 0).
  - If the modal should be shown:
    - Binds Accept button to set cookie (when duration &gt; 0) and close modal.
    - Cancel/Decline: Cancel closes and re-opens modal after 100 ms (user cannot proceed without accepting or using the decline link). Decline uses `declineLink` to leave the page.
    - Prevents closing via overlay click or Escape.
  - Modal is shown with `display: flex` and focus moved to the accept button.

So the modal is blocking until the user either accepts (and optionally gets a cookie) or follows the decline link.

---

## Files Involved

| Area | File | Role |
|------|------|------|
| Model | `model/.../zone/LoginConsent.java` | Config POJO for login consent. |
| Model | `model/.../zone/BrandingInformation.java` | Holds `loginConsent`. |
| Server | `server/.../login/LoginInfoEndpoint.java` | Adds consent config and hash/duration to login model. |
| Server | `server/.../login/LoginConsentHashUtil.java` | Consent hash (SHA-256 of title+text) and duration parsing. |
| Server | `server/.../zone/LoginConsentValidator.java` | Validates `LoginConsent` when enabled. |
| Server | `server/.../zone/GeneralIdentityZoneConfigurationValidator.java` | Invokes `LoginConsentValidator` for zone config. |
| Server | `server/.../templates/web/login.html` | Renders consent modal and includes CSS/JS when `loginConsent != null`. |
| Webapp | `uaa/.../javascripts/login_consent/consent.js` | Modal show/hide logic and cookie handling. |
| Webapp | `uaa/.../stylesheets/login-consent.css` | Styles for the consent modal (including responsive and a11y). |

---

## Security and UX Notes

- **Client-side verification only**: This feature provides UI-level consent tracking but does not enforce consent at the server authentication level. Do not rely on this mechanism for security-critical consent verification.
- Consent text is rendered as HTML (`th:utext`); only trusted, zone-controlled content should be used to avoid XSS.
- The cookie is used only to avoid re-prompting; it does not by itself grant access. Authentication still requires successful login.
- Decline link should point to a safe, zone-approved URL (e.g. exit or policy page).
- Modal is non-dismissible (no overlay click or Escape) except via Accept or Decline/Cancel, so users cannot bypass the notice.
