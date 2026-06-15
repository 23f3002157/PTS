# 1. Score Board

- **Finding ID:** JS-01
- **Target:** `/#/score-board`
- **Title:** Hidden Score Board Discovery
- **Vulnerability Type:** Security Misconfiguration / Improper Access Control

**Brief:**
The score board page is hidden from navigation but accessible via direct URL. Finding it is itself a challenge testing whether users enumerate application routes.

**Payload:**

```text
Navigate directly to /#/score-board
```

**CVSS Score:** 2.7 (Low) — `CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:L/I:N/A:N`

**Remediation:**
Restrict sensitive pages behind authentication and avoid security through obscurity.

**Rationale:**
Hidden pages that rely solely on obscurity for protection violate defense-in-depth principles.

**References:**
OWASP A05:2021 – Security Misconfiguration

---

# 2. DOM XSS

- **Finding ID:** JS-02
- **Target:** Search bar (`/#/search?q=`)
- **Title:** DOM-Based Cross-Site Scripting
- **Vulnerability Type:** XSS — DOM-Based

**Brief:**
User input is reflected into the DOM without sanitization, allowing script execution in the victim's browser context.

**Payload:**

```html
<iframe src="javascript:alert(`xss`)">
```

**CVSS Score:** 6.1 (Medium) — `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N`

**Remediation:**

- Use `textContent` instead of `innerHTML`
- Implement a strict Content Security Policy
- Sanitize all user-controlled input before DOM insertion

**Rationale:**
DOM XSS bypasses server-side filters entirely since the payload never reaches the server.

**References:**

- OWASP A03:2021 – Injection
- CWE-79

---

# 3. Bonus Payload

- **Finding ID:** JS-03
- **Target:** Search bar (`/#/search?q=`)
- **Title:** DOM XSS — Bonus Payload (Embedded Media)
- **Vulnerability Type:** XSS — DOM-Based

**Brief:**
Extension of the DOM XSS challenge using a more complex iframe payload embedding external media, demonstrating that XSS payloads aren't limited to `alert()`.

**Payload:**

```html
<iframe width="100%" height="166" scrolling="no" frameborder="no" allow="autoplay"
src="https://w.soundcloud.com/player/?url=https%3A//api.soundcloud.com/tracks/771984076&color=%23ff5500&auto_play=true&hide_related=false&show_comments=true&show_user=true&show_reposts=false&show_teaser=true"></iframe>
```

**CVSS Score:** 6.1 (Medium) — `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N`

**Remediation:**
Same as JS-02. CSP should block external frame sources via `frame-src`.

**Rationale:**
Real-world XSS attacks embed malicious content or exfiltrate data — not just `alert()`.

**References:**

- OWASP A03:2021 – Injection
- CWE-79

---

# 4. Reflected XSS

- **Finding ID:** JS-04
- **Target:** Order tracking page (`/#/track-result?id=`)
- **Title:** Reflected Cross-Site Scripting
- **Vulnerability Type:** XSS — Reflected

**Brief:**
A URL parameter is reflected back into the page response without encoding, allowing an attacker to craft a malicious link that executes script in the victim's browser.

**Payload:**

```html
<iframe src="javascript:alert(`xss`)">
```

Delivered via:

```text
/#/track-result?id=<payload>
```

**CVSS Score:** 6.1 (Medium) — `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N`

**Remediation:**

- HTML-encode all reflected input
- Implement CSP headers
- Use X-XSS-Protection header

**Rationale:**
Reflected XSS is commonly used in phishing attacks where victims click crafted links.

**References:**

- OWASP A03:2021 – Injection
- CWE-79

---

# 5. Login Admin

- **Finding ID:** JS-05
- **Target:** `/#/login → POST /rest/user/login`
- **Title:** SQL Injection Authentication Bypass — Admin Account
- **Vulnerability Type:** SQL Injection — Authentication Bypass

**Brief:**
The login form is vulnerable to classic SQL injection, allowing authentication bypass without knowing the admin password.

**Payload:**

```text
Email:    ' OR 1=1--
Password: anything
```

**CVSS Score:** 9.8 (Critical) — `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`

**Remediation:**
Use parameterized queries / prepared statements. Never concatenate user input into SQL strings.

**Rationale:**
Authentication bypass via SQLi gives full admin access, the highest-impact injection class.

**References:**

- OWASP A03:2021 – Injection
- CWE-89

---

# 6. Login MC SafeSearch

- **Finding ID:** JS-06
- **Target:** `/#/login`
- **Title:** Credentials Exposed via Public OSINT (Social Engineering)
- **Vulnerability Type:** Sensitive Data Exposure / OSINT

**Brief:**
MC SafeSearch's password is derivable from publicly available information (a YouTube music video where he sings about his password). No technical exploit required.

**Payload:**

```text
Credentials: mc.safesearch@juice-sh.op / Mr. N00dles
```

**CVSS Score:** 5.3 (Medium) — `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`

**Remediation:**

- Enforce strong, unique password policies
- Conduct user security awareness training
- Implement MFA

**Rationale:**
Demonstrates that weak passwords derived from personal information are trivially discoverable via OSINT.

**References:**

- OWASP A07:2021 – Identification and Authentication Failures
- CWE-521

---
