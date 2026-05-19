# Finding Hidden Dashboard / Scoreboard / Challenge Pages
### A Complete Systematic Manual — From Network Scan to Page Discovery

> **Purpose:** After running nmap and identifying live hosts and open ports, this manual gives you a complete, ordered procedure to find any hidden dashboard, scoreboard, challenge page, or admin panel — across every known OWASP project, CTF platform, and custom web application.
>
> **Rule:** Work through every layer in order. Do not skip layers. The page will be found by one of them.

---

## Table of Contents

1. [The Mental Model — Why Pages Are Hidden](#1-the-mental-model--why-pages-are-hidden)
2. [Layer 0 — Start Here: Read Your nmap Output](#2-layer-0--start-here-read-your-nmap-output)
3. [Layer 1 — Application Identification](#3-layer-1--application-identification)
4. [Layer 2 — Known Application Lookup](#4-layer-2--known-application-lookup)
5. [Layer 3 — Passive Recon (Before Touching the App)](#5-layer-3--passive-recon-before-touching-the-app)
6. [Layer 4 — Manual Obvious Path Checks](#6-layer-4--manual-obvious-path-checks)
7. [Layer 5 — Page Source & JavaScript Analysis](#7-layer-5--page-source--javascript-analysis)
8. [Layer 6 — API & Documentation Endpoints](#8-layer-6--api--documentation-endpoints)
9. [Layer 7 — Cookie & Header Analysis](#9-layer-7--cookie--header-analysis)
10. [Layer 8 — Directory Brute Force (dirb / wfuzz)](#10-layer-8--directory-brute-force-dirb--wfuzz)
11. [Layer 9 — ZAP Spidering](#11-layer-9--zap-spidering)
12. [Layer 10 — Burp Suite Passive Capture](#12-layer-10--burp-suite-passive-capture)
13. [Layer 11 — Authenticated Scanning (Post-Login)](#13-layer-11--authenticated-scanning-post-login)
14. [Layer 12 — Parameter & ID Fuzzing](#14-layer-12--parameter--id-fuzzing)
15. [Layer 13 — Framework-Specific Tricks](#15-layer-13--framework-specific-tricks)
16. [Layer 14 — Error-Based Discovery](#16-layer-14--error-based-discovery)
17. [OWASP Project Scoreboard Reference — All Known Pages](#17-owasp-project-scoreboard-reference--all-known-pages)
18. [Complete Decision Flowchart](#18-complete-decision-flowchart)
19. [Master Command Cheatsheet](#19-master-command-cheatsheet)

---

## 1. The Mental Model — Why Pages Are Hidden

Before running a single command, understand **why** a scoreboard or challenge page is hidden. There are five reasons, each requiring a different discovery method:

```
┌─────────────────────────────────────────────────────────────────────────┐
│              WHY A PAGE IS HIDDEN — AND HOW TO FIND IT                  │
├───────────────────────────┬─────────────────────────────────────────────┤
│ REASON                    │ DISCOVERY METHOD                            │
├───────────────────────────┼─────────────────────────────────────────────┤
│ 1. Not linked in the UI   │ dirb / wfuzz brute force, ZAP spider        │
│    (exists but invisible) │                                             │
├───────────────────────────┼─────────────────────────────────────────────┤
│ 2. Route defined in JS    │ Grep JS bundles for route definitions       │
│    but no nav link        │ (critical for SPAs like Juice Shop)         │
├───────────────────────────┼─────────────────────────────────────────────┤
│ 3. Requires authentication│ Log in first, then re-scan authenticated    │
│    before it appears      │                                             │
├───────────────────────────┼─────────────────────────────────────────────┤
│ 4. Known app with         │ Google it / check known-apps reference      │
│    documented hidden page │ table — 30 second lookup                    │
├───────────────────────────┼─────────────────────────────────────────────┤
│ 5. Custom app — page name │ Full brute force + source grep +            │
│    is unpredictable       │ error-based discovery                       │
└───────────────────────────┴─────────────────────────────────────────────┘
```

Your entire strategy is: **identify which of these 5 cases you're in, then apply the matching method.**

---

## 2. Layer 0 — Start Here: Read Your nmap Output

### You have already run:
```bash
nmap -sn 192.168.X.0/24                              # host discovery
nmap -sV -sC -p- --open -T4 <TARGET-IP> -oN scan.txt # full port scan
```

### Now extract maximum information from that output before touching anything else.

**Check 1 — What port is the web app on?**
```bash
grep -E "open|http|ssl|tcp" scan.txt
# Look for: 80, 443, 8080, 8443, 3000, 5000, 8000, 8888, or any non-standard port
```

**Check 2 — Does nmap already tell you the app name?**
```bash
grep -iE "title|server|location|powered|cookie|copyright|html" scan.txt
# -sC grabs the HTTP title and server header automatically
# Look for:
#   http-title: Juice Shop        → OWASP Juice Shop
#   http-title: Security Shepherd → OWASP Security Shepherd
#   http-title: DVWA              → Damn Vulnerable Web Application
#   Server: Werkzeug              → Flask/Python custom app
#   commonName=OwaspShepherd      → SSL cert naming Shepherd
#   X-Recruiting: /#/jobs         → Juice Shop signature header
```

**Check 3 — Is SSL/TLS in use?**
```bash
grep -i "ssl\|tls\|https\|443" scan.txt
# If yes → add -k to all curl commands, use -S in dirb, use --hc 404 in wfuzz
```

**Check 4 — Read the SSL certificate if HTTPS:**
```bash
openssl s_client -connect TARGET:PORT </dev/null 2>/dev/null | grep -E "CN=|O=|subject"
# The commonName often contains the application name:
# CN=OwaspShepherd     → Security Shepherd
# CN=localhost         → custom/generic
# CN=JuiceShop         → Juice Shop
```

**Check 5 — Grep for any redirect location:**
```bash
grep -i "location:" scan.txt
# If it redirects to /login.jsp → Java app (Shepherd, WebGoat)
# If it redirects to /#/        → Angular SPA (Juice Shop)
# If it redirects to /login     → Generic (Flask, PHP, Node)
```

**After Layer 0 you should know:**
- The target IP and port
- Whether it uses HTTP or HTTPS
- Possibly the application name already
- The framework/stack (Java, Python, Node, PHP)

---

## 3. Layer 1 — Application Identification

### Step 1 — Read HTTP Headers
```bash
# HTTP
curl -I http://TARGET:PORT

# HTTPS (ignore cert)
curl -Ik https://TARGET:PORT

# Verbose — shows full handshake and headers
curl -Ikv https://TARGET:PORT 2>&1 | grep -E "^[<>]|Server:|X-Powered|Content-Type|Location|Set-Cookie"
```

**What each header tells you:**

| Header | Value | Application |
|---|---|---|
| `Server` | `Werkzeug/3.x Python/3.x` | Flask — custom Python app |
| `Server` | `Apache/2.x` | PHP app or Java on Apache |
| `Server` | `Apache-Coyote` | Apache Tomcat — Java |
| `X-Powered-By` | `Express` | Node.js app |
| `X-Powered-By` | `PHP/7.x` | PHP app |
| `X-Recruiting` | `/#/jobs` | OWASP Juice Shop (100% confirmed) |
| `Set-Cookie` | `JSESSIONID=...` | Java servlet container |
| `Set-Cookie` | `session=...` | Flask or generic |
| `Set-Cookie` | `PHPSESSID=...` | PHP app |
| `Content-Type` | `text/html; charset=UTF-8` | Generic — check title |

### Step 2 — whatweb (Full Stack Fingerprint in One Command)
```bash
whatweb http://TARGET:PORT -v
whatweb https://TARGET:PORT --no-errors -v

# Output shows: CMS, framework, JavaScript libraries, jQuery version,
# server version, cookies, meta tags, title — everything in one pass
```

### Step 3 — Read the Page Title
```bash
curl -s http://TARGET:PORT | grep -i "<title"
# Examples:
# <title>Juice Shop</title>          → OWASP Juice Shop
# <title>Security Shepherd</title>   → OWASP Security Shepherd
# <title>DVWA</title>                → DVWA
# <title>NanoCorp Bites</title>      → Custom Flask app
# <title>WebGoat</title>             → OWASP WebGoat
```

### Step 4 — Check the Page Source for Copyright / Branding
```bash
curl -s http://TARGET:PORT | grep -iE "copyright|powered by|version|generator|bjoern|kimminich|shepherd|webgoat|dvwa|owasp"
# Juice Shop: "Copyright (c) 2014-2024 Bjoern Kimminich"
# Shepherd:   "OWASP Security Shepherd"
# WebGoat:    "WebGoat"
```

### Decision After Layer 1:
```
Do you know the application name?
    YES → Go to Layer 2 (Known App Lookup) immediately
    NO  → Continue to Layer 3 (Passive Recon)
```

---

## 4. Layer 2 — Known Application Lookup

**If you have identified a known application, look up its scoreboard/challenge page BEFORE running any scanning tools.** This takes 30 seconds and is always faster than scanning.

### Known OWASP Projects — Scoreboard / Challenge Pages

| Application | Identified By | Scoreboard / Challenge URL | Notes |
|---|---|---|---|
| **OWASP Juice Shop** | `X-Recruiting: /#/jobs` header OR `Bjoern Kimminich` in source | `/#/score-board` | SPA — Angular hash routing. NOT linked in nav by design |
| **OWASP Security Shepherd** | SSL cert `CN=OwaspShepherd` OR redirect to `/login.jsp` | `/scoreboard.jsp` (post-login) | Login first with your USN. Dashboard at `/index.jsp` |
| **OWASP WebGoat** | Page title `WebGoat` OR `/WebGoat/` path | `/WebGoat/start.mvc` (post-login) | Register first at `/WebGoat/login`. Challenge list is the "scoreboard" |
| **OWASP Mutillidae II** | `/mutillidae/` path in URL OR OWASP logo | `/mutillidae/index.php` (left nav) | No scoreboard — challenges in left navigation menu |
| **OWASP WebGoat.NET** | `.aspx` pages + IIS server | `/WebGoat/` | .NET version — lesson list IS the challenge page |
| **DVWA** | `/dvwa/` path OR `Damn Vulnerable` in title | `/dvwa/index.php` | Left nav menu. Setup at `/dvwa/setup.php` first |
| **bWAPP** | `/bWAPP/` path OR `bee-box` branding | `/bWAPP/portal.php` | Install at `/bWAPP/install.php` first. bee/bug creds |
| **Metasploitable 2** | Apache 2.2.8 + Ubuntu 8.04 | `/` (index lists all apps) | Multiple apps: `/dvwa/`, `/mutillidae/`, `/tikiwiki/` |
| **XVWA** | `/xvwa/` path + red UI | `/xvwa/` (left nav) | No scoreboard — categories in left nav |
| **HackSys (HEVD)** | Windows kernel driver | N/A | Not a web app |
| **NodeGoat** | `Node.js` + port 4000 | `/tutorial` (post-login) | Tutorial page lists all challenges |
| **RailsGoat** | `Rails` server + port 3000 | `/` (post-login) | Dashboard after login |
| **PyGoat** | `Django` + port 8000 | `/` (post-login) | Lab list on homepage |
| **DVGA** | `GraphQL` + port 5013 | `/graphiql` | GraphQL explorer IS the challenge interface |
| **VAmPI** | `Werkzeug` + port 5000 + JSON responses | `/docs` (Swagger UI) | REST API only — Swagger lists all endpoints |
| **NanoCorp Bites** | `Werkzeug` + food portal theme | No scoreboard (custom app) | Use full discovery layers below |
| **Hackazon** | E-commerce storefront | `/account` (post-login) | No scoreboard — realistic scenario app |
| **Google Gruyere** | Python GAE + cheese theme | `http://google-gruyere.appspot.com/start` | Online only — session-based |

### How to Use This Table
```
1. Identify the app from Layer 1
2. Find it in the table above
3. Navigate directly to the Scoreboard / Challenge URL
4. If it requires login:
   a. Register/login first
   b. Then navigate to the scoreboard URL
5. If the URL doesn't work → continue to Layer 3
```

### Google Search Syntax for Any Known App
```bash
# If you know the app name but not the exact URL:
# Search exactly:
"<APP NAME> scoreboard URL"
"<APP NAME> challenge page URL"
"<APP NAME> hidden page"
"<APP NAME> CTF walkthrough"
"<APP NAME> score-board"

# Examples:
"OWASP Juice Shop scoreboard URL"
"Security Shepherd challenge page URL"
"WebGoat score page URL"
"DVWA challenge list URL"
```

---

## 5. Layer 3 — Passive Recon (Before Touching the App)

Run these before any active scanning. They are low-noise and often immediately reveal hidden paths.

### Step 1 — robots.txt
```bash
curl -s http://TARGET:PORT/robots.txt
curl -sk https://TARGET:PORT/robots.txt

# What to look for:
# Disallow: /admin          → admin panel exists here
# Disallow: /scoreboard     → scoreboard hidden here
# Disallow: /secret         → hidden page
# Disallow: /dashboard      → dashboard path
# Allow: /                  → open (not helpful)

# In Juice Shop specifically — robots.txt lists:
# Disallow: /ftp
# (the scoreboard is NOT in robots.txt — that's the challenge)
```

### Step 2 — sitemap.xml
```bash
curl -s http://TARGET:PORT/sitemap.xml
curl -sk https://TARGET:PORT/sitemap.xml

# A sitemap lists every page the site wants search engines to index.
# Sometimes developers forget to restrict the admin/challenge pages.
# Look for: <loc>http://TARGET/admin</loc> etc.
```

### Step 3 — Security.txt (Modern Standard)
```bash
curl -s http://TARGET:PORT/.well-known/security.txt
curl -s http://TARGET:PORT/security.txt

# security.txt is a standard file disclosing security contacts.
# Some CTF/lab apps put hints here.
```

### Step 4 — Common Disclosure Files
```bash
# Check all of these — one command per line:
curl -s -o /dev/null -w "%{http_code} — /robots.txt\n"       http://TARGET:PORT/robots.txt
curl -s -o /dev/null -w "%{http_code} — /sitemap.xml\n"      http://TARGET:PORT/sitemap.xml
curl -s -o /dev/null -w "%{http_code} — /.well-known/\n"     http://TARGET:PORT/.well-known/
curl -s -o /dev/null -w "%{http_code} — /crossdomain.xml\n"  http://TARGET:PORT/crossdomain.xml
curl -s -o /dev/null -w "%{http_code} — /clientaccesspolicy.xml\n" http://TARGET:PORT/clientaccesspolicy.xml
curl -s -o /dev/null -w "%{http_code} — /humans.txt\n"        http://TARGET:PORT/humans.txt
curl -s -o /dev/null -w "%{http_code} — /README.md\n"         http://TARGET:PORT/README.md
curl -s -o /dev/null -w "%{http_code} — /CHANGELOG\n"         http://TARGET:PORT/CHANGELOG
curl -s -o /dev/null -w "%{http_code} — /VERSION\n"           http://TARGET:PORT/VERSION
# A 200 response means the file exists — read it fully
```

### Step 5 — Git Exposure
```bash
# Developers sometimes leave .git/ exposed — it contains the full repo history
# including all file paths (including hidden pages)
curl -s -o /dev/null -w "%{http_code}" http://TARGET:PORT/.git/HEAD
# If 200 → git is exposed. Read:
curl -s http://TARGET:PORT/.git/HEAD
curl -s http://TARGET:PORT/.git/config
curl -s http://TARGET:PORT/.git/COMMIT_EDITMSG
# This reveals all file paths in the repository including hidden routes
```

---

## 6. Layer 4 — Manual Obvious Path Checks

Test these paths manually with curl. This is fast (under 2 minutes) and covers 90% of common challenge/admin page naming conventions.

### The Master Path List — Run This Block
```bash
TARGET="http://TARGET:PORT"   # set your target

# ---- SCOREBOARD VARIANTS ----
for path in \
  scoreboard score-board score_board scores score \
  "#/score-board" "#/scoreboard" \
  challenges challenge challenge-list ctf ctf-board \
  dashboard dash home portal main \
  progress progress-board completion status \
  leaderboard leader-board rankings rank \
  admin administrator administration manage management \
  panel control control-panel cp \
  index index.jsp index.php index.html \
  login login.jsp login.php \
  welcome start begin; do
    code=$(curl -s -o /dev/null -w "%{http_code}" "$TARGET/$path" 2>/dev/null)
    [ "$code" != "404" ] && echo "$code — /$path"
done
```

### PHP Application Specific (add .php extension)
```bash
TARGET="http://TARGET:PORT"

for path in \
  scoreboard score dashboard challenges admin \
  index login register panel control; do
    code=$(curl -s -o /dev/null -w "%{http_code}" "$TARGET/$path.php")
    [ "$code" != "404" ] && echo "$code — /$path.php"
done
```

### Java Application Specific (add .jsp extension)
```bash
TARGET="https://TARGET:PORT"   # Shepherd uses HTTPS

for path in \
  scoreboard score dashboard challenges admin \
  index login register panel moduleList; do
    code=$(curl -sk -o /dev/null -w "%{http_code}" "$TARGET/$path.jsp")
    [ "$code" != "404" ] && echo "$code — /$path.jsp"
done
```

### Single Page Application (Angular/React — hash routing)
```bash
# SPAs use /#/route format — these can't be brute-forced with dirb
# because the server returns 200 for ALL hash routes (client handles routing)
# You MUST grep the JavaScript bundle for route definitions (see Layer 5)

# Common Juice Shop routes for reference:
for route in \
  score-board administration privacy-security \
  accounting about contact; do
    echo "Try in browser: http://TARGET:PORT/#/$route"
done
```

### Interpret the HTTP Status Codes
```
200 → Page exists and is accessible — open it in browser immediately
301 → Permanent redirect — follow it (curl -L)
302 → Temporary redirect — follow it (curl -Lk)
401 → Exists but requires HTTP Basic Auth — try default credentials
403 → Exists but forbidden — page is there, needs different access method
404 → Does not exist at this path
500 → Server error — page exists, something broke — still interesting
```

---

## 7. Layer 5 — Page Source & JavaScript Analysis

This is the most important layer for **Single Page Applications** (Angular, React, Vue) and any app that embeds its navigation structure in JavaScript.

### Step 1 — Identify if it's an SPA
```bash
# An SPA has almost no content in the initial HTML — just script tags
curl -s http://TARGET:PORT | wc -c        # small = SPA
curl -s http://TARGET:PORT | grep -c "href"  # very few hrefs = SPA

# Dead giveaway: URL contains #/ after any navigation
# Also: view-source shows mostly <script src="..."> tags
```

### Step 2 — Find the JavaScript Bundle Filename
```bash
# Get the page HTML and extract script src attributes:
curl -s http://TARGET:PORT | grep -oE 'src="[^"]*\.js[^"]*"' | sort -u
curl -s http://TARGET:PORT | grep -oE "src='[^']*\.js[^']*'" | sort -u

# Common bundle filenames:
# main.js, main.<hash>.js, bundle.js, app.js, vendor.js, runtime.js
# chunk-<hash>.js (React/Webpack)
# polyfills.js (Angular)
```

### Step 3 — Download and Grep the JavaScript Bundles
```bash
# Download the main bundle:
curl -s http://TARGET:PORT/main.js -o main.js

# Search for route/path definitions:
grep -oE '"[/a-zA-Z0-9_-]+"' main.js | sort -u | grep -v "^\"[a-z]\"$"

# Search specifically for scoreboard/challenge patterns:
grep -iE "score|board|challenge|admin|dashboard|panel|hidden|secret" main.js

# Search for Angular route definitions (look for 'path:' entries):
grep -oE '"path":"[^"]*"' main.js | sort -u
grep -oE "'path':'[^']*'" main.js | sort -u

# Search for React Router route definitions:
grep -iE "Route|path=|to=" main.js | head -50

# Prettify minified JS first for better reading:
python3 -c "
import sys, re
content = open('main.js').read()
# Simple indent — not perfect but reveals structure
content = content.replace('{', '{\n  ').replace('}', '\n}').replace(';', ';\n')
print(content[:5000])  # show first 5000 chars
"
```

### Step 4 — Juice Shop Specific (Angular Route Extraction)
```bash
# Download all JS bundles Juice Shop uses:
curl -s http://TARGET:PORT | grep -oE 'src="[^"]*\.js"' | \
  sed 's/src="//;s/"//' | while read f; do
    curl -s "http://TARGET:PORT/$f" -o "$(basename $f)"
done

# Now search ALL downloaded JS files for routes:
grep -rhiE '"path":"[^"]*"' *.js | grep -v "node_modules" | sort -u

# Juice Shop's scoreboard route will appear as:
# "path":"score-board"
# or similar — this is how you find it from code analysis
```

### Step 5 — Search for Hardcoded URLs and Paths in Source
```bash
# Look for any hardcoded paths in the entire page source:
curl -s http://TARGET:PORT | grep -oE '(href|action|src|url|endpoint)="[^"]*"' | sort -u

# Look for API endpoint definitions:
curl -s http://TARGET:PORT | grep -oE '"/[a-zA-Z0-9/_-]+"' | sort -u

# Look for comments — developers hide hints in HTML comments:
curl -s http://TARGET:PORT | grep -oE '<!--.*?-->' 

# Multi-line comments (longer hidden notes):
curl -s http://TARGET:PORT | python3 -c "
import sys, re
html = sys.stdin.read()
comments = re.findall(r'<!--.*?-->', html, re.DOTALL)
for c in comments:
    print(c)
"
```

### Step 6 — Inspect Network Requests in Browser DevTools
```
1. Open Firefox → Navigate to the target
2. Press F12 → Network tab
3. Reload the page (Ctrl+R)
4. Click on the first request (the HTML document)
5. Check: Response tab → look for hidden paths in the HTML
6. Check: All requests made — each file loaded is a potential endpoint
7. Filter by: JS → look at all JavaScript files loaded
8. Click each JS file → Search tab → search for "score", "admin", "challenge"
```

---

## 8. Layer 6 — API & Documentation Endpoints

Many modern apps (especially Node.js, Flask, Spring Boot) expose API documentation that lists every single endpoint — including the scoreboard.

### Step 1 — Check for Swagger / OpenAPI
```bash
# These are the most common API documentation endpoints:
for path in \
  api-docs swagger.json swagger-ui.html swagger-ui \
  openapi.json openapi.yaml \
  v1/api-docs v2/api-docs v3/api-docs \
  api/v1 api/v2 api/swagger \
  docs api/docs documentation; do
    code=$(curl -s -o /dev/null -w "%{http_code}" "http://TARGET:PORT/$path")
    [ "$code" = "200" ] && echo "FOUND: /$path"
done

# If Swagger is found — read it fully:
curl -s http://TARGET:PORT/api-docs | python3 -m json.tool | less
# Every "path" entry in the output is an endpoint
# Look for: /score-board, /challenges, /admin, /dashboard etc.
```

### Step 2 — GraphQL Schema Introspection
```bash
# If the app uses GraphQL (check for /graphql endpoint):
code=$(curl -s -o /dev/null -w "%{http_code}" http://TARGET:PORT/graphql)
[ "$code" = "200" ] && echo "GraphQL endpoint found"

# Run introspection query to get ALL types and queries:
curl -s -X POST http://TARGET:PORT/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"{ __schema { types { name fields { name } } } }"}' \
  | python3 -m json.tool | grep -E '"name"' | sort -u
```

### Step 3 — Juice Shop API Docs (Specific)
```bash
# Juice Shop exposes its full REST API via Swagger:
curl -s http://TARGET:PORT/api-docs | python3 -m json.tool > juice_api.txt
cat juice_api.txt | grep -i "path\|score\|challenge\|admin"

# This reveals routes like:
# /rest/challenges/
# /rest/admin/application-configuration
# etc.
```

### Step 4 — Check for Web Application Firewall / API Gateway Hints
```bash
# Some apps expose their routing config:
curl -s http://TARGET:PORT/config
curl -s http://TARGET:PORT/config.json
curl -s http://TARGET:PORT/settings
curl -s http://TARGET:PORT/app-config
curl -s http://TARGET:PORT/.env           # never should be public but often is
curl -s http://TARGET:PORT/web.config     # ASP.NET config
curl -s http://TARGET:PORT/app.config
```

---

## 9. Layer 7 — Cookie & Header Analysis

After accessing any page (even just the homepage), examine what the server tells you in headers and cookies.

### Step 1 — Full Verbose Header Dump
```bash
curl -ikv http://TARGET:PORT/ 2>&1 | grep -E "^[<>]" | head -50
# < = response headers from server
# > = request headers you sent
```

### Step 2 — Look for Hints in Headers
```bash
curl -I http://TARGET:PORT | grep -v "^HTTP\|^Date\|^Content"
# Look for non-standard headers — developers sometimes leave breadcrumbs:
# X-Recruiting: /#/jobs           → Juice Shop (also reveals /#/ SPA routing)
# X-Powered-By: Express           → Node.js
# X-Application-Context: app:8080 → Spring Boot
# X-Generator: Drupal             → Drupal CMS
# X-Debug-Token: abc123           → Symfony debug mode
```

### Step 3 — Decode Cookies
```bash
# After loading the homepage, Burp captures Set-Cookie headers
# Or use curl to show cookies:
curl -ic http://TARGET:PORT/ 2>&1 | grep -i "set-cookie"

# Base64 decode any cookie values:
echo "COOKIE_VALUE" | base64 -d 2>/dev/null

# URL decode:
python3 -c "import urllib.parse; print(urllib.parse.unquote('COOKIE_VALUE'))"

# JSON cookies often contain role, userId, or navigation hints:
echo "eyJ1c2VyIjoiYWRtaW4ifQ==" | base64 -d
# → {"user":"admin"}

# Security Shepherd specific:
# The token cookie contains JWT — decode it:
echo "HEADER.PAYLOAD.SIGNATURE" | cut -d. -f2 | base64 -d 2>/dev/null | python3 -m json.tool
```

---

## 10. Layer 8 — Directory Brute Force (dirb / wfuzz)

When manual checks haven't found the page, systematic brute force will.

### Step 1 — dirb Standard Scan
```bash
# HTTP
dirb http://TARGET:PORT /usr/share/dirb/wordlists/common.txt

# HTTPS (suppress SSL errors)
dirb https://TARGET:PORT /usr/share/dirb/wordlists/common.txt -S

# Save output to file (important — lots of results)
dirb http://TARGET:PORT /usr/share/dirb/wordlists/common.txt -o dirb_results.txt

# With file extensions (adapt to stack):
dirb http://TARGET:PORT /usr/share/dirb/wordlists/common.txt -X .php        # PHP
dirb http://TARGET:PORT /usr/share/dirb/wordlists/common.txt -X .jsp        # Java
dirb http://TARGET:PORT /usr/share/dirb/wordlists/common.txt -X .asp,.aspx  # ASP.NET
dirb http://TARGET:PORT /usr/share/dirb/wordlists/common.txt -X .py         # Flask (rare)

# Bigger wordlist when common.txt misses it:
dirb http://TARGET:PORT /usr/share/dirb/wordlists/big.txt -o dirb_big.txt
```

### Step 2 — wfuzz (More Filtering Control)
```bash
# Basic — hide 404s
wfuzz -c -w /usr/share/wfuzz/wordlist/general/common.txt \
  --hc 404 http://TARGET:PORT/FUZZ

# Show only successful responses (200, 301, 302, 403)
wfuzz -c -w /usr/share/wfuzz/wordlist/general/common.txt \
  --sc 200,301,302,403 http://TARGET:PORT/FUZZ

# HTTPS
wfuzz -c -w /usr/share/wfuzz/wordlist/general/common.txt \
  --hc 404 https://TARGET:PORT/FUZZ

# With extensions
wfuzz -c -w /usr/share/wfuzz/wordlist/general/common.txt \
  --hc 404 http://TARGET:PORT/FUZZ.php

# Bigger wordlist
wfuzz -c -w /usr/share/wfuzz/wordlist/general/big.txt \
  --hc 404 http://TARGET:PORT/FUZZ
```

### Step 3 — Interpret dirb/wfuzz Output
```
DIRB output format:
==> DIRECTORY: http://TARGET/admin/         → directory found, enter it
+ http://TARGET/scoreboard (CODE:200)       → page found directly
+ http://TARGET/login (CODE:302)            → redirect — follow it
+ http://TARGET/dashboard (CODE:403)        → exists but forbidden
                                              → still note it, try after login

WFUZZ output format:
000000001:   200  45 L  120 W  3742 Ch  "scoreboard"    → FOUND, 200 OK
000000002:   302  0 L    0 W     0 Ch   "admin"          → redirect
000000003:   403  5 L   20 W   200 Ch   "dashboard"      → forbidden (exists)
```

### Step 4 — Pay Attention to These Response Patterns
```
Code 200 with unusual Content-Length:
  → If most 404s are ~500 bytes but one path returns 3742 bytes → that's a real page

Code 403 (Forbidden):
  → The page EXISTS but you're not authorized
  → After getting admin access (via SQLi or other), retry this path

Code 302 to /login:
  → The page exists but requires authentication → log in first then retry

Different response length for "404":
  → Some apps return custom 404 pages that still say 200 OK
  → Compare response lengths — the odd one out is a real page
```

---

## 11. Layer 9 — ZAP Spidering

ZAP crawls the application automatically and discovers pages you haven't manually visited.

### For Server-Rendered Apps (Flask, PHP, Java)
```bash
# From command line:
zap-cli spider http://TARGET:PORT

# Or in ZAP GUI:
# 1. Open ZAP
# 2. Quick Start → Automated Scan → enter URL → Attack
# 3. After scan: Sites tree (left panel) shows ALL discovered URLs
# 4. Check the Alerts tab for vulnerability findings too
```

### For SPAs — Use Ajax Spider (Critical)
```
ZAP GUI only (no CLI equivalent):
1. Tools → Ajax Spider
2. Browser: Firefox (headless)
3. Target URL: http://TARGET:PORT
4. Click Start
5. ZAP opens a browser and actually CLICKS through the app
6. Every URL it visits appears in the Sites tree
7. Wait until "Stopped" — then examine Sites tree

Why this is different from regular spider:
Regular spider: reads HTML, follows href links
Ajax Spider:     actually runs JavaScript, clicks buttons, 
                 follows hash routes, triggers API calls
→ This is the ONLY way to spider Angular/React/Vue apps properly
```

### After ZAP Spider — Search the Sites Tree
```
In ZAP GUI → Sites tab (left panel):
Expand the target node → look through every URL found

Right-click any URL → Open in Browser → check if it's the scoreboard/dashboard

Also check:
ZAP → Alerts tab → look for:
- "Hidden Feature Enabled"
- "Application Error Disclosure"  
- "Information Disclosure"
These alerts often point directly to admin/hidden pages
```

---

## 12. Layer 10 — Burp Suite Passive Capture

Run Burp in the background while you manually browse. It records everything including background API calls and XHR requests that aren't visible in the address bar.

### Setup
```
1. Open Burp Suite
2. Proxy → Intercept → turn Intercept OFF
   (you want passive recording, not blocking)
3. Firefox: Settings → Network → Manual Proxy:
   HTTP Proxy: 127.0.0.1  Port: 8080
4. Visit http://TARGET:PORT in Firefox
5. Click EVERYTHING:
   - Every nav link
   - Every button
   - Log in / log out
   - Submit every form
   - Click every image
6. While browsing, Burp records every single request silently
```

### After Browsing — Analyse HTTP History
```
Burp → Proxy → HTTP History

Sort by: URL (click column header)
Look for:
  - Paths you haven't visited manually
  - API calls (usually /api/*, /rest/*, /v1/*)
  - Endpoints with unusual names
  - Paths containing: admin, score, challenge, dashboard, panel

Filter: right-click → Search → type "score" or "admin" or "challenge"
→ Every request matching appears in the filtered view
```

### Burp Site Map
```
Burp → Target → Site Map
Expand the target host
Every URL Burp has seen appears here — including:
  - Paths only visited in JavaScript (XHR requests)
  - API endpoints called by the app in the background
  - Hidden endpoints called during login/logout
```

---

## 13. Layer 11 — Authenticated Scanning (Post-Login)

Many challenge/scoreboard pages only appear AFTER you log in. Always re-scan after authentication.

### Step 1 — Log In and Get Your Session Token
```bash
# For apps with JSON login (Juice Shop, most REST APIs):
TOKEN=$(curl -s -X POST http://TARGET:PORT/rest/user/login \
  -H "Content-Type: application/json" \
  -d '{"email":"your@email.com","password":"yourpassword"}' \
  | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('authentication',{}).get('token',''))")

echo "Token: $TOKEN"

# For form-based login (PHP, Flask):
# Use Burp to log in, then copy the session cookie from Storage tab
# SESSIONCOOKIE="your_session_id_value"
```

### Step 2 — Re-Run Manual Path Checks With Auth
```bash
TOKEN="your-jwt-token"
SESSIONCOOKIE="your-session-cookie"

# JWT-authenticated requests:
for path in \
  administration admin scoreboard score-board dashboard \
  challenges panel management users; do
    code=$(curl -s -o /dev/null -w "%{http_code}" \
      -H "Authorization: Bearer $TOKEN" \
      "http://TARGET:PORT/$path")
    [ "$code" != "404" ] && echo "$code — /$path (authenticated)"
done

# Cookie-authenticated requests:
for path in \
  administration admin scoreboard dashboard challenges panel; do
    code=$(curl -s -o /dev/null -w "%{http_code}" \
      -b "session=$SESSIONCOOKIE" \
      "http://TARGET:PORT/$path")
    [ "$code" != "404" ] && echo "$code — /$path (authenticated)"
done
```

### Step 3 — Authenticated dirb
```bash
# JWT:
dirb http://TARGET:PORT /usr/share/dirb/wordlists/common.txt \
  -H "Authorization: Bearer YOUR_TOKEN"

# Session cookie:
dirb http://TARGET:PORT /usr/share/dirb/wordlists/common.txt \
  -H "Cookie: session=YOUR_SESSION_VALUE"
```

### Step 4 — In Juice Shop — Access Admin Panel After Admin Login
```
After logging in as admin (via SQLi F-05):
1. Navigate to: http://TARGET:PORT/#/administration
2. This page is only accessible to admin role
3. It lists all users, all complaints, all feedback
4. From here you can see hidden data about other users
```

---

## 14. Layer 12 — Parameter & ID Fuzzing

Some challenge pages are not at a fixed path but are accessed via a parameter value.

### Step 1 — Fuzz URL Parameters
```bash
# If you find a URL like: http://TARGET:PORT/page?id=1
# Try changing the id:
for i in $(seq 1 20); do
  code=$(curl -s -o /dev/null -w "%{http_code}" "http://TARGET:PORT/page?id=$i")
  echo "$code — ?id=$i"
done

# Fuzz with wfuzz — numeric IDs:
wfuzz -c -z range,1-100 --hc 404 http://TARGET:PORT/page?id=FUZZ

# Fuzz with wfuzz — named parameters:
wfuzz -c -w /usr/share/wfuzz/wordlist/general/common.txt \
  --hc 404 "http://TARGET:PORT/page?view=FUZZ"
```

### Step 2 — Fuzz POST Body Parameters
```bash
# If the app accepts POST with a page/action parameter:
wfuzz -c -w /usr/share/wfuzz/wordlist/general/common.txt \
  --hc 404 -X POST \
  -d "action=FUZZ" \
  http://TARGET:PORT/index.php

# Security Shepherd specific — module ID fuzzing:
# Shepherd loads modules by ID — try incrementing:
for i in $(seq 1 50); do
  curl -sk -b "JSESSIONID=YOUR_SESSION" \
    "https://TARGET:PORT/module/getModuleByName?moduleId=$i" \
    | grep -v "error\|invalid" | head -1
done
```

### Step 3 — Hash Fragment Fuzzing (SPAs)
```bash
# SPAs use /#/route — you can't curl these (client-side only)
# But you CAN grep the JS bundle for all defined routes:

curl -s http://TARGET:PORT/main.js | \
  grep -oE '"path":"[^"]*"' | \
  sed 's/"path":"//;s/"//' | \
  sort -u | \
  while read route; do
    echo "Browser URL to try: http://TARGET:PORT/#/$route"
  done
```

---

## 15. Layer 13 — Framework-Specific Tricks

Each framework has unique properties that can reveal hidden pages.

### Flask (Python / Werkzeug)

```bash
# Flask debug mode exposes an interactive console and all routes:
curl -s http://TARGET:PORT/console
# If this returns a Python console → RCE possible AND all routes listed

# Flask route map — sometimes exposed:
curl -s http://TARGET:PORT/site-map
curl -s http://TARGET:PORT/_routes

# Check if Werkzeug debugger is enabled (shows full route map):
# Navigate to: http://TARGET:PORT/non-existent-path-that-errors
# If you see the Werkzeug debugger → it lists ALL registered routes

# Enumerate Flask routes via error page:
curl -s http://TARGET:PORT/DOESNOTEXIST999 | grep -oE '"[/][a-zA-Z0-9/_<>-]+"'
```

### Spring Boot (Java)

```bash
# Spring Boot Actuator exposes management endpoints:
for path in \
  actuator actuator/health actuator/info actuator/mappings \
  actuator/env actuator/beans actuator/routes \
  /manage /management; do
    code=$(curl -s -o /dev/null -w "%{http_code}" "http://TARGET:PORT/$path")
    [ "$code" = "200" ] && echo "FOUND: /$path"
done

# actuator/mappings is the goldmine — lists ALL route mappings in the app:
curl -s http://TARGET:PORT/actuator/mappings | python3 -m json.tool | grep "pattern\|path"
```

### Node.js / Express

```bash
# Express apps sometimes expose route info in debug mode:
curl -s http://TARGET:PORT/ -H "X-Debug: true"

# Check for Express's default error page (reveals app structure):
curl -s http://TARGET:PORT/DOESNOTEXIST | grep -i "express\|cannot GET\|route"

# Express route definitions are usually in app.js or server.js:
# If .git is exposed, fetch these files
```

### Angular (Juice Shop)

```bash
# All Angular routes are compiled into the main JS bundle
# The router module defines routes as objects: { path: 'score-board', component: ... }

# Method 1: Download and grep
curl -s http://TARGET:PORT/main.js | grep -oE '"path":"[^"]*"' | sort -u

# Method 2: Use browser console
# F12 → Console → type:
# ng.probe(document.querySelector('[ng-version]')).injector.get(ng.coreTokens.Router).config
# This dumps the full router config including all hidden routes

# Method 3: Check Angular route guards
# Routes with canActivate guards are often admin/hidden pages
curl -s http://TARGET:PORT/main.js | grep -oE '"canActivate".*?"path":"[^"]*"'
```

### PHP Applications

```bash
# PHP apps often expose config files:
for file in \
  config.php config.inc.php configuration.php \
  settings.php wp-config.php db.php \
  includes/config.php admin/config.php; do
    code=$(curl -s -o /dev/null -w "%{http_code}" "http://TARGET:PORT/$file")
    [ "$code" = "200" ] && echo "FOUND: /$file"
done

# PHP info page — reveals document root and all loaded files:
curl -s -o /dev/null -w "%{http_code}" http://TARGET:PORT/phpinfo.php
curl -s -o /dev/null -w "%{http_code}" http://TARGET:PORT/info.php

# DVWA uses a menu system — the scoreboard IS the menu:
# http://TARGET/dvwa/index.php?page=CHALLENGE_NAME
for page in \
  brute exec csrf fi sqli sqli_blind upload xss_d xss_r xss_s; do
    code=$(curl -s -o /dev/null -w "%{http_code}" \
      -b "PHPSESSID=YOUR_SESSION; security=low" \
      "http://TARGET/dvwa/vulnerabilities/$page/")
    echo "$code — /$page"
done
```

---

## 16. Layer 14 — Error-Based Discovery

Deliberately trigger errors to make the application reveal its internal structure.

### Step 1 — Trigger 404 to See Error Page Format
```bash
curl -s http://TARGET:PORT/THISPAGESURELYDOESNOTEXIST12345
# Read the 404 page content carefully:
# - Does it list other pages? ("You might be looking for: /admin")
# - Does it show the framework version? (exploit known CVEs)
# - Does it show a sitemap link?
# - Does it reveal the document root? (/var/www/html/THISPAGESURELYDOESNOTEXIST12345.php not found)
```

### Step 2 — Trigger 500 to See Debug Information
```bash
# Send malformed input to trigger server errors:
curl -s -X POST http://TARGET:PORT/login \
  -H "Content-Type: application/json" \
  -d '{invalid json'

# Or send unexpected data types:
curl -s "http://TARGET:PORT/api/user?id=NOTANUMBER"
curl -s "http://TARGET:PORT/api/product?id='"'"

# A 500 error with stack trace reveals:
# - Full file paths (document root, app structure)
# - Class names (helps identify framework)
# - Database query structure (SQL injection points)
# - All registered routes in some frameworks (Flask debug)
```

### Step 3 — Nikto (Automated Error-Based Discovery)
```bash
# Nikto tests 6,700+ known paths and misconfigurations:
nikto -h http://TARGET:PORT

# HTTPS:
nikto -h https://TARGET:PORT -ssl

# Save output:
nikto -h http://TARGET:PORT -o nikto_results.txt -Format txt

# Nikto specifically checks for:
# - /admin, /administrator, /manager
# - /backup, /old, /test, /dev
# - Config files, backup files
# - Framework-specific paths
# It will find things dirb misses because it uses targeted checks
```

---

## 17. OWASP Project Scoreboard Reference — All Known Pages

### Complete Reference Table

| Application | Scoreboard URL | Pre-Login Required? | How to Identify the App | Special Notes |
|---|---|---|---|---|
| **OWASP Juice Shop** | `/#/score-board` | No (but register with USN first for screenshots) | `X-Recruiting: /#/jobs` header; Bjoern Kimminich copyright in HTML | Angular SPA. JS bundle grep: `"path":"score-board"`. NOT in robots.txt by design |
| **OWASP Security Shepherd** | `/scoreboard.jsp` | YES — login at `/login.jsp` first | SSL cert `CN=OwaspShepherd`; redirects to `/login.jsp` | HTTPS only. Self-signed cert — ignore SSL errors. Dashboard at `/index.jsp` after login |
| **OWASP WebGoat** | `/WebGoat/start.mvc` | YES — register at `/WebGoat/login` | Page title `WebGoat`; `/WebGoat/` path | The lesson list IS the scoreboard. WebWolf companion on port 9090 |
| **OWASP Mutillidae II** | `/mutillidae/` (left nav) | No | `/mutillidae/` path; OWASP logo on page | No true scoreboard — left nav shows all categories |
| **DVWA** | `/dvwa/index.php` | YES — setup at `/dvwa/setup.php` first | `/dvwa/` path; `Damn Vulnerable` branding | admin/password. Security level sets challenge difficulty |
| **bWAPP** | `/bWAPP/portal.php` | YES — install at `/bWAPP/install.php` | `/bWAPP/` path; bee branding | bee/bug credentials |
| **XVWA** | `/xvwa/` | No | `/xvwa/` path; red UI | Left nav = challenge menu |
| **NodeGoat** | `/tutorial` | YES | Port 4000; Node.js headers | admin/Admin_123 |
| **RailsGoat** | `/` post-login | YES | Port 3000; Rails server | admin@example.com/backdoor |
| **PyGoat** | `/` post-login | Register first | Port 8000; Django headers | Lab list on homepage |
| **DVGA** | `/graphiql` | No | Port 5013; GraphQL endpoint | GraphQL explorer = challenge interface |
| **VAmPI** | `/docs` (Swagger) | Register via API | Port 5000; Werkzeug + JSON | REST API only — no browser UI |
| **Metasploitable 2** | `/` (index) | No | Apache 2.2.8; Ubuntu 8.04; multiple apps linked | Multiple apps: /dvwa/, /mutillidae/, /tikiwiki/, /phpmyadmin/ |
| **HackSys HEVD** | N/A | N/A | Windows kernel driver | Not a web app |
| **NanoCorp Bites** | No scoreboard | N/A | Werkzeug + food portal title | Custom app — use full discovery layers |
| **Hackazon** | `/account` | YES | E-commerce storefront | Realistic scenario — no formal scoreboard |
| **Google Gruyere** | `http://google-gruyere.appspot.com/start` | Session-based | Python GAE; cheese theme | Online only |
| **PortSwigger Academy** | `https://portswigger.net/web-security/all-labs` | YES (free account) | Online platform | Best structured labs available |
| **TryHackMe** | `https://tryhackme.com/dashboard` | YES | Online platform | VPN or AttackBox required |
| **HackTheBox** | `https://www.hackthebox.com/machines` | YES | Online platform | Submit flags (user.txt, root.txt) |
| **OverTheWire Natas** | `http://natas0.natas.labs.overthewire.org` | Per-level HTTP auth | Online platform | Password from current level unlocks next |
| **PicoCTF** | `https://play.picoctf.org/practice` | YES | Online platform | Carnegie Mellon CTF |

---

## 18. Complete Decision Flowchart

```
START: You have TARGET_IP:PORT from nmap
          │
          ▼
┌─────────────────────────────┐
│ LAYER 0: Read nmap output   │
│ grep for title, server,     │
│ cert CN, redirect location  │
└──────────────┬──────────────┘
               │
               ▼
      App name in nmap output?
      ┌────YES────┐ ┌───NO────┐
      ▼           │ │         ▼
┌──────────────┐  │ │  ┌──────────────────┐
│ LAYER 1:     │  │ │  │ LAYER 1:         │
│ Skip to      │  │ │  │ curl -I headers  │
│ Layer 2      │  │ │  │ whatweb          │
└──────┬───────┘  │ │  │ grep page title  │
       │          │ │  └────────┬─────────┘
       │          │ │           │
       └──────────┘ └───────────┘
                       │
                       ▼
              Known application?
           ┌──────YES──────┐
           ▼               │
┌──────────────────┐       │
│ LAYER 2:         │       │
│ Look up in table │       │
│ above → go       │       │
│ directly to      │       │
│ scoreboard URL   │       │
└──────────┬───────┘       │
           │               │
           ▼               ▼
      Page loads?    Custom/unknown app
      ┌──YES──┐      ┌─────────────────────┐
      ▼       │      │ LAYER 3:            │
   DONE ✅    │      │ robots.txt          │
              │      │ sitemap.xml         │
              │      │ .git/HEAD           │
              │      │ security.txt        │
              │      └──────────┬──────────┘
              │                 │
              │                 ▼
              │      ┌─────────────────────┐
              │      │ LAYER 4:            │
              │      │ Manual path checks  │
              │      │ (shell loop above)  │
              │      └──────────┬──────────┘
              │                 │
              │                 ▼
              │      ┌─────────────────────┐
              │      │ LAYER 5:            │
              │      │ JS bundle analysis  │
              │      │ grep for routes     │
              │      │ HTML comment grep   │
              │      └──────────┬──────────┘
              │                 │
              │                 ▼
              │      ┌─────────────────────┐
              │      │ LAYER 6:            │
              │      │ API docs (swagger)  │
              │      │ GraphQL introspect  │
              │      └──────────┬──────────┘
              │                 │
              │                 ▼
              │      ┌─────────────────────┐
              │      │ LAYER 7:            │
              │      │ Cookie & header     │
              │      │ analysis            │
              │      └──────────┬──────────┘
              │                 │
              │                 ▼
              │      ┌─────────────────────┐
              │      │ LAYER 8:            │
              │      │ dirb / wfuzz        │
              │      │ brute force         │
              │      └──────────┬──────────┘
              │                 │
              │                 ▼
              │      ┌─────────────────────┐
              │      │ LAYER 9:            │
              │      │ ZAP spider          │
              │      │ (Ajax if SPA)       │
              │      └──────────┬──────────┘
              │                 │
              │                 ▼
              │      ┌─────────────────────┐
              │      │ LAYER 10:           │
              │      │ Burp HTTP History   │
              │      │ + Site Map          │
              │      └──────────┬──────────┘
              │                 │
              │                 ▼
              │      Still not found? → LOG IN first
              │      ┌─────────────────────┐
              │      │ LAYER 11:           │
              │      │ Repeat all above    │
              │      │ WITH auth token/    │
              │      │ session cookie      │
              │      └──────────┬──────────┘
              │                 │
              │                 ▼
              │      ┌─────────────────────┐
              │      │ LAYER 12:           │
              │      │ Param & ID fuzzing  │
              │      │ (page?id=1,2,3...)  │
              │      └──────────┬──────────┘
              │                 │
              │                 ▼
              │      ┌─────────────────────┐
              │      │ LAYER 13:           │
              │      │ Framework tricks    │
              │      │ (Flask debug,       │
              │      │  Spring Actuator,   │
              │      │  Angular router)    │
              │      └──────────┬──────────┘
              │                 │
              │                 ▼
              │      ┌─────────────────────┐
              │      │ LAYER 14:           │
              │      │ Error-based         │
              │      │ nikto scan          │
              │      └──────────┬──────────┘
              │                 │
              └────────────────→┤
                                ▼
                          Page found ✅
                          Screenshot it
                          Document the path
```

---

## 19. Master Command Cheatsheet

```bash
# ═══════════════════════════════════════════════════
# LAYER 0 — NMAP OUTPUT ANALYSIS
# ═══════════════════════════════════════════════════
grep -iE "title|server|location|copyright|cookie|x-recruit" scan.txt
openssl s_client -connect TARGET:PORT </dev/null 2>/dev/null | grep "CN="

# ═══════════════════════════════════════════════════
# LAYER 1 — APP IDENTIFICATION
# ═══════════════════════════════════════════════════
curl -I http://TARGET:PORT
curl -Ik https://TARGET:PORT
curl -s http://TARGET:PORT | grep -i "<title"
curl -s http://TARGET:PORT | grep -iE "copyright|version|powered|generator"
whatweb http://TARGET:PORT -v

# ═══════════════════════════════════════════════════
# LAYER 3 — PASSIVE RECON
# ═══════════════════════════════════════════════════
curl -s http://TARGET:PORT/robots.txt
curl -s http://TARGET:PORT/sitemap.xml
curl -s http://TARGET:PORT/.git/HEAD
curl -s http://TARGET:PORT/.well-known/security.txt
curl -s http://TARGET:PORT/humans.txt

# ═══════════════════════════════════════════════════
# LAYER 4 — MANUAL PATH CHECKS (shell loop)
# ═══════════════════════════════════════════════════
for path in scoreboard score-board score challenges challenge \
  dashboard admin administrator administration panel \
  ctf leaderboard progress completion index.jsp \
  login.jsp moduleList.jsp scoreboard.jsp; do
    code=$(curl -sk -o /dev/null -w "%{http_code}" "https://TARGET:PORT/$path")
    [ "$code" != "404" ] && echo "$code — /$path"
done

# ═══════════════════════════════════════════════════
# LAYER 5 — JS ANALYSIS
# ═══════════════════════════════════════════════════
curl -s http://TARGET:PORT | grep -oE 'src="[^"]*\.js[^"]*"'
curl -s http://TARGET:PORT/main.js | grep -oE '"path":"[^"]*"' | sort -u
curl -s http://TARGET:PORT | grep -oE '<!--.*?-->'
curl -s http://TARGET:PORT | grep -iE "score|challenge|admin|dashboard|panel|hidden"

# ═══════════════════════════════════════════════════
# LAYER 6 — API DOCS
# ═══════════════════════════════════════════════════
curl -s http://TARGET:PORT/api-docs | python3 -m json.tool | grep path
curl -s http://TARGET:PORT/swagger.json
curl -s http://TARGET:PORT/swagger-ui.html
curl -s -X POST http://TARGET:PORT/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"{ __schema { types { name } } }"}'

# ═══════════════════════════════════════════════════
# LAYER 8 — BRUTE FORCE
# ═══════════════════════════════════════════════════
dirb http://TARGET:PORT /usr/share/dirb/wordlists/common.txt -o dirb.txt
dirb https://TARGET:PORT /usr/share/dirb/wordlists/common.txt -S -o dirb_ssl.txt
dirb http://TARGET:PORT /usr/share/dirb/wordlists/common.txt -X .php -o dirb_php.txt
dirb http://TARGET:PORT /usr/share/dirb/wordlists/common.txt -X .jsp -o dirb_jsp.txt
dirb http://TARGET:PORT /usr/share/dirb/wordlists/big.txt -o dirb_big.txt
wfuzz -c -w /usr/share/wfuzz/wordlist/general/common.txt --hc 404 http://TARGET:PORT/FUZZ
wfuzz -c -w /usr/share/wfuzz/wordlist/general/common.txt --sc 200,301,302,403 http://TARGET:PORT/FUZZ

# ═══════════════════════════════════════════════════
# LAYER 9 — ZAP
# ═══════════════════════════════════════════════════
zap-cli spider http://TARGET:PORT
# For SPA → use ZAP GUI → Tools → Ajax Spider

# ═══════════════════════════════════════════════════
# LAYER 11 — AUTHENTICATED SCANS
# ═══════════════════════════════════════════════════
dirb http://TARGET:PORT /usr/share/dirb/wordlists/common.txt \
  -H "Authorization: Bearer YOUR_JWT_TOKEN"
dirb http://TARGET:PORT /usr/share/dirb/wordlists/common.txt \
  -H "Cookie: session=YOUR_SESSION"

# ═══════════════════════════════════════════════════
# LAYER 13 — FRAMEWORK TRICKS
# ═══════════════════════════════════════════════════
# Flask debug:
curl -s http://TARGET:PORT/console
curl -s http://TARGET:PORT/DOESNOTEXIST | grep -i "werkzeug\|route\|url"

# Spring Boot Actuator:
curl -s http://TARGET:PORT/actuator/mappings | python3 -m json.tool | grep pattern

# Angular routes:
curl -s http://TARGET:PORT/main.js | grep -oE '"path":"[^"]*"' | sort -u

# ═══════════════════════════════════════════════════
# LAYER 14 — ERROR-BASED + NIKTO
# ═══════════════════════════════════════════════════
curl -s http://TARGET:PORT/DOESNOTEXIST12345
nikto -h http://TARGET:PORT -o nikto.txt -Format txt
nikto -h https://TARGET:PORT -ssl -o nikto_ssl.txt -Format txt
```

---

*Document version: 2.0 — May 2026*
*Covers: 14 discovery layers, all OWASP projects, all major web frameworks,*
*custom applications, SPAs, server-rendered apps, and authenticated scanning.*
