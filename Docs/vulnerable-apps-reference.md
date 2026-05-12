# Vulnerable Applications — Pentest Reference Table
### Scoreboard / Challenge Pages, Default Credentials, Ports & Notes

> **How to use this table:** When nmap or curl identifies a known application, look it up here first. The scoreboard/challenge URL, default credentials, and identification signals are documented so you can skip straight to testing instead of spending time guessing.

---

## Legend

| Symbol | Meaning |
|---|---|
| ✅ | Has a scoreboard or challenge progress page |
| ❌ | No scoreboard — challenges are standalone or CTF-style |
| ⚠️ | Partial — challenge list exists but no progress tracking |
| 🔐 | Requires login before accessing challenge/scoreboard page |
| 🌐 | Online platform — no local install needed |
| 📦 | Self-hosted / Docker / VM |

---

## Section 1 — OWASP Official Applications

| # | Application | Default Port(s) | Login / Challenge Page URL | Scoreboard URL | Default Credentials | Stack | Identification Signal | Scoreboard? | Notes |
|---|---|---|---|---|---|---|---|---|---|
| 1 | **OWASP Juice Shop** | 3000 (Docker), any (custom) | `http://TARGET:PORT/#/login` | `http://TARGET:PORT/#/score-board` | Register your own account | Node.js / Angular SPA | `X-Recruiting: /#/jobs` header; copyright `Bjoern Kimminich` in HTML | ✅ | SPA with hash routing — use ZAP Ajax Spider. Scoreboard is hidden by design (finding it is Challenge 1). Swagger API docs at `/api-docs`. 100+ challenges covering full OWASP Top 10. |
| 2 | **OWASP WebGoat** | 8080 (app), 9090 (WebWolf) | `http://TARGET:8080/WebGoat/login` | `http://TARGET:8080/WebGoat/start.mvc` | Register your own account | Java / Spring Boot | `WebGoat` in page title; `JSESSIONID` cookie | ⚠️ 🔐 | No scoreboard — lesson list is the challenge index. Lessons listed at `/WebGoat/start.mvc` after login. Companion app WebWolf runs on port 9090. Covers OWASP Top 10 in lesson format. Must register before accessing lessons. |
| 3 | **OWASP Security Shepherd** | 8080 (HTTP) or 8443 (HTTPS) | `https://TARGET:PORT/login.jsp` | Dashboard after login | Register your own account (use USN as username in labs) | Java / Tomcat | SSL cert `commonName=OwaspShepherd`; redirects to `/login.jsp`; `JSESSIONID` | ✅ 🔐 | HTTPS with self-signed/expired cert — use `-k` flag everywhere. Challenge dashboard accessible after login. Covers web and mobile security. Score tracked per user. |
| 4 | **OWASP Mutillidae II** | 80 (Apache/XAMPP) | `http://TARGET/mutillidae/` | `http://TARGET/mutillidae/index.php?page=home.php` | No login required for most challenges; admin/adminpass for admin | PHP / MySQL | Apache server; `/mutillidae/` path; OWASP logo | ⚠️ | No scoreboard — challenges listed in left-side navigation menu by OWASP category. Has a "Reset DB" button to restore defaults. 40+ vulnerabilities. Can switch between security levels. |
| 5 | **OWASP WebGoat.NET** | 80 | `http://TARGET/WebGoat/` | `http://TARGET/WebGoat/` | guest/guest or register | ASP.NET | `.aspx` pages; IIS server header | ⚠️ | .NET version of WebGoat. Less maintained than the Java version. Lesson-based, no scoreboard. |
| 6 | **OWASP Hackademic** | 80 | `http://TARGET/` | Challenge list on homepage | Register your own | PHP | WordPress-like interface | ❌ | Standalone vulnerable scenarios. Each challenge is a separate app. No unified scoreboard. |
| 7 | **OWASP SKF (Security Knowledge Framework) Labs** | Various (Docker) | Per-lab URL | N/A | Per-lab | Various | Docker lab containers | ❌ | Each lab is a standalone Docker container targeting one specific vulnerability class. No unified scoreboard. |

---

## Section 2 — Classic Self-Hosted Vulnerable Apps

| # | Application | Default Port(s) | Login / Challenge Page URL | Scoreboard URL | Default Credentials | Stack | Identification Signal | Scoreboard? | Notes |
|---|---|---|---|---|---|---|---|---|---|
| 8 | **DVWA (Damn Vulnerable Web Application)** | 80 (Apache/XAMPP) | `http://TARGET/dvwa/login.php` or `http://TARGET/DVWA/login.php` | `http://TARGET/dvwa/index.php` (challenge menu) | admin / password | PHP / MySQL | `/dvwa/` path; PHP session cookies; Apache | ⚠️ | No scoreboard — vulnerabilities listed in left nav menu. Must run Setup/Reset Database on first run at `/dvwa/setup.php`. Security levels: Low / Medium / High / Impossible. Commonly bundled with Metasploitable 2 at `/dvwa/`. |
| 9 | **bWAPP (Buggy Web Application)** | 80 (Apache/XAMPP) | `http://TARGET/bWAPP/login.php` | `http://TARGET/bWAPP/portal.php` | bee / bug | PHP / MySQL | `/bWAPP/` path; `bee` branding in HTML | ⚠️ | 100+ vulnerabilities organized by OWASP category in a dropdown menu on the portal page. Must run install at `/bWAPP/install.php` on first use. No progress tracking scoreboard. |
| 10 | **Metasploitable 2** | 80 (HTTP), 8180 (Tomcat), 8080 (various) | `http://TARGET/` (main page with app links) | `http://TARGET/` (index lists all apps) | msfadmin / msfadmin (OS login) | Linux VM (multiple apps) | Multiple old services; Apache 2.2.8; Ubuntu 8.04 | ❌ | Not a single app — it's a Linux VM with multiple intentionally vulnerable services and web apps pre-installed. Web apps at port 80: DVWA at `/dvwa/`, Mutillidae at `/mutillidae/`, phpMyAdmin at `/phpmyadmin/`, TWiki at `/twiki/`, tikiwiki at `/tikiwiki/`. Port 8180 hosts Tomcat with default credentials. |
| 11 | **Metasploitable 3** | 80 (Windows IIS or Linux Apache) | `http://TARGET/` | N/A | vagrant / vagrant (Linux); administrator / vagrant (Windows) | Windows Server 2008 R2 or Ubuntu 14.04 | IIS or Apache; multiple services | ❌ | More complex than Metasploitable 2. Contains web apps, services, and network-level vulnerabilities. Designed for intermediate/advanced users. |
| 12 | **Hackazon** | 80 | `http://TARGET/` | `http://TARGET/account` | Register your own | PHP / MySQL | E-commerce storefront appearance | ❌ | Mimics a real e-commerce site (shopping cart, payment system, accounts). No scoreboard. Realistic context makes it good for IDOR, SQLi, CSRF practice. |
| 13 | **VulnHub VMs (general)** | Varies per VM | Varies per VM | Varies per VM | Varies — check VM description | Various | Varies | ❌ | Not a single app — a repository of downloadable CTF-style VMs. Each VM has its own challenge and flag. No scoreboard — find root.txt or flag.txt as proof. |
| 14 | **Google Gruyere** | N/A (runs locally or online at `google-gruyere.appspot.com`) | `http://TARGET/` | `http://google-gruyere.appspot.com/start` | No login required initially | Python (GAE) | Cheese-themed UI; Python framework headers | ❌ | Unique instance per user (session-based). Challenges are documented inline on the platform. Covers XSS, XSRF, path traversal, info disclosure. Simple and beginner-friendly. |
| 15 | **Badstore** | 80 | `http://TARGET/` | `http://TARGET/cgi-bin/badstore.cgi` | admin / admin (check robots.txt for hints) | Perl CGI | Old CGI-based UI; Perl in server headers | ❌ | VM-based. Very old but teaches fundamentals: XSS, SQLi, shopping cart manipulation, hidden field tampering. robots.txt exposes hidden paths. |
| 16 | **Peruggia** | 80 | `http://TARGET/peruggia/` | N/A | admin / admin | PHP | Photo gallery UI at `/peruggia/` | ❌ | Image gallery application with controlled vulnerabilities. Good for file upload, path traversal, and access control testing. |
| 17 | **XVWA (Xtreme Vulnerable Web Application)** | 80 | `http://TARGET/xvwa/` | `http://TARGET/xvwa/` (left-nav menu) | No login required | PHP / MySQL | `/xvwa/` path; bright red UI | ⚠️ | Challenge categories in left nav. Covers OWASP Top 10. No progress tracking. Good for beginners. |
| 18 | **VAmPI** | 5000 (Flask) | `http://TARGET:5000/` | `http://TARGET:5000/docs` (Swagger UI) | Register via API | Python / Flask REST API | Werkzeug/Flask headers; JSON responses; Swagger docs | ⚠️ | REST API-only — no browser UI. All interaction via curl or Burp. Swagger docs at `/docs` list all endpoints. Covers OWASP API Top 10. No scoreboard. |
| 19 | **Damn Vulnerable GraphQL Application (DVGA)** | 5013 (Docker) | `http://TARGET:5013/` | `http://TARGET:5013/graphiql` (GraphQL explorer) | No auth by default | Python / Flask / GraphQL | Port 5013; GraphQL endpoint at `/graphql`; GraphiQL UI | ⚠️ | GraphQL-specific vulnerabilities: introspection abuse, injection, IDOR. GraphiQL browser at `/graphiql` is the challenge interface. No scoreboard. |
| 20 | **Vulnerable WordPress** | 80 | `http://TARGET/wp-login.php` | `http://TARGET/wp-admin/` | admin / password (or varies) | PHP / MySQL / WordPress | WordPress login page; `wp-content` in source | ❌ | Intentionally misconfigured WordPress with outdated plugins and themes. WPScan is the primary tool: `wpscan --url http://TARGET`. Exposes plugin CVEs, user enumeration, XML-RPC abuse. |
| 21 | **SQLi-Labs** | 80 | `http://TARGET/sqli-labs/` | `http://TARGET/sqli-labs/` (index lists all labs) | No login required | PHP / MySQL | `/sqli-labs/` path; lab index page | ⚠️ | 75 SQL injection labs only — covers error-based, blind, time-based, stacked queries. No other vulnerability types. No scoreboard. |
| 22 | **HackSys Extreme Vulnerable Driver (HEVD)** | N/A (kernel driver) | N/A | N/A | N/A | Windows Kernel | Windows driver | ❌ | Not a web app — a Windows kernel driver for kernel exploitation practice (buffer overflows, use-after-free). Included for completeness. |

---

## Section 3 — Online Platforms (No Local Install)

| # | Application | URL | Challenge/Scoreboard Page | Login Required | Cost | Notes |
|---|---|---|---|---|---|---|
| 23 | **PortSwigger Web Security Academy** | `https://portswigger.net/web-security` | `https://portswigger.net/web-security/all-labs` | Yes (free account) | Free | Best structured web security training available. Labs run in browser — no VM needed. Progress tracked per account. Covers every major vuln class with guided + unguided labs. Companion to Burp Suite. |
| 24 | **TryHackMe** | `https://tryhackme.com` | `https://tryhackme.com/dashboard` | Yes | Free + Paid | Browser-based VMs. Rooms are guided challenges. Progress tracked. Good for beginners. OWASP Top 10 room at `/room/owasptop10`. VPN or browser AttackBox required. |
| 25 | **Hack The Box (HTB)** | `https://www.hackthebox.com` | `https://www.hackthebox.com/machines` | Yes | Free + Paid | Competition-style VMs. Submit user.txt and root.txt flags. No in-app scoreboard per machine — global leaderboard. Harder than TryHackMe. Good for intermediate/advanced. |
| 26 | **PentesterLab** | `https://pentesterlab.com` | `https://pentesterlab.com/exercises` | Yes | Free + Paid (Pro) | Structured web security exercises with badges. Progress tracked. Many free labs on SQLi, XSS, code injection. |
| 27 | **HackThisSite** | `https://www.hackthissite.org` | `https://www.hackthissite.org/missions/` | Yes (free) | Free | Classic training site. Mission-based challenges: Basic, Realistic, Application, Programming. Score tracked per account. |
| 28 | **OverTheWire (Bandit/Natas)** | `https://overthewire.org/wargames/` | `https://overthewire.org/wargames/natas/` | SSH/HTTP per level | Free | Natas = web security wargame. Each level is a URL. Password found in current level unlocks next. No scoreboard — flag-based progression. |
| 29 | **PicoCTF** | `https://picoctf.org` | `https://play.picoctf.org/practice` | Yes (free) | Free | Carnegie Mellon CTF platform. Challenges across web, crypto, forensics, binary. Scoreboard per competition event. Good for beginners. |
| 30 | **CTFlearn** | `https://ctflearn.com` | `https://ctflearn.com/challenge/1` | Yes (free) | Free | Community-contributed CTF challenges. Global scoreboard. Web, forensics, crypto, binary categories. |
| 31 | **Root Me** | `https://www.root-me.org` | `https://www.root-me.org/en/Challenges/Web-Client/` | Yes (free) | Free | French platform, English available. Web client and server challenge tracks. Score per challenge. Large library of realistic scenarios. |

---

## Section 4 — Specialised / Category-Specific Apps

| # | Application | Focus Area | Default Port | Key URL | Default Creds | Notes |
|---|---|---|---|---|---|---|
| 32 | **Kubernetes Goat** | Kubernetes / Container Security | Various (K8s cluster) | Per-scenario | N/A | Intentionally vulnerable Kubernetes cluster. Requires a running K8s environment. No scoreboard — scenario guides. |
| 33 | **CloudGoat (Rhino Security Labs)** | AWS Cloud Security | N/A (AWS) | AWS console | IAM key-based | Deploys vulnerable AWS infrastructure. Teaches IAM misconfigs, S3 exposure, privilege escalation in AWS. |
| 34 | **WrongSecrets** | Secrets Management | 8080 (Docker) | `http://TARGET:8080/` | No login | Shows how secrets are mishandled in Docker, Kubernetes, and cloud environments. Challenge list on homepage. |
| 35 | **SSRF Vulnerable Lab** | SSRF Only | 80 | `http://TARGET/` | No login | Single-topic lab for Server-Side Request Forgery. Good for targeted SSRF practice. |
| 36 | **Damn Vulnerable iOS App (DVIA)** | iOS Mobile Security | N/A (iOS app) | Installed on iOS device | N/A | iOS app for mobile pen testing. Covers local data storage, network, authentication, runtime manipulation. |
| 37 | **InsecureBankv2** | Android Mobile Security | N/A (Android APK) | APK on Android device | dinesh / Dinesh@123! | Android banking app. Requires running the companion server. Covers Android-specific vulns. |
| 38 | **OWASP NodeGoat** | Node.js Security | 4000 (Node) | `http://TARGET:4000/login` | admin / Admin_123 | OWASP Top 10 implemented in a Node.js retirement portfolio app. Tutorial mode guides through each vulnerability. |
| 39 | **RailsGoat** | Ruby on Rails Security | 3000 (Rails) | `http://TARGET:3000/login` | admin@example.com / backdoor | Ruby on Rails app covering OWASP Top 10. No scoreboard — vulnerability list in docs. |
| 40 | **PyGoat** | Python / Django Security | 8000 (Django) | `http://TARGET:8000/` | No default (register) | Django-based vulnerable app. Covers OWASP Top 10 in a Python context. Lab list on homepage. |

---

## Section 5 — Quick Identification Cheatsheet

When nmap gives you output, match these signals to identify the app immediately:

| Signal in nmap / curl output | Application | What to do next |
|---|---|---|
| `Bjoern Kimminich` or `OWASP Juice Shop` in HTML | Juice Shop | Go to `/#/score-board` immediately |
| `X-Recruiting: /#/jobs` header | Juice Shop | Confirmed Juice Shop |
| `commonName=OwaspShepherd` in SSL cert | Security Shepherd | HTTPS, register with USN, access dashboard |
| `WebGoat` in page title | WebGoat | Go to `/WebGoat/login`, register, then `/WebGoat/start.mvc` |
| `/dvwa/` path returns 302 | DVWA | Go to `/dvwa/setup.php` first, then `/dvwa/login.php`, admin/password |
| `/mutillidae/` returns 200 | Mutillidae | No login needed, challenges in left nav |
| `/bWAPP/` returns 302 | bWAPP | Run `/bWAPP/install.php`, then login bee/bug |
| `Werkzeug` in Server header + port 5000 | Flask app or VAmPI | Check `/docs` for Swagger, `/api-docs`, spider normally |
| `Werkzeug` + food/employee themed title | Custom Flask app (e.g., NanoCorp) | Gobuster + manual URL guessing |
| `wp-login.php` or `wp-content` in source | WordPress | Run WPScan, try admin/password |
| `JSESSIONID` + redirects to `.jsp` | Java app (WebGoat/Shepherd/custom) | Add `-x jsp` to gobuster, accept SSL cert warnings |
| `Tomcat` in headers + port 8080/8180 | Apache Tomcat | Try `/manager/html` with tomcat/tomcat or admin/admin |
| Port 80 with links to `/dvwa/`, `/mutillidae/` | Metasploitable 2 | Multiple apps, test each path separately |
| `GraphQL` endpoint at `/graphql` | DVGA or custom GraphQL | Use GraphiQL or introspection query to enumerate schema |
| Port 5013 with GraphQL | DVGA | Access `/graphiql` for interactive explorer |

---

## Section 6 — Default Credentials Master List

| Application | Username | Password | Notes |
|---|---|---|---|
| DVWA | admin | password | Set at `/dvwa/setup.php` |
| bWAPP | bee | bug | Set at install |
| Metasploitable 2 (OS) | msfadmin | msfadmin | SSH login |
| Metasploitable 2 Tomcat | tomcat | tomcat | Port 8180 `/manager` |
| Metasploitable 2 phpMyAdmin | root | (blank) | Port 80 `/phpmyadmin/` |
| OWASP NodeGoat | admin | Admin_123 | |
| RailsGoat | admin@example.com | backdoor | |
| InsecureBankv2 | dinesh | Dinesh@123! | |
| WordPress (generic) | admin | admin or password | Check `/wp-login.php` |
| Apache Tomcat (default) | admin / tomcat | admin / tomcat / s3cret | Try all three |
| Juice Shop | (register your own) | — | Creating account is part of challenge |
| WebGoat | (register your own) | — | Register at `/WebGoat/login` |
| Security Shepherd | (register your own) | — | Use USN as username in lab context |
| Mutillidae | No login required | — | Admin panel: admin/adminpass |
| Google Gruyere | (session-based) | — | Each user gets a unique instance |
| XVWA | No login required | — | Open access |
| SQLi-Labs | No login required | — | Open access |

---

## Section 7 — Port Reference by Application

| Port | Application / Service | Protocol |
|---|---|---|
| 80 | DVWA, Mutillidae, bWAPP, Badstore, Metasploitable 2 web | HTTP |
| 443 | Any HTTPS app | HTTPS |
| 3000 | Juice Shop (Docker default), RailsGoat, NodeGoat | HTTP |
| 4000 | OWASP NodeGoat | HTTP |
| 5000 | VAmPI, Flask apps (generic) | HTTP |
| 5013 | Damn Vulnerable GraphQL Application | HTTP |
| 8000 | PyGoat, Django apps | HTTP |
| 8080 | WebGoat, Tomcat (general), Jenkins | HTTP |
| 8180 | Metasploitable 2 Tomcat | HTTP |
| 8443 | Security Shepherd (HTTPS), Tomcat SSL | HTTPS |
| 9090 | WebGoat WebWolf companion | HTTP |
| Non-standard (e.g. 29391, 32893) | Proxied lab apps — content determines app | HTTP/HTTPS |

---

*Last updated: May 2026*
*Covers 40 applications across local, Docker, VM, and online platforms.*
