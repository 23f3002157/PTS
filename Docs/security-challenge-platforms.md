# 🔐 Deliberately Vulnerable Security Practice Applications

A comprehensive reference for security practitioners, pentesters, and learners covering the most popular deliberately vulnerable web applications — including their home pages, dashboard/scoreboard routes, Docker quick-starts, and curated GitHub solution repositories.

---

## Table of Contents

1. [OWASP Juice Shop](#1-owasp-juice-shop)
2. [DVWA — Damn Vulnerable Web Application](#2-dvwa--damn-vulnerable-web-application)
3. [OWASP WebGoat](#3-owasp-webgoat)
4. [bWAPP — Buggy Web Application](#4-bwapp--buggy-web-application)
5. [OWASP Mutillidae II](#5-owasp-mutillidae-ii)
6. [OWASP NodeGoat](#6-owasp-nodegoat)
7. [OWASP RailsGoat](#7-owasp-railsgoat)
8. [HackTheBox](#8-hackthebox)
9. [TryHackMe](#9-tryhackme)
10. [PortSwigger Web Security Academy](#10-portswigger-web-security-academy)
11. [VulnHub](#11-vulnhub)
12. [PicoCTF](#12-picoctf)
13. [Quick Comparison Table](#quick-comparison-table)

---

## 1. OWASP Juice Shop

### Overview
OWASP Juice Shop is widely considered the most modern and sophisticated deliberately insecure web application. Written entirely in **Node.js, Express, and Angular**, it covers vulnerabilities from the entire OWASP Top Ten plus many more real-world flaws. It supports CTF events, security training, and tool benchmarking.

### Key Details

| Field | Info |
|---|---|
| **Stack** | Node.js + Express + Angular |
| **Home Page** | https://owasp.org/www-project-juice-shop/ |
| **Project Site** | https://owasp-juice.shop |
| **GitHub (Official)** | https://github.com/juice-shop/juice-shop |
| **Docker** | `docker run --rm -p 3000:3000 bkimminich/juice-shop` |
| **Default Port** | `3000` |

### Dashboard / Scoreboard Routes

| Route | Description |
|---|---|
| `/#/score-board` | Main scoreboard (finding it is itself a challenge!) |
| `/api/challenges` | REST API — lists all challenges and completion status |
| `/api/challenges/?completed=true` | Filters only completed challenges |
| `/#/administration` | Admin panel (requires admin login) |
| `/metrics` | Prometheus metrics endpoint |

### Solution / Writeup Repositories

| Repository | Notes |
|---|---|
| https://github.com/refabr1k/owasp-juiceshop-solutions | Classic community solutions, OSWE-focused |
| https://github.com/Whyiest/Juice-Shop-Write-up | Step-by-step by difficulty (1–6 stars), with remediation |
| https://github.com/apox64/OWASP-Juice-Shop-Write-Up | Detailed write-up covering SQL injection, XSS, JWT, etc. |
| https://github.com/akash-pawar/owasp-juice-shop | Solutions through Level 5 with explanations |
| https://github.com/blueorionn/owasp-juice-shop-solutions | Solutions & walkthroughs, MIT licensed |
| https://github.com/WebGoat/WebGoat/wiki/Main-Exploits | (See WebGoat section, but also references Juice Shop patterns) |

### Vulnerability Coverage
- SQL Injection, XSS (Reflected, Stored, DOM)
- Broken Authentication & JWT attacks
- Broken Access Control
- Sensitive Data Exposure
- XXE, SSRF, CSRF
- Insecure Deserialization
- Business Logic Flaws
- Security Misconfiguration
- Race Conditions

---

## 2. DVWA — Damn Vulnerable Web Application

### Overview
DVWA is the go-to beginner-friendly vulnerable app, built in **PHP/MySQL**. Each vulnerability module has **Low, Medium, High, and Impossible** difficulty levels with visible source code, making it ideal for understanding root causes and practicing with tools like Burp Suite and SQLMap.

### Key Details

| Field | Info |
|---|---|
| **Stack** | PHP + MySQL |
| **Home Page** | https://dvwa.co.uk |
| **GitHub (Official)** | https://github.com/digininja/DVWA |
| **Docker** | `docker run --rm -it -p 80:80 vulnerables/web-dvwa` |
| **Default Port** | `80` |
| **Default Creds** | `admin / password` |

### Dashboard / Scoreboard Routes

| Route | Description |
|---|---|
| `/DVWA/` or `/` | Main landing page after setup |
| `/DVWA/security.php` | Set security level (Low/Medium/High/Impossible) |
| `/DVWA/setup.php` | Create/Reset the database |
| `/DVWA/vulnerabilities/` | Directory of all vulnerability modules |

> ⚠️ DVWA does not have a CTF-style scoreboard — progress tracking is manual. The security level page at `/security.php` acts as the configuration "dashboard".

### Vulnerability Modules
```
/vulnerabilities/brute/        — Brute Force
/vulnerabilities/sqli/         — SQL Injection
/vulnerabilities/sqli_blind/   — Blind SQL Injection
/vulnerabilities/xss_r/        — XSS Reflected
/vulnerabilities/xss_s/        — XSS Stored
/vulnerabilities/xss_d/        — XSS DOM
/vulnerabilities/exec/         — Command Injection
/vulnerabilities/fi/           — File Inclusion (LFI/RFI)
/vulnerabilities/upload/       — File Upload
/vulnerabilities/csrf/         — CSRF
/vulnerabilities/captcha/      — Insecure CAPTCHA
/vulnerabilities/javascript/   — JavaScript
/vulnerabilities/weak_id/      — Weak Session IDs
/vulnerabilities/authbypass/   — Authorization Bypass
```

### Solution / Writeup Repositories

| Repository | Notes |
|---|---|
| https://github.com/Aftab700/DVWA-Writeup | Comprehensive writeups across all security levels |
| https://github.com/j0wittmann/Attacking-DVWA | Step-by-step guide per vulnerability (low/mid/high .md files) |
| https://github.com/VVVI5HNU/DVWA | All challenges across Low/Medium/High/Impossible |
| https://github.com/keewenaw/dvwa-guide-2019 | Detailed notes, Kali + XAMPP setup oriented |
| https://github.com/UnpredictablePrashant/DVWA-solution | Walkthrough of all DVWA challenges |
| https://github.com/kashrathod19/SQL-Injection-DVWA-SOLUTION | Deep-dive specifically on SQL Injection per level |

---

## 3. OWASP WebGoat

### Overview
WebGoat is OWASP's **Java-based** intentionally insecure application. Unlike DVWA, it follows a structured guided-learning model — each lesson explains the vulnerability, demonstrates the attack, and requires you to exploit it before proceeding. Paired with **WebWolf** (a helper server for receiving callbacks).

### Key Details

| Field | Info |
|---|---|
| **Stack** | Java (Spring Boot) |
| **Home Page** | https://owasp.org/www-project-webgoat/ |
| **GitHub (Official)** | https://github.com/WebGoat/WebGoat |
| **Docker** | `docker run -it -p 127.0.0.1:8080:8080 -p 127.0.0.1:9090:9090 webgoat/webgoat` |
| **Default Ports** | WebGoat: `8080`, WebWolf: `9090` |

### Dashboard / Scoreboard Routes

| Route | Description |
|---|---|
| `http://localhost:8080/WebGoat/` | Main application entry point |
| `http://localhost:8080/WebGoat/login` | Login page |
| `http://localhost:9090/WebWolf/` | WebWolf companion (receives links, files, etc.) |
| `http://localhost:8080/WebGoat/lesson_progress/` | Tracks lesson completion per user |

> WebGoat does not have a traditional "scoreboard." Progress is tracked per-lesson within the left-side navigation panel. Each lesson shows a green checkmark when completed.

### Lesson Categories
- Injection (SQL, NoSQL, XML, Path Traversal)
- Broken Authentication
- Sensitive Data Exposure
- Broken Access Control / IDOR
- Security Misconfiguration
- Cross-Site Scripting (XSS)
- Insecure Deserialization
- Using Components with Known Vulnerabilities
- JWT Token Attacks
- Request Forgeries (CSRF, SSRF)

### Solution / Writeup Repositories

| Repository | Notes |
|---|---|
| https://github.com/WebGoat/WebGoat/wiki/Main-Exploits | Official wiki with exploit notes per lesson |
| https://github.com/WebGoat/WebGoat/wiki/(Almost)-Fully-Documented-Solution-(en) | Near-complete official solution guide |
| https://github.com/vernjan/webgoat | Selected solutions for WebGoat 8.0.0.M26 |
| https://github.com/an1604/WebGoat-Solutions- | OWASP Top 10 solutions with proof of work |

---

## 4. bWAPP — Buggy Web Application

### Overview
bWAPP (Buggy Web Application) holds the record for **breadth** — over **100 vulnerability types** in a single application, spanning OWASP Top 10, WASC Threat Classification, and beyond. Built in PHP/MySQL. The companion VM "bee-box" comes pre-installed. Login credentials: `bee / bug`.

### Key Details

| Field | Info |
|---|---|
| **Stack** | PHP + MySQL |
| **Home Page** | http://www.itsecgames.com |
| **Bugs List** | http://www.itsecgames.com/bugs.htm |
| **SourceForge** | https://sourceforge.net/projects/bwapp/ |
| **GitHub (mirror)** | https://github.com/ajpalok/bWAPP |
| **Docker** | `docker run -d -p 80:80 raesene/bwapp` |
| **Default Creds** | `bee / bug` |

### Dashboard / Scoreboard Routes

| Route | Description |
|---|---|
| `http://localhost/bWAPP/install.php` | First-time database setup |
| `http://localhost/bWAPP/login.php` | Login page |
| `http://localhost/bWAPP/portal.php` | Main bug portal / challenge selection |
| `http://localhost/bWAPP/bugs.php?bug=<id>` | Individual bug challenge by ID |

> bWAPP does not have a formal scoreboard. The `portal.php` page acts as the challenge hub, with a dropdown to select bugs by category and difficulty (low/medium/high).

### Vulnerability Coverage (Highlights beyond OWASP Top 10)
- Heartbleed (simulated), Shellshock (simulated)
- Drupageddon SQL Injection
- Server Side Request Forgery (SSRF)
- HTML5 ClickJacking, CORS issues
- HTTP Verb Tampering, HTTP Response Splitting
- XML External Entity (XXE) attacks
- SMTP/LDAP/iFrame/SSI/OS Command Injection
- Insecure DistCC, FTP, NTP, Samba, SNMP configurations

### Solution / Writeup Repositories

| Repository | Notes |
|---|---|
| https://github.com/kashrathod19/XSS-BWAPP-SOLUTION | XSS challenge solutions (Reflected, Stored, DOM) |
| https://github.com/jehy-security/bwapp | Source code mirror with detailed README |

---

## 5. OWASP Mutillidae II

### Overview
Mutillidae II is OWASP's PHP-based training platform with **40+ vulnerabilities** covering OWASP Top Ten from 2007 through 2017. It features built-in hints and tutorials, bubble-hints on vulnerable elements, a switchable secure/insecure mode, and a one-click database reset. Pre-installed on Metasploitable 2 and SamuraiWTF.

### Key Details

| Field | Info |
|---|---|
| **Stack** | PHP + MySQL + Apache |
| **Home Page** | https://owasp.org/www-project-mutillidae-ii/ |
| **GitHub (Official)** | https://github.com/webpwnized/mutillidae |
| **Docker** | `git clone https://github.com/webpwnized/mutillidae-docker.git` |
| **Default Port** | `80` (or `8888` in some Docker setups) |

### Dashboard / Scoreboard Routes

| Route | Description |
|---|---|
| `http://localhost/mutillidae/` | Main landing page |
| `http://localhost/mutillidae/index.php` | Application home |
| `http://localhost/mutillidae/set-up-database.php` | Database initialization |
| `http://localhost/mutillidae/index.php?page=<vuln-page>` | Challenge navigation via `page` parameter |
| `http://localhost/mutillidae/index.php?page=user-info.php` | Example vulnerable page (SQLi) |

> Mutillidae does not have a scoreboard. The top navigation menu categorizes challenges by OWASP category (Injection, XSS, Authentication, etc.) with hint levels (0, 1, 2).

### Solution / Writeup Repositories

| Repository | Notes |
|---|---|
| https://github.com/Yugi71120/OWASP_Mutillidae-walkthrough-writeup | Full walkthrough and writeup |
| https://github.com/webpwnized/mutillidae | Official repo — includes video tutorial links |
| https://github.com/dev-angelist/Writeups-and-Walkthroughs | Multi-platform writeups including Mutillidae section |

---

## 6. OWASP NodeGoat

### Overview
NodeGoat is OWASP's **Node.js/Express/MongoDB** vulnerable application, specifically designed to demonstrate how OWASP Top 10 risks manifest in JavaScript server-side code. It includes a built-in tutorial mode showing vulnerable code alongside secure fix examples.

### Key Details

| Field | Info |
|---|---|
| **Stack** | Node.js + Express + MongoDB |
| **Home Page** | https://owasp.org/www-project-node.js-goat/ |
| **GitHub (Official)** | https://github.com/OWASP/NodeGoat |
| **Docker** | `docker-compose up` (docker-compose.yml included in repo) |
| **Default Port** | `4000` (node) / `5000` (nodemon) |

### Dashboard / Scoreboard Routes

| Route | Description |
|---|---|
| `http://localhost:4000/` | Landing/login page |
| `http://localhost:4000/login` | User login |
| `http://localhost:4000/tutorial` | Built-in tutorial mode (shows A1–A10 explanations) |
| `http://localhost:4000/allocations/:userId` | Vulnerable allocations page (NoSQL Injection target) |
| `http://localhost:4000/research` | Research page (Unvalidated Redirects) |

> NodeGoat does not have a gamified scoreboard. The `/tutorial` routes are the closest equivalent — they show vulnerable code, attack demonstrations, and secure fixes side-by-side.

### Unique Vulnerabilities (Node.js specific)
- NoSQL Injection (MongoDB `$where` queries)
- MEAN stack-specific misconfigurations
- RegEx DoS (ReDoS)
- HTTP Parameter Pollution in Express

### Solution / Writeup Repositories

| Repository | Notes |
|---|---|
| https://github.com/OWASP/NodeGoat/wiki | Official tutorial wiki with exploitation notes |
| https://github.com/lirantal/NodeGoat-training | Training fork with Heroku deploy instructions |

---

## 7. OWASP RailsGoat

### Overview
RailsGoat is a deliberately vulnerable **Ruby on Rails** application covering OWASP Top 10 vulnerabilities as they manifest in Rails 3–8. It serves as a hands-on training platform for Rails developers and security professionals, with a comprehensive wiki documenting each vulnerability.

### Key Details

| Field | Info |
|---|---|
| **Stack** | Ruby on Rails |
| **Home Page** | https://owasp.org/www-project-railsgoat/ |
| **GitHub (Official)** | https://github.com/OWASP/railsgoat |
| **Wiki / Solutions** | https://github.com/OWASP/railsgoat/wiki |
| **Docker** | `docker-compose up` |
| **Default Port** | `3000` |

### Dashboard / Scoreboard Routes

| Route | Description |
|---|---|
| `http://localhost:3000/` | Application landing page |
| `http://localhost:3000/login` | Login (default user: `admin@metacorp.com / admin1234`) |
| `http://localhost:3000/users` | User listing (IDOR target) |
| `http://localhost:3000/admin` | Admin dashboard (Broken Access Control target) |

> RailsGoat does not have a scoreboard. The GitHub wiki serves as the progress/solution guide.

### Vulnerability Coverage
- Mass Assignment (Rails-specific)
- SQL Injection in ActiveRecord
- XSS, CSRF
- Insecure Direct Object References
- Unvalidated Redirects and Forwards
- Broken Authentication (session management)
- Security Misconfiguration

### Solution / Writeup Repositories

| Repository | Notes |
|---|---|
| https://github.com/OWASP/railsgoat/wiki | Official wiki with per-vulnerability write-ups (R1–R10) |

---

## 8. HackTheBox

### Overview
HackTheBox (HTB) is an online platform with realistic CTF-style machines, challenges, and professional labs. Unlike self-hosted apps, HTB machines run on cloud infrastructure. Users gain points and ranks by "pwning" (rooting) machines. Excellent for intermediate-to-advanced practitioners.

### Key Details

| Field | Info |
|---|---|
| **Type** | Online Platform (cloud-hosted) |
| **Home Page** | https://www.hackthebox.com |
| **Academy** | https://academy.hackthebox.com |
| **Pricing** | Free tier + VIP ($18/month) |

### Dashboard / Progress Routes

| Route | Description |
|---|---|
| `https://www.hackthebox.com/dashboard` | User dashboard |
| `https://www.hackthebox.com/machines` | Active machines list |
| `https://www.hackthebox.com/challenges` | Web, Crypto, Forensics, Reversing challenges |
| `https://www.hackthebox.com/leaderboard` | Global rankings |
| `https://app.hackthebox.com/profile/<username>` | Per-user profile and stats |

### Solution / Writeup Repositories

| Repository | Notes |
|---|---|
| https://0xdf.gitlab.io | One of the best HTB writeup blogs (0xdf); covers hundreds of machines |
| https://github.com/DhilipSanjay/CTFs | Walkthrough notes for HTB, TryHackMe, and PortSwigger |

---

## 9. TryHackMe

### Overview
TryHackMe (THM) is the most beginner-friendly online platform, featuring guided "rooms" with step-by-step explanations, in-browser attack machine (no VPN needed), and structured learning paths for CompTIA Security+, CEH, OSCP prep, and more.

### Key Details

| Field | Info |
|---|---|
| **Type** | Online Platform (cloud-hosted) |
| **Home Page** | https://tryhackme.com |
| **Pricing** | Free tier + Premium ($10–$14/month) |

### Dashboard / Progress Routes

| Route | Description |
|---|---|
| `https://tryhackme.com/dashboard` | Main learner dashboard |
| `https://tryhackme.com/hacktivities` | Browse all rooms and challenges |
| `https://tryhackme.com/path` | Learning paths (Beginner, Web, SOC, etc.) |
| `https://tryhackme.com/leaderboards` | Global and monthly rankings |
| `https://tryhackme.com/p/<username>` | User profile with badges and stats |

### Solution / Writeup Repositories

| Repository | Notes |
|---|---|
| https://github.com/DhilipSanjay/CTFs | TryHackMe + HTB + PortSwigger combined writeups |

---

## 10. PortSwigger Web Security Academy

### Overview
PortSwigger Web Security Academy (created by the makers of Burp Suite) is a free, browser-based learning platform exclusively focused on **web application security**. It covers 20+ vulnerability categories with theory + interactive labs. Considered the best resource for web-focused certifications (BSCP, eWPT).

### Key Details

| Field | Info |
|---|---|
| **Type** | Online Platform (free) |
| **Home Page** | https://portswigger.net/web-security |
| **Labs** | https://portswigger.net/web-security/all-labs |
| **Pricing** | Completely Free |

### Dashboard / Progress Routes

| Route | Description |
|---|---|
| `https://portswigger.net/web-security/dashboard` | Learner dashboard with progress |
| `https://portswigger.net/web-security/all-labs` | All labs by topic and difficulty |
| `https://portswigger.net/web-security/certification` | BSCP exam info |

### Lab Categories
- SQL Injection, XXE, SSRF
- XSS, CSRF, CORS
- Clickjacking, DOM-based vulnerabilities
- HTTP Host Header attacks
- OAuth and OpenID Connect
- JWT attacks
- Web Cache Poisoning / Deception
- Prototype Pollution
- GraphQL API vulnerabilities
- Business Logic Vulnerabilities

### Solution / Writeup Repositories

| Repository | Notes |
|---|---|
| https://github.com/DhilipSanjay/CTFs | PortSwigger Academy solutions alongside CTF writeups |

---

## 11. VulnHub

### Overview
VulnHub hosts downloadable **virtual machine images** (`.ova` / `.vmdk`) designed to be vulnerable and exploitable. Machines cover web application, network, privilege escalation, and Active Directory scenarios. Ideal for offline/local practice.

### Key Details

| Field | Info |
|---|---|
| **Type** | Downloadable VMs (VirtualBox / VMware) |
| **Home Page** | https://www.vulnhub.com |
| **VM Index** | https://www.vulnhub.com/?q=web+app |

### Dashboard / Progress Routes
VulnHub is a download-and-run platform with no built-in dashboard. Writeups and solutions are community-published on personal blogs and GitHub.

Popular prebuilt VMs include applications at these default ports once running:
```
DVWA          → :1335 or :80
Mutillidae    → :1336
WebGoat       → :1337/WebGoat
bWAPP         → :8080
Juice Shop    → :3000
```

---

## 12. PicoCTF

### Overview
PicoCTF is a **free, beginner-friendly CTF** run by Carnegie Mellon University, focused on teaching cybersecurity through gamified challenges. Covers web exploitation, binary exploitation, cryptography, reverse engineering, and forensics. Open year-round as a practice archive.

### Key Details

| Field | Info |
|---|---|
| **Type** | Online CTF Platform (free) |
| **Home Page** | https://picoctf.org |
| **Practice Arena** | https://play.picoctf.org |

### Dashboard / Progress Routes

| Route | Description |
|---|---|
| `https://play.picoctf.org/practice` | All practice challenges |
| `https://play.picoctf.org/login` | Login page |
| `https://play.picoctf.org/events` | Active and past competitions |
| `https://play.picoctf.org/users/<username>` | User profile and score |

---

## Quick Comparison Table

| App | Stack | Type | Difficulty | Scoreboard Route | Docker |
|---|---|---|---|---|---|
| **OWASP Juice Shop** | Node.js/Angular | Self-host | Beginner–Advanced | `/#/score-board` | ✅ |
| **DVWA** | PHP/MySQL | Self-host | Beginner | `/security.php` (config page) | ✅ |
| **WebGoat** | Java/Spring | Self-host | Beginner–Intermediate | Per-lesson checkmarks | ✅ |
| **bWAPP** | PHP/MySQL | Self-host | Beginner–Advanced | `/portal.php` | ✅ |
| **Mutillidae II** | PHP/MySQL | Self-host | Beginner–Intermediate | Top-nav menu | ✅ |
| **NodeGoat** | Node.js/MongoDB | Self-host | Intermediate | `/tutorial` routes | ✅ |
| **RailsGoat** | Ruby on Rails | Self-host | Intermediate | GitHub wiki | ✅ |
| **HackTheBox** | Cloud | Online | Intermediate–Advanced | `/dashboard` | N/A |
| **TryHackMe** | Cloud | Online | Beginner–Intermediate | `/dashboard` | N/A |
| **PortSwigger WSA** | Cloud | Online (Free) | Beginner–Advanced | `/web-security/dashboard` | N/A |
| **VulnHub** | VM Download | Offline | Varies | N/A | N/A |
| **PicoCTF** | Cloud | Online (Free) | Beginner | `/practice` | N/A |

---

## Running Multiple Apps Together (Docker Compose)

For running several vulnerable apps in one lab environment, community tools like [webvuln-runner](https://github.com/yusufarbc/webvuln-runner) provide a TUI/dashboard to spin up 15+ apps at once:

```bash
# Debian/Ubuntu/Kali
sudo su
wget -O - https://raw.githubusercontent.com/yusufarbc/webvuln-runner/main/installers/debian/install.sh | bash
```

Or use a manual Docker Compose with multiple services (Juice Shop on :3000, DVWA on :80, WebGoat on :8080, bWAPP on :8081).

---

## ⚠️ Safety Warning

All these applications are **deliberately insecure**. Never run them on:
- Public-facing servers or cloud instances with open ports
- Networks you do not control
- Systems connected to sensitive data

Always use an **isolated local network**, a dedicated VM, or Docker with `127.0.0.1` port bindings only.

---

*Document compiled May 2026. All URLs verified against current project pages.*
