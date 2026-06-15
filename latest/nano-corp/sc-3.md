# Scenario-3 — "NanoCorp Bites" — Full Reference

## 1. Docker Commands to Inspect Scenario-3

```bash
# Confirm container name and port
docker ps -a | grep scenario-3

# Check entrypoint / working dir / cmd
docker inspect sclab-scenario-3 --format '{{.Config.Cmd}}'
docker inspect sclab-scenario-3 --format '{{.Config.Entrypoint}}'
docker inspect sclab-scenario-3 --format '{{.Config.WorkingDir}}'

# Get host port mapping via proxy
docker inspect sclab-s3-proxy --format '{{.Config.Cmd}}'

# List app directory contents
docker exec sclab-scenario-3 python3 -c "import os; print(os.listdir('/app'))"

# View logs
docker logs sclab-scenario-3 --tail 50
```

## 2. Path to Main Program

```
/app/app.py        # Flask application source — all routes & vuln logic
/app/seed.sql      # DB schema + seed data + credentials
/app/requirements.txt
/app/templates/    # Jinja2 templates
/app/static/       # CSS/JS/images
```

Read commands:

```bash
docker exec sclab-scenario-3 python3 -c "print(open('/app/app.py').read())"
docker exec sclab-scenario-3 python3 -c "print(open('/app/seed.sql').read())"
docker exec sclab-scenario-3 python3 -c "print(open('/app/requirements.txt').read())"
```

## 3. All Challenges Found in the App

The** **`CHALLENGES` list in** **`app.py` only shows 2 on the** **`/scoreboard` page, but the** **`challenge_completions` table tracks** ****5 total** vulnerabilities via** **`mark_solved()`:

| Key               | Name               | On Scoreboard? | Difficulty | Category              |
| ----------------- | ------------------ | -------------- | ---------- | --------------------- |
| `reflected_xss` | Reflected XSS      | Yes            | Easy       | XSS                   |
| `stored_xss`    | Stored XSS         | Yes            | Medium     | XSS                   |
| `sqli`          | SQL Injection      | No (hidden)    | —         | Injection             |
| `idor`          | IDOR               | No (hidden)    | —         | Broken Access Control |
| `admin_bypass`  | Admin Panel Bypass | No (hidden)    | —         | Broken Access Control |

Seeded credentials (from** **`seed.sql`):

| Username | Password  | Role  |
| -------- | --------- | ----- |
| admin    | sunshine1 | admin |
| jsmith   | burger99  | user  |

## 4. Solutions / Steps for Each Challenge

### Reflected XSS (`reflected_xss`)

**Location:** `/restaurants?search=` **Code:** `query` is rendered via** **`Markup(query)`, bypassing auto-escape.** ****Steps:**

1. Login as any user.
2. Navigate to:
   ```
   /restaurants?search=<script>alert(1)</script>
   ```
3. The page reflects the payload unescaped → solved automatically (any input containing** **`<` triggers** **`mark_solved`).

### Stored XSS (`stored_xss`)

**Location:** `/profile` (POST)** ****Code:** `display_name` saved raw, rendered via** **`Markup()`.** ****Steps:**

1. Go to** **`/profile`.
2. Set "Display Name" to:
   ```
   <script>alert(document.cookie)</script>
   ```
3. Submit. Solved instantly (detected before storing). Payload also persists and fires on every profile view.

### SQL Injection (`sqli`)

**Location:** `/cart/checkout` (POST),** **`comment` field** ****Code:**

```python
sql = f"INSERT INTO orders (user_id, comment, status) VALUES ({user['id']}, '{comment}', 'placed')"
```

String concatenation — classic injection point.** ****Detection:** needs a** **`'` AND one of:** **`union, select, drop, insert, delete, update, or 1, or 0, -- , -- -, #` **Steps:**

1. Add any item to cart.
2. Go to checkout, enter comment:

   ```
   ', 'placed'); DROP TABLE cart_items-- 
   ```

   or simpler to just trigger detection without breaking the query:

   ```
   test', 'placed') -- 
   ```
3. Submit →** **`sqli` marked solved.

> Note: True exploitation (e.g. UNION-based extraction) is possible since input is unescaped — but for the auto-detector, even a basic payload with** **`'` + keyword suffices.

### IDOR (`idor`)

**Location:** `/orders/<order_id>` **Code:** No ownership check —** **`SELECT * FROM orders WHERE id = %s` regardless of** **`user_id`.** ****Steps:**

1. Login as a user that is NOT jsmith (e.g. register a new account, wait 60s for auto-approval, or login as admin).
2. Visit:

   ```
   /orders/1/orders/2/orders/3
   ```

   (jsmith's seeded orders, user_id=2)
3. If your** **`user['id'] != order['user_id']`,** **`idor` is marked solved.

### Admin Bypass (`admin_bypass`)

**Location:** `/admin` **Code:** No role check in the route — only the template hides admin controls.** ****Steps:**

1. Login as** **`jsmith / burger99` (role='user').
2. Navigate directly to:
   ```
   /admin
   ```
3. Page renders fully (pending users list etc.) →** **`admin_bypass` marked solved since** **`user['role'] != 'admin'`.

## 5. If Scenario-3 Is Modified — General Recon Procedure

### Step A — Find the Container

```bash
docker ps -a
docker ps --format "table {{.Names}}\t{{.Image}}\t{{.Ports}}"
```

Look for the scenario-3 entry (port 5000 typically = Flask, 8080/8443 = Java/Tomcat, 3000 = Node).

### Step B — Identify the Stack & Entry Point

```bash
docker inspect <container> --format '{{.Config.Cmd}}'
docker inspect <container> --format '{{.Config.Entrypoint}}'
docker inspect <container> --format '{{.Config.WorkingDir}}'
docker exec <container> cat /docker-entrypoint.sh 2>/dev/null
```

### Step C — Locate the App Directory

```bash
# Try common runtimes — pick whichever exists
docker exec <container> python3 -c "import os; print(os.listdir('/'))"
docker exec <container> /nodejs/bin/node -e "console.log(require('fs').readdirSync('/'))"

# Then drill into likely app dirs
docker exec <container> python3 -c "
import os
for d in ['/app','/src','/code','/usr/src/app','/opt/app','/srv']:
    if os.path.exists(d):
        print(d, '->', os.listdir(d))
"
```

### Step D — Read the Main Source File

```bash
docker exec <container> python3 -c "print(open('/app/app.py').read())"
# or for Node:
docker exec <container> /nodejs/bin/node -e "console.log(require('fs').readFileSync('/app/server.js','utf8'))"
```

### Step E — Find ALL Challenges (not just scoreboard)

Search the source for the patterns that mark completions — search for keywords like** **`mark_solved`,** **`solveIf`,** **`challenge`,** **`flag`,** **`CTF`,** **`completed`:

```bash
docker exec <container> python3 -c "
import os
for root, dirs, files in os.walk('/app'):
    for f in files:
        if f.endswith(('.py','.js','.ts','.json','.yml','.sql')):
            p = os.path.join(root, f)
            try:
                content = open(p, errors='ignore').read()
                for kw in ['mark_solved','solveIf','challenge','flag','CTF','completed','vuln']:
                    if kw.lower() in content.lower():
                        print(f'{p}: contains \"{kw}\"')
                        break
            except: pass
"
```

### Step F — Read the Seed/DB File for Credentials & Hints

```bash
docker exec <container> python3 -c "print(open('/app/seed.sql').read())"
```

Look for comments (`--<span class="Apple-converted-space"> </span>`) — these often contain intentional hints about vuln locations and credentials, as seen in this scenario.

### Step G — Cross-Reference Routes ↔ Challenge Keys

For each** **`mark_solved(user_id, 'xxx')` or equivalent call found, trace:

1. What route/endpoint it's in
2. What input field triggers it
3. What detection condition (`_detect_xss`,** **`_detect_sqli`, ownership checks, role checks, etc.) must be satisfied

This gives you the exact payload/steps needed — same methodology applied above for NanoCorp Bites.

### Step H — Enumerate Hidden Routes

```bash
docker exec <container> python3 -c "
content = open('/app/app.py').read()
import re
routes = re.findall(r\"@app\.route\('([^']+)'\)\", content)
print('\n'.join(routes))
"
```

This lists every route — including ones not linked from the UI navigation, which often hide additional challenges (admin panels, debug endpoints, API-only routes).
