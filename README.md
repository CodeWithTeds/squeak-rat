<div align="center">

<img src="rat.png" width="420" alt="RAT" style="border-radius:24px; box-shadow: 0 20px 60px rgba(124,58,237,0.35);" />

<br/>

<h1 style="color:#7c3aed; font-size:42px; margin: 16px 0 4px 0; letter-spacing: -1px;">🐀 RAT <span style="color:#a78bfa; font-weight:300;">squeak/rat</span></h1>

<p style="color:#8b5cf6; font-size:16px; letter-spacing: 4px; text-transform:uppercase; margin:0;">Laravel Security & Behavior Analyzer • 2026 Edition</p>

<p style="color:#a1a1aa; font-size:14px; margin-top:8px;">Terminal forensic tool for Laravel — <i style="color:#c4b5fd;">RAT follows the trail.</i></p>

<p>
<img src="https://img.shields.io/badge/PHP-8.1%E2%80%938.4-7c3aed?style=for-the-badge&logo=php&logoColor=white" />
<img src="https://img.shields.io/badge/Laravel-9%20%7C%2010%20%7C%2011%20%7C%2012-8b5cf6?style=for-the-badge&logo=laravel&logoColor=white" />
<img src="https://img.shields.io/badge/Terminal-Violet_2026-7c3aed?style=for-the-badge" />
<img src="https://img.shields.io/badge License-MIT-a78bfa?style=for-the-badge" />
</p>

<p style="color:#71717a; font-size:12px;">Whole codebase • Vendor excluded • Monolith + Modular Monolith + Microservices • 0 or ALL findings • Any architecture</p>

</div>

---

<div style="background: linear-gradient(135deg, #0a0a0f 0%, #1a0b2e 50%, #0a0a0f 100%); border: 1px solid #2d1b4e; border-radius:16px; padding:24px; margin:24px 0;">

### <span style="color:#a78bfa;">▌</span> Why RAT?

<pre style="color:#c4b5fd; background:transparent; border:none; margin:0; font-size:13px;">
Developer:  "What happens if this endpoint is called?"

RAT:        "Let me show you."
            Route → Middleware → Controller → Service → Model → Observer → Job → External
            with <span style="color:#8b5cf6;">SOURCE → SINK</span> taint, <span style="color:#a78bfa;">CONFIDENCE</span>, and <span style="color:#7c3aed;">FIX</span>.
</pre>

> Not a linter. Not a dashboard. Not 500 warnings. **3 important findings > 300 noise.**

</div>

---

## <span style="color:#8b5cf6;">◆</span> Install — 2026

### Standalone (any PHP project, no Laravel required)

```bash
git clone https://github.com/squeak/rat.git squeak-rat && cd squeak-rat
composer install
chmod +x bin/rat
php bin/rat --help
# optional global
ln -s $(pwd)/bin/rat /usr/local/bin/rat
rat --deep
```

### Laravel Package `squeak/rat`

```bash
composer require squeak/rat --dev
php artisan vendor:publish --tag=rat-config  # → config/rat.php
php artisan rat --help
```

> **Requires:** `PHP ^8.1|^8.2|^8.3|^8.4`, `ext-json`, `ext-mbstring` · `ext-gd` optional (true-color `rat.png` half-block `▀` — falls back to violet block letters `█████╗` on plain terminals) · `nikic/php-parser ^4|^5` · `symfony/console ^6|^7|^8` · `illuminate/* ^9|^10|^11|^12`

---

## <span style="color:#8b5cf6;">◆</span> Banner First — Violet 2026

Every run starts with `rat.png` **before** scanning — `src/Support/RatBanner.php:32` + `src/Support/TerminalImage.php:26`:

* **Inline** (iTerm2 / WezTerm / VSCode / Ghostty / Kitty) → OSC 1337 `rat.png` image
* **True-color fallback** (any terminal with GD) → half-block `▀` 36×18 violet-shaded RAT
* **Plain** (`--no-image` or no GD) → violet block letters

```text
  ██████╗  █████╗ ████████╗
  ██╔══██╗██╔══██╗╚══██╔══╝  🐀 RAT — Laravel Security & Behavior Analyzer
  ██████╔╝███████║   ██║     RAT follows the trail.  2026 VIOLET • #8b5cf6
  ──────────────────────────────────────────────────────────
  🐀 RAT // DEEP SECURITY SCAN  Advanced data-flow + behavior analysis
```

`--no-image` disables image, `--compact` single line for CI.

---

## <span style="color:#8b5cf6;">◆</span> Quick Start

```bash
# 1) Scan — interactive chooser on TTY (vendor/storage/public/.git always excluded)
php artisan rat
# ? What should RAT scan?
#   [0] Whole codebase (all PHP — recommended)      ← default '.'
#   [1] Laravel lot (monolith + modular + microservices)
#   [2] Security scan (22 families → SECURITYSCAN.md)
#   [3] Deep security scan — Advanced data-flow + behavior
#   [4] Use config/rat.php
#   [5] Custom — you type paths

# 2) Flags — no prompt, CI friendly
php artisan rat --all --no-image                 # whole codebase
php artisan rat --path=app,routes                # limited
php artisan rat --security --no-image            # security scan
php artisan rat --deep --no-image                # deep scan
php artisan rat --deep --format=json > report.json
```

**Standalone `bin/rat` mirrors all flags:**
```bash
php bin/rat --deep
php bin/rat --security --all
php bin/rat --path=Modules/Billing --format=json
rat --deep  # after ln -s
```

---

## <span style="color:#8b5cf6;">◆</span> What RAT Sees

| <span style="color:#8b5cf6;">Scan</span> | **Checks** |
|---|---|
| **Whole codebase** | All PHP under `.` except `exclude` — any architecture |
| **Laravel lot** | `app, routes, config, database, resources, Modules, Domain, src, packages, services, apps, microservices, tests` |
| **Security scan** | 22 families — `SECURITYSCAN.md:17` |
| **Deep** | Same + `depth=12`, lower cap, full tainted chain + hidden behavior |

**Vulnerability families (defensive only, `Potential dangerous flow` + `Severity` + `Confidence`):**

<div style="display:grid; grid-template-columns: 1fr 1fr; gap:8px; font-size:12px; color:#a1a1aa;">

`[✓] Injection` `[✓] SQL injection` `[✓] Command injection` `[✓] XSS` `[✓] Path traversal` `[✓] SSRF` `[✓] Deserialization` `[✓] File upload` `[✓] Auth weak` `[✓] IDOR / Authz` `[✓] Mass assignment`

`[✓] Open redirect` `[✓] Sensitive data` `[✓] Hardcoded secrets` `[✓] Debug endpoints` `[✓] Dynamic execution` `[✓] Rate-limit` `[✓] Resource exhaustion` `[✓] Queue/job` `[✓] Webhook` `[✓] CORS` `[✓] Insecure config`

</div>

See `SECURITYSCAN.md:1` for full table (sources → sinks, example `VulnerableController.php:15` `DB::select("...$search")` vs `shell_exec("cat $filename")`).

> **Security boundary `flow.md:818`:** RAT never exploits or runs payloads. It shows `WHERE it started → WHERE it went → WHY → CONFIDENCE → WHAT to review`.

---

## <span style="color:#8b5cf6;">◆</span> Terminal Output — Violet 2026

```text
  Analyzing application behavior...

  <violet>████████████████████░░ 100%</violet>

  Routes ................ 5
  Controllers ........... 3
  Models ................ 1
  Services .............. 2
  Jobs .................. 0

  Findings ──────────────────────────────────────────────
  CRITICAL 2  HIGH 5  MEDIUM 1  LOW 0

  Run:
    rat show RAT-001   — deep dive
    rat flow "GET /vulnerable/sql-injection" --depth=12
```

**Deep dive:**
```bash
php artisan rat:show RAT-001   # or rat show RAT-001
```
```text
🐀 RAT-001  CRITICAL  DB::raw  HIGH
ENTRY POINT  GET /vulnerable/sql-injection
SOURCE  $request->query('q')
FLOW  HTTP Request → Route → VulnerableController → DB::select → Database
WHY  User input reaches DB::raw at app/Http/Controllers/VulnerableController.php:15
CONFIDENCE  ██████████████████░░ HIGH
RECOMMENDATION  Use bindings, validate, prefer builder
LOCATION  app/Http/Controllers/VulnerableController.php:15
  14  $search = $request->query('q');
  ›15 $results = DB::select("SELECT * FROM users WHERE name = '$search'");
```

---

## <span style="color:#8b5cf6;">◆</span> Commands — All Violet

| Command | What |
|---|---|
| `php artisan rat` | Interactive scan — banner first, choice, progress, findings |
| `php artisan rat:scan --deep` | Non-interactive deep scan, persist `storage/rat/last.json` + `.rat.last.json` |
| `php artisan rat:show` | List all — `[All] [Critical] [High] [Medium] [Low]` + search |
| `php artisan rat:show RAT-001` | Full forensic view (above) |
| `php artisan rat:show high --format=json` | Filtered JSON |
| `php artisan rat:why UserController` | `WHO` depends → `WHY` has `Redis` trail |
| `php artisan rat:flow "POST /api/import"` | Visual flow with `├─► Branch` |
| `php artisan rat:impact User.php` | `DIRECT 12, INDIRECT 23, IMPACT HIGH` |
| `php artisan rat:baseline` | Write `.rat.baseline.json` — `--ci` then only fails on **new** |
| `php artisan rat:ui` | Dark 2026 UI `http://127.0.0.1:7331` — same engine |
| `rat` / `php bin/rat` | Standalone mirrors all: `rat --deep`, `rat scan --security`, `rat show`, `rat why`, `rat flow`, `rat impact`, `rat baseline`, `rat ui` |

**Machine-readable:**
```bash
php artisan rat --format=json
php artisan rat --format=ndjson
php artisan rat:scan --deep --format=json
rat why UserController --format=json
rat impact User --format=json
rat flow "GET /vulnerable/sql-injection" --format=json
```

---

## <span style="color:#8b5cf6;">◆</span> CI — 2026

```bash
php artisan rat --ci --fail-on=high          # exit 1 if ≥ high
php artisan rat --deep --ci --fail-on=medium
php artisan rat:baseline --update             # snapshot → --ci only fails on new
```

`config/rat.php:19`:
```php
'fail_on' => 'high', // critical|high|medium|low|info|null
'paths' => ['.'],    // whole codebase — change to ['app','routes'] to limit
'exclude' => ['vendor','storage','bootstrap/cache','node_modules','public','.git'],
'baseline' => base_path('.rat.baseline.json'),
```

---

## <span style="color:#8b5cf6;">◆</span> Architecture Coverage

<div style="border:1px solid #2d1b4e; border-radius:12px; padding:16px; background:#0a0a0f;">

**Monolith** → `app`, `routes`  
**Modular monolith** → `Modules/*/Routes/*.php`, `Domain/*/Routes/*.php`, `src/*/Routes/*.php` (`RouteDiscovery.php:86`) + `FileDiscovery.php:108` suffix/content heuristics for `Controller|Model|Service|Job|Event|Listener|Observer|Middleware` across `Modules/`, `Domain/`, `src/`, `packages/`  
**Microservices** → `services/*/routes/*.php`, `apps/*/routes/*.php`, `microservices/*/routes/*.php` or per-service repo (`'.'` from service root)  
**0 or ALL** → `0 Routes` handled, `Files 27` whole scan capped `80 → dedup → 15` sorted by severity

</div>

Default prompts let you pick architecture; `--all` / `--security` / `--deep` force whole codebase.

---

## <span style="color:#8b5cf6;">◆</span> Engine

```
RAT ENGINE
   │
   ├─ RouteDiscovery (monolith + modular + microservices patterns)
   ├─ FileDiscovery (app/routes/config/database/resources/Modules/Domain/src/packages/services/apps/tests)
   ├─ Graph (ApplicationGraph: Route→Controller→Service→Model→Observer→Job→External, edges CALLS|DISPATCHES|TRIGGERS|WRITES)
   ├─ Detection (Source $request→input/query/file + Sink 85+ Storage::put/DB::raw/shell_exec/Http/eval/unserialize/redirect)
   ├─ Analyzer (auth: authorize/Gate/Policy/can: vs User::update, hidden: Observer→Event→Job)
   └─ Reporters (Table / JSON / NDJSON) + CLI / Web UI (same engine)
```

---

## <span style="color:#8b5cf6;">◆</span> Try Here

```bash
# this package
cd /Applications/XAMPP/xamppfiles/htdocs/package-contribution/rat
php bin/rat --deep --no-image   # violet banner + rat.png

# your vulnerable test app (already has VulnerableController.php:12)
cd /Applications/XAMPP/xamppfiles/htdocs/package-contribution/test-rat/app
php /Applications/XAMPP/xamppfiles/htdocs/package-contribution/rat/bin/rat --deep --no-image
php /Applications/XAMPP/xamppfiles/htdocs/package-contribution/rat/bin/rat show RAT-001 --no-image
```

---

<div align="center" style="margin-top:32px; padding:24px; border:1px solid #2d1b4e; border-radius:16px; background:#0a0a0f;">

<span style="color:#8b5cf6; font-size:20px;">🐀 RAT</span> <span style="color:#a78bfa;">squeak/rat</span> <span style="color:#52525b;">2026</span>

<span style="color:#a1a1aa;">Terminal forensic tool for Laravel</span> • <span style="color:#c4b5fd;">RAT follows the trail.</span>

`composer require squeak/rat --dev` • `php artisan rat --deep` • `rat.png` violet

</div>
