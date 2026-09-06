<div align="center">

<table>
<tr>
<td width="340" align="center" valign="middle">
  <img src="rat.png" alt="RAT — squeak/rat" width="320" style="border-radius:20px; box-shadow: 0 20px 60px rgba(124,58,237,0.35);">
</td>
<td align="left" valign="middle">

# 🐀 RAT

### Terminal-first Laravel *Security* & *Behavior* Analyzer

**Forensic · Taint Analysis · Attack-Surface — from a single request**

> 🐀 **Your request is already there. Why audit manually when the path it will take through your application can be traced automatically?**

</td>
</tr>
</table>

[![PHP ^8.1|^8.2|^8.3|^8.4](https://img.shields.io/badge/PHP-^8.1%7C8.2%7C8.3%7C8.4-7c3aed?style=for-the-badge&logo=php&logoColor=white)](https://php.net)
[![Laravel 9|10|11|12](https://img.shields.io/badge/Laravel-9%20%7C%2010%20%7C%2011%20%7C%2012-8b5cf6?style=for-the-badge&logo=laravel&logoColor=white)](https://laravel.com)
[![squeak/rat v1.0.0](https://img.shields.io/badge/squeak%2Frat-v1.0.0-7c3aed?style=for-the-badge)](https://github.com/squeak/rat)
[![Tests](https://img.shields.io/badge/tests-passing-22c55e?style=for-the-badge)](tests)
[![License MIT](https://img.shields.io/badge/license-MIT-a78bfa?style=for-the-badge)](LICENSE)
[![Violet 2026](https://img.shields.io/badge/Terminal-Violet_2026-7c3aed?style=for-the-badge)](#)
[![Owner Prof Alex / TE-AD](https://img.shields.io/badge/owner-Prof%20Alex%20%2F%20TE--AD-8b5cf6?style=for-the-badge)](https://github.com/squeak/rat)

```bash
composer require squeak/rat --dev
php artisan rat --deep
```

</div>

---

### Why RAT?

> You trace a route. RAT shows the whole trail — not just the controller.

<table>
<tr>
<td>

**You give**
```php
POST /api/import
  → ImportController::import()
    → $request->file('document')
      → Storage::put()
```
*or* any Laravel app:
```
app/Http/Controllers
app/Services
app/Models (Observers)
routes/api.php
Modules/Billing/...
Domain/*/...
services/auth-service/...
```

</td>
<td>

**You get — forensic, not noisy**
```
🐀 RAT-001  CRITICAL  Storage::put  HIGH
ENTRY  POST /api/import
SOURCE $request->file('document')
FLOW   HTTP Request
         ↓ ImportController
         ↓ ImportService
         ↓ Storage::put() → Filesystem
WHY    User input reaches filesystem
       without clear validation/boundary
CONFIDENCE ██████████████████░░ HIGH
FIX    auth, filename, path, mime
```
`3 important findings > 300 noise` — vendor excluded, `Potential dangerous flow` only.

</td>
</tr>
</table>

**No dashboard. No SaaS. No AI.** Pure PHP — runs 100% locally, `rat.png` violet before scanning (`src/Support/RatBanner.php:32`).

---

### ✨ Analyzer, not just scanner

| Generic scanner | **RAT — Forensic / Taint / Behavior** |
|---|---|
| Regex only | **+ Graph** `Route→Controller→Service→Model→Observer→Job→External` (`ApplicationGraph.php:1`) |
| Lists files | **+ Traces** `SOURCE $request→input/query/file/$_GET` → `SINK 85+ Storage::put/DB::raw/shell_exec/Http/eval/redirect` |
| No auth check | **+ Authz** `authorize()/Gate/Policy/can:` vs `User::update($request->all())` (`AuthorizationAnalyzer.php:1`) |
| No hidden behavior | **+ Hidden** `Observer → Event → Listener → Job → Notification` (`HiddenBehaviorAnalyzer.php:1`) |
| One project shape | **Monolith + Modular monolith + Microservices monorepo** (`RouteDiscovery.php:86`, `FileDiscovery.php:108`) |
| No impact | **+ `rat:impact User.php` → DIRECT 12, INDIRECT 23, IMPACT HIGH** |
| No flow viz | **+ `rat:flow "POST /api/import"` → branch `├─►`** |
| Fixed paths | **All paths configurable — `config/rat.php:19` or `--path=`** |

Use it as:
- **Security review** before deploy (`--security`, `--deep` → `SECURITYSCAN.md:17` 22 families)
- **Behavior map** for new devs (`rat:why UserService` → why has Redis?)
- **Blast radius** for refactors (`rat:impact Order.php`)
- **CI gate** (`rat --ci --fail-on=high`, `rat:baseline`)

---

### ⚡ 10 seconds to first findings

```bash
composer require squeak/rat --dev
php artisan rat --deep
```

```
🐀 RAT — squeak/rat 2026 VIOLET • #8b5cf6
  🐀 RAT // DEEP SECURITY SCAN  Advanced data-flow + behavior analysis

  Analyzing application behavior...
  ████████████████████░░ 100%

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

<details>
<summary>Chooser + CI / non-interactive</summary>

```bash
php artisan rat
# ? What should RAT scan? (vendor/storage/public/.git always excluded)
#   [0] Whole codebase (all PHP — recommended)      ← '.'
#   [1] Laravel lot (monolith + modular + microservices)
#   [2] Security scan (22 families → SECURITYSCAN.md)
#   [3] Deep security scan — Advanced data-flow + behavior
#   [4] Use config/rat.php
#   [5] Custom — you type paths

# flags — no prompt, CI friendly
php artisan rat --all --no-image                 # whole
php artisan rat --path=app,routes                # limited
php artisan rat --security --no-image            # security
php artisan rat --deep --no-image                # deep
php artisan rat --deep --format=json > report.json
php artisan rat --deep --ci --fail-on=high      # exit 1 if ≥ high
php artisan rat:baseline --update               # snapshot → --ci only fails on new
# standalone
php bin/rat --deep
rat --security --format=ndjson
```
</details>

### 📁 Scan scope — you choose where RAT looks

Whole codebase by default (`paths: ['.']` in `config/rat.php:19` — all PHP except `exclude: vendor/storage/bootstrap/cache/node_modules/public/.git`). Limit per run, no config edit:

```bash
php artisan rat --path=Modules/Billing --no-image
# → only Modules/Billing + its Routes

php artisan rat --path=services/payment-service,services/user-service
# → microservices monorepo — two services only

php artisan rat --path=app,Domain --format=json
# → monolith + DDD

# permanent: config/rat.php
'paths' => ['app','Modules','Domain','services'],
'exclude' => ['vendor','storage'],
```

`RouteDiscovery.php:86` covers `routes/*.php` + `Modules/*/Routes/*.php` + `Domain/*/Routes/*.php` + `services/*/routes/*.php` + `apps/*/routes/*.php`.

---

### 🧬 Inputs — Any architecture → one graph

**Monolith** `app/Http/Controllers`, `routes/api.php`  
**Modular monolith** `Modules/Billing/Http/Controllers/InvoiceController.php`, `Domain/Entity/Aggregate`  
**Microservices** `services/auth-service/app/Http/Controllers`, `apps/admin/routes/api.php`  
**DDD** `Domain/Billing/Entity/Invoice.php`, `Application/Service/InvoiceService.php`

`FileDiscovery.php:108` suffix/content heuristics (`*Controller`, `*Service`, `*Repository`, `*Job`, `extends Model`, `ShouldQueue`, `*Action/*Handler`) work across all.

---

### 🧩 What gets flagged — Vulnerability families (defensive only)

<div style="background: linear-gradient(135deg, #1e0a3a 0%, #2d1b4e 50%, #1e0a3a 100%); border: 2px solid #8b5cf6; border-radius:16px; padding:20px; box-shadow: 0 12px 40px rgba(139,92,246,0.25);">

<div style="display:grid; grid-template-columns: 1fr 1fr; gap:8px; font-size:13px; color:#e9d5ff; font-weight:600; line-height:1.6;">

`[✓] Injection` `[✓] SQL injection` `[✓] Command injection` `[✓] XSS` `[✓] Path traversal` `[✓] SSRF` `[✓] Deserialization` `[✓] File upload` `[✓] Auth weak` `[✓] IDOR / Authz` `[✓] Mass assignment`

`[✓] Open redirect` `[✓] Sensitive data` `[✓] Hardcoded secrets` `[✓] Debug endpoints` `[✓] Dynamic execution` `[✓] Rate-limit` `[✓] Resource exhaustion` `[✓] Queue/job` `[✓] Webhook` `[✓] CORS` `[✓] Insecure config`

</div>

</div>

Each: `Potential dangerous flow` + `Severity CRITICAL/HIGH/MEDIUM/LOW` + `Confidence HIGH/MEDIUM/LOW` + `ENTRY → SOURCE → SINK → FLOW` + `FILE:LINE` + code snippet + `WHY` + `RECOMMENDATION`. See `SECURITYSCAN.md:1` for full table ( `VulnerableController.php:15` `DB::select("...$search")` vs `shell_exec("cat $filename")` ).

> **Security boundary `flow.md:818`:** RAT never exploits or runs payloads. It shows `WHERE it started → WHERE it went → WHY → CONFIDENCE → WHAT to review`.

---

### 🎨 Customize Everything — Violet 2026

```php
// config/rat.php
return [
  'fail_on' => 'high', // critical|high|medium|low
  'paths' => ['.'],    // whole codebase — or ['app','Modules']
  'exclude' => ['vendor','storage','bootstrap/cache','node_modules','public','.git'],
  'analysis' => ['routes'=>true,'authorization'=>true,'data_flow'=>true,'hidden_behavior'=>true,'impact'=>true],
  'baseline' => base_path('.rat.baseline.json'),
  'ui' => ['host'=>'127.0.0.1','port'=>7331],
];
```

Banner — violet `#8b5cf6/#7c3aed/#a78bfa` (`RatBanner.php:32`), `rat.png` inline OSC1337 where supported + GD half-block `▀` fallback (`TerminalImage.php:26`), `--no-image` disables, `--compact` single line.

Progress — violet `████████████████████░░` (`RatCommand.php:118`).

---

### 🛡️ Safety & DX — Violet

- **Never overwrites** findings without `rat:baseline --update`
- **`--deep`** depth 12, lower cap, full chain — `0` or `ALL` handled, capped `80 → dedup → 15` sorted by severity
- **Terminal-first** — `rat`/`bin/rat` standalone without Laravel, `php artisan rat` when installed
- **Machine-readable** `rat --format=json|ndjson` + `rat:why`/`rat:flow`/`rat:impact` also `--format=json`
- **CI** `rat --ci --fail-on=high` (baseline-aware), `rat:baseline`
- **UI** `rat:ui` → `http://127.0.0.1:7331` dark violet, same engine

---

### 🏗️ Architecture — 2026

```
src/
├── Support/RatBanner.php + TerminalImage.php   # violet banner + rat.png
├── Engine/Analyzer.php                         # 5 phases: routes → files → graph → taint → auth/hidden
│   ├── Discovery/RouteDiscovery.php            # monolith + modular + microservices patterns
│   │            FileDiscovery.php              # suffix/content across Modules/Domain/src/packages/services
│   ├── Graph/ApplicationGraph.php              # Route→Controller→Service→Model→Observer→Job→External
│   ├── Detection/SourceDetector.php → SinkDetector.php (85+ sinks)
│   │           AuthorizationAnalyzer.php, HiddenBehaviorAnalyzer.php
│   └── Reporters/JsonReporter.php
├── Console/Commands/ rat, rat:scan --deep, rat:show, rat:why, rat:flow, rat:impact, rat:baseline, rat:ui
└── RatServiceProvider.php                      # config publish
```

No giant scanner. Each detector isolated, testable, violet.

---

### 🧪 Tests

```bash
composer install
composer test # vendor/bin/phpunit
php bin/rat --deep --no-image   # self-scan → violet
```

---

### 📦 Install (GitHub) — Prof Alex / TE-AD

```bash
composer config repositories.squeak-rat vcs https://github.com/squeak/rat.git
composer require squeak/rat:@dev --dev
# once on Packagist:
composer require squeak/rat --dev
```
Once published: `squeak/rat` (`composer.json:2` `name: squeak/rat`) — MIT, owner **Prof Alex / TE-AD**.

Requires `PHP ^8.1|^8.2|^8.3|^8.4` · `Laravel 9|10|11|12|13`

---

### 🔄 Update RAT

```bash
composer update squeak/rat --with-all-dependencies
# clear old scan cache & rescan
rm -f .rat.last.json storage/rat/last.json .rat/last.json
php artisan rat --deep --no-image
```

If you installed via VCS (`repositories.squeak-rat vcs https://github.com/squeak/rat.git`):
```bash
composer clear-cache
composer update squeak/rat --with-all-dependencies
composer show squeak/rat | grep version
```

Standalone: `rm -rf vendor/squeak/rat && composer update` or pull the `rat/` folder directly.

---

### 🗺️ Roadmap — Violet 2026

- `--api` / `--web` presets, enum casts, factories, `--all` for multi-table ERD, `rat:why --depth=20`

PRs welcome. Build your next audit with `php artisan rat --deep`.

---

<div align="center">

**Built for builders who ship features, not vulnerabilities.**

<span style="color:#8b5cf6;">MIT</span> · Owned by **Prof Alex / TE-AD** · [github.com/squeak/rat](https://github.com/squeak/rat) · [Report issue](https://github.com/squeak/rat/issues) · `php artisan rat --deep` · <span style="color:#7c3aed;">🐀 RAT follows the trail. 2026 VIOLET</span>

</div>
