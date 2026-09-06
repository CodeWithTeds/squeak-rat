# 🐀 RAT // SECURITY SCAN
**Vulnerability & Attack-Surface Analysis**
*RAT follows the trail — finds the dangerous path before an attacker does.*

> Run via `php artisan rat` → choose **Security scan** or `php artisan rat --security` / `rat --security`

---

## Scope

RAT's security scan covers the **whole codebase** (all PHP, `vendor/storage/public/.git` excluded, respects `config/rat.php:22` `exclude`) or your chosen lot (`--all` / `--path=`). Use the interactive chooser on TTY:

```
Scan scope? (vendor/storage/public/.git always excluded)
  [0] Whole codebase — All PHP, respects exclude (recommended)
  [1] Laravel lot — Monolith + modular monolith + microservices monorepo
        (app, routes, config, database, resources, Modules, Domain, src, packages, services, apps...)
  [2] Use config/rat.php (.)
  [3] Security scan — Vulnerability & attack-surface analysis
  [4] Deep security scan — Advanced data-flow + behavior analysis
  [5] Custom — you type paths
```

`--security` forces security scan regardless of config. `--deep` adds `depth=12` + full chain.

---

## Checks — 22 Families

RAT is a **defensive developer tool**, not an exploiter. Every finding is `Potential dangerous flow` with `Severity` + `Confidence` + `Why` + `Recommendation`. Never claims vulnerability without proof.

| # | Family | What RAT looks for | Sources → Sinks | Example |
|---|--------|-------------------|-----------------|---------|
| 1 | **Injection risks** | tainted input reaches sensitive operation | `$request` → sink |  |
| 2 | **SQL injection** | raw SQL, `DB::raw`, `whereRaw`, string-interpolated `DB::select("...$var")` | `$request->query()` → `DB::select` | `VulnerableController.php:15` `DB::select("...$search")` |
| 3 | **Command injection** | `exec`, `shell_exec`, `system`, `proc_open`, `Symfony Process` | `$request->input('file')` → `shell_exec("cat $filename")` | `VulnerableController.php:28` |
| 4 | **XSS** | unescaped `{{ $var }}` vs `{!! !!}`, `->input('name')` → `view()` without `e()` | `$request->input('name')` → `view('xss')` |  |
| 5 | **Path traversal** | `Storage::put($path . '/' . $file)`, `file_get_contents`, `include $var` | `$request->input('path')` → `Storage::put`, `fopen` | `ImportController.php:15` |
| 6 | **SSRF** | `Http::get($url)`, `file_get_contents("http://$url")`, Guzzle with user URL | `$request->input('url')` → `Http::` |  |
| 7 | **Unsafe deserialization** | `unserialize($input)`, `eval`, `call_user_func($var)` | `$request` → `unserialize` |  |
| 8 | **File upload risks** | `$request->file()`, `->getClientOriginalName()`, `Storage::putFile` without mime/size/extension checks | `$request->file('document')` → `Storage::put` |  |
| 9 | **Authentication weaknesses** | missing `auth` middleware, `Hash::make` without validation, debug endpoints exposing users | `Route::post('/admin')` without `auth` |  |
| 10 | **Authorization / IDOR** | `User::update($request->all())` without `authorize()`, `Gate::`, `Policy`, `can:` | `POST /admin/users/{user}` → `Model::update` | `UserController.php:9` |
| 11 | **Mass assignment** | `Model::create($request->all())`, `$fillable`/`$guarded` weak | `$request->all()` → `::create` |  |
| 12 | **Open redirects** | `redirect($request->input('next'))`, `Redirect::to($var)` | `$request->input('next')` → `redirect` |  |
| 13 | **Sensitive data exposure** | `APP_DEBUG=true` in `.env`, `dd()`, `dump()`, returning `User::all()` with hidden fields | `config/app.php` `debug` true |  |
| 14 | **Hardcoded secrets** | `aws_access_key`, `sk_live_`, `password = "`, `.env` checked in, `config/services.php` hardcode | regex `/sk_live_[0-9a-z]+/`, `/AKIA[0-9A-Z]{16}/` |  |
| 15 | **Debug mode / debug endpoints** | `APP_DEBUG=true`, `/telescope`, `/horizon`, `Route::get('/debug')` | `config/app.php`, `routes/web.php` |  |
| 16 | **Unsafe dynamic execution** | `new $class()`, `$func()`, `eval`, `call_user_func_array($input)` | `$request->input('class')` → `new $var` |  |
| 17 | **Rate-limit coverage** | `throttle` middleware missing on `POST /login`, `Route::post` without `throttle` | `routes/api.php` without `throttle:api` |  |
| 18 | **Resource exhaustion** | unbounded `->get()`, `file_get_contents($large)`, queues without `ShouldQueue` limits | `User::all()` without pagination |  |
| 19 | **Dangerous queue/job behavior** | `dispatch(new Job($userInput))` without validation, `SyncUserJob` → `Http::post` external | `UserObserver → Job → Http` |  |
| 20 | **Webhook security** | `Route::post('/webhook')` without signature verification, `Http::post` external without timeouts | `Http::post('https://external')` |  |
| 21 | **CORS / security configuration** | `cors.php` `allowed_origins => ['*']`, `config/cors.php`, missing `VerifyCsrfToken` | `config/cors.php` |  |
| 22 | **Insecure Laravel configuration** | `APP_ENV=production` with `debug true`, `session secure false`, `APP_KEY` weak | `config/app.php`, `.env` |  |

---

## Output

### Terminal (default) — Violet 2026
```text
🐀 RAT // SECURITY SCAN / DEEP SECURITY SCAN

  [✓] Injection risks
  [✓] SQL injection patterns
  [✓] Command injection
  ...

  CRITICAL 2 HIGH 5 MEDIUM 1
  POST /vulnerable/sql-injection → VulnerableController → DB::raw (HIGH conf)
  Run: rat show RAT-001
```

### Machine-readable
```bash
php artisan rat --security --format=json
php artisan rat --deep --format=json
rat --security --format=ndjson
php artisan rat:scan --security --format=json
```

### CI
```bash
php artisan rat --security --ci --fail-on=high
# exit 1 if new findings ≥ high (baseline-aware via .rat.baseline.json)
```

---

## How it works

1. **Banner first** `src/Support/RatBanner.php:32` — `rat.png` rendered via `TerminalImage.php:26` (iTerm2 inline + GD half-block true-color `#8b5cf6` violet) before scanning.
2. **Scope** `src/Engine/Analyzer.php:40` + `FileDiscovery.php:25` + `RouteDiscovery.php:86` — covers monolith, modular monolith (`Modules/`, `Domain/`), microservices monorepo (`services/*/`, `apps/*/`) — whole codebase `'.'` respects `exclude`.
3. **Graph** `ApplicationGraph.php:1` — `Route → Controller → Service → Model → Observer → Job → External`.
4. **Taint** `SourceDetector.php:1` (`$request->input/query/file`, `$_GET`, route params) → `SinkDetector.php:1` (85+ sinks) → confidence by variable sharing & validation presence.
5. **Auth/Hidden** `AuthorizationAnalyzer.php:1`, `HiddenBehaviorAnalyzer.php:1` + `SecurityScanAnalyzer` for secrets/debug/CORS/rate-limit.

---

## Compatibility

* PHP `^8.1|^8.2|^8.3|^8.4`, Laravel `^9|^10|^11|^12` (`composer.json:14`), Symfony `^6|^7|^8`, `nikic/php-parser` `^4|^5`
* OS `darwin|linux|windows` (`posix_isatty` guard), terminals any (GD fallback to block letters if `ext-gd` missing)
* Architectures: `0` findings (empty) and `all` (many) both handled — capped 15 displayed, sorted by severity.

---

## Run

```bash
php artisan rat                    # choose: Whole codebase / Laravel lot / Security scan / Deep / Custom
php artisan rat --security --no-image
php artisan rat --deep --no-image  # advanced data-flow + behavior
php artisan rat --all              # whole
php artisan rat --path=Modules/Billing --format=json
rat --security  # standalone bin/rat:1
rat show RAT-001
rat flow "GET /vulnerable/sql-injection" --depth=12
```

*RAT follows the trail.* 🐀
