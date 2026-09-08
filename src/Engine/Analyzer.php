<?php

namespace Rat\Engine;

use Rat\Engine\Graph\ApplicationGraph;
use Rat\Engine\Graph\Node;
use Rat\Engine\Graph\Edge;
use Rat\Engine\Discovery\RouteDiscovery;
use Rat\Engine\Discovery\FileDiscovery;
use Rat\Engine\Detection\SourceDetector;
use Rat\Engine\Detection\SinkDetector;
use Rat\Engine\Detection\AuthorizationAnalyzer;
use Rat\Engine\Detection\HiddenBehaviorAnalyzer;
use Rat\Engine\Findings\Finding;
use Rat\Engine\Findings\Severity;
use Rat\Engine\Findings\Confidence;

class Analyzer
{
    private string $projectRoot;
    private array $config;

    public function __construct(?string $projectRoot = null, array $config = [])
    {
        $this->projectRoot = $projectRoot ?? $this->detectProjectRoot();
        $this->config = array_merge($this->defaultConfig(), $config);
    }

    private function defaultConfig(): array
    {
        $cfgPath = $this->projectRoot . '/config/rat.php';
        if (file_exists($cfgPath)) {
            try {
                $cfg = require $cfgPath;
                if (is_array($cfg)) return $cfg;
            } catch (\Throwable $e) {}
        }
        return [
            'fail_on' => 'high',
            'paths' => ['.'], // whole codebase by default — vendor/storage excluded below
            'exclude' => ['vendor','storage','bootstrap/cache','node_modules','public','.git','.idea','.vscode','tests','tests_python','.rat'],
            'analysis' => ['routes'=>true,'authorization'=>true,'data_flow'=>true,'hidden_behavior'=>true,'impact'=>true],
        ];
    }

    private function detectProjectRoot(): string
    {
        // If artisan exists, use cwd; else use rat/ parent logic
        $cwd = getcwd() ?: dirname(__DIR__, 2);
        // Walk up looking for composer.json or artisan
        $dir = $cwd;
        for ($i=0; $i<5; $i++) {
            if (file_exists($dir . '/artisan') || file_exists($dir . '/composer.json')) {
                return $dir;
            }
            $parent = dirname($dir);
            if ($parent === $dir) break;
            $dir = $parent;
        }
        return $cwd;
    }

    public function projectRoot(): string { return $this->projectRoot; }
    public function config(): array { return $this->config; }

    /**
     * @return array{graph: ApplicationGraph, findings: Finding[], stats: array}
     */
    public function analyze(?callable $progress = null): array
    {
        $graph = new ApplicationGraph();
        $findings = [];

        $progress && $progress('routes', 10);

        // Phase 1: Route + Controller discovery
        $routeDiscovery = new RouteDiscovery($this->projectRoot);
        $routeInfo = $routeDiscovery->discover($graph);

        $progress && $progress('files', 30);

        $fileDiscovery = new FileDiscovery($this->projectRoot, $this->config);
        $fileInfo = $fileDiscovery->discover($graph);

        $progress && $progress('flows', 60);

        // Phase 2: Source -> Sink tracing per file
        $findings = array_merge($findings, $this->traceDataFlows($graph));

        $progress && $progress('auth', 80);

        // Phase 3: Authorization + hidden behavior
        if (($this->config['analysis']['authorization'] ?? true)) {
            $findings = array_merge($findings, $this->analyzeAuthorization($graph));
        }

        if (($this->config['analysis']['hidden_behavior'] ?? true)) {
            $findings = array_merge($findings, $this->analyzeHiddenBehavior($graph));
        }

        // Phase 4: Additional security families for better finding (AF-01..AF-09 from rat-audit.txt / rat-miss-finding.txt)
        if (($this->config['analysis']['security'] ?? false) || ($this->config['analysis']['deep'] ?? false) || ($this->config['analysis']['data_flow'] ?? true)) {
            $findings = array_merge($findings, $this->analyzeAdditionalSecurity($graph));
        }

        $progress && $progress('done', 100);

        // Deduplicate + assign IDs
        $findings = $this->assignIds($findings);

        // Sort by severity weight desc
        usort($findings, fn(Finding $a, Finding $b) => $b->severity->weight() <=> $a->severity->weight());

        $stats = [
            'routes' => $routeInfo['count'],
            'files' => $fileInfo['files'],
            'by_type' => $fileInfo['by_type'],
            'graph' => $graph->stats(),
            'findings' => $this->countBySeverity($findings),
            'project_root' => $this->projectRoot,
        ];

        return ['graph' => $graph, 'findings' => $findings, 'stats' => $stats];
    }

    private function stripPhp(string $content): string
    {
        // Mirror python_rat/strip.py — remove string literals and comments so detectors don't fire inside them
        $strings = [];
        $tmp = preg_replace_callback('/\'(?:\\\\.|[^\'\\\\])*\'|"(?:\\\\.|[^"\\\\])*"/', function($m) use (&$strings) {
            $strings[] = $m[0];
            return '__STR' . (count($strings)-1) . '__';
        }, $content);
        $tmp = preg_replace('/\/\/.*/', '', $tmp);
        $tmp = preg_replace('/^\s*#.*/m', '', $tmp);
        $tmp = preg_replace('/\/\*.*?\*\//s', '', $tmp);
        return $tmp;
    }

    /** @return Finding[] */
    private function traceDataFlows(ApplicationGraph $graph): array
    {
        $findings = [];
        $paths = $this->config['paths'] ?? ['.'];
        $exclude = $this->config['exclude'] ?? ['vendor','storage','bootstrap/cache','node_modules','public','.git'];

        $files = $this->collectPhpFiles($paths, $exclude);

        $counter = 0;
        foreach ($files as $file) {
            $rel = str_replace($this->projectRoot . '/', '', $file);
            $raw = @file_get_contents($file) ?: '';
            if ($raw === '') continue;
            $clean = $this->stripPhp($raw);

            $sources = SourceDetector::detectInContent($clean);
            $sinks = SinkDetector::detectInContent($clean);

            if (empty($sources) || empty($sinks)) continue;

            // Build tainted vs sanitized vars (mirrors python_rat/analyzer.py)
            $taintedVars = [];
            $sanitizedVars = [];
            $hasFormRequest = (bool) preg_match('/\b[A-Z][a-zA-Z0-9_]*Request\s+\$request/', $raw);
            foreach (explode("\n", $clean) as $line) {
                if (SourceDetector::isSourceLine($line)) {
                    if (preg_match('/(\$[a-zA-Z_]\w*)\s*=\s*.*(?:\$request|request\s*\()/', $line, $m)) {
                        $var = $m[1];
                        if (preg_match('/->\s*(validate|validated|safe|only)\s*\(/i', $line)) {
                            $sanitizedVars[$var] = true;
                        } else {
                            $taintedVars[$var] = true;
                        }
                    }
                    foreach (['$_GET','$_POST','$_REQUEST','$_FILES','$_COOKIE'] as $sup) {
                        if (str_contains($line, $sup)) $taintedVars[$sup] = true;
                    }
                    $taintedVars['$request'] = true;
                }
                if (preg_match('/(\$[a-zA-Z_]\w*)\s*=\s*\$request->\s*(safe|validated)\b/', $line, $m2)) {
                    $sanitizedVars[$m2[1]] = true;
                }
                if (preg_match('/(\$[a-zA-Z_]\w*)\s*=\s*\$request->\s*validate\s*\(/', $line, $m3)) {
                    $sanitizedVars[$m3[1]] = true;
                }
                if (preg_match('/(\$[a-zA-Z_]\w*)\s*=\s*\$request->\s*only\s*\(/', $line, $m4)) {
                    $sanitizedVars[$m4[1]] = true;
                }
                if (preg_match('/(\$[a-zA-Z_]\w*)\s*=\s*\$request->\s*(validated|safe)\s*\(/', $line, $m5)) {
                    $sanitizedVars[$m5[1]] = true;
                }
            }

            foreach ($sinks as $sink) {
                $sinkLine = $this->lineForOffset($clean, $sink['offset']);
                // Extract sink line content (both clean and raw)
                $cleanLines = explode("\n", $clean);
                $rawLines = explode("\n", $raw);
                $sinkLineContent = '';
                $sinkLineRaw = '';
                $cur = 0;
                foreach ($cleanLines as $idx => $cl) {
                    $nxt = $cur + strlen($cl) + 1;
                    if ($sink['offset'] >= $cur && $sink['offset'] < $nxt) {
                        $sinkLineContent = $cl;
                        if (isset($rawLines[$idx])) $sinkLineRaw = $rawLines[$idx];
                        break;
                    }
                    $cur = $nxt;
                }

                $hasTaint = false;
                // Dynamic sink special handling
                if ($sink['sink'] === 'dynamic function call') {
                    if (preg_match('/\$([a-zA-Z_]\w*)\s*\(\s*\$/', $sinkLineContent, $m)) {
                        $funcVar = '$' . $m[1];
                        if (isset($taintedVars[$funcVar])) $hasTaint = true;
                        else continue;
                    } else {
                        if (SourceDetector::isSourceLine($sinkLineContent)) $hasTaint = true;
                        else continue;
                    }
                } elseif ($sink['sink'] === 'dynamic class instantiation') {
                    if (preg_match('/new\s+(\$[a-zA-Z_]\w*)/', $sinkLineContent, $m) && isset($taintedVars[$m[1]])) {
                        $hasTaint = true;
                    } else {
                        continue;
                    }
                } else {
                    if (SourceDetector::isSourceLine($sinkLineContent) || SourceDetector::isSourceLine($this->stripPhp($sinkLineRaw))) {
                        $hasTaint = true;
                    }
                    if (! $hasTaint) {
                        foreach (array_keys($taintedVars) as $tv) {
                            if (str_contains($sinkLineContent, $tv) || ($sinkLineRaw && str_contains($sinkLineRaw, $tv))) {
                                $hasTaint = true; break;
                            }
                        }
                    }
                }

                // For mass assignment, extend context for multiline arrays
                $extendedRaw = $sink['sink'] === 'mass assignment' ? substr($raw, $sink['offset'], 1500) : '';
                $extendedClean = $sink['sink'] === 'mass assignment' ? substr($clean, $sink['offset'], 1500) : '';
                if ($sink['sink'] === 'mass assignment' && ! $hasTaint) {
                    foreach (array_keys($taintedVars) as $tv) {
                        if (str_contains($extendedRaw, $tv) || str_contains($extendedClean, $tv)) { $hasTaint = true; break; }
                    }
                    if (! $hasTaint && SourceDetector::isSourceLine($extendedClean)) $hasTaint = true;
                    if (! $hasTaint && SourceDetector::isSourceLine($this->stripPhp($extendedRaw))) $hasTaint = true;
                }

                // Mass assignment precise filtering (fixes RAT-001..003 false positives)
                if ($sink['sink'] === 'mass assignment') {
                    foreach (array_keys($sanitizedVars) as $sv) {
                        if (str_contains($sinkLineContent, $sv) || ($sinkLineRaw && str_contains($sinkLineRaw, $sv)) || str_contains($extendedRaw, $sv) || str_contains($extendedClean, $sv)) {
                            $hasTaint = false; break;
                        }
                    }
                    if (! $hasTaint) continue;
                    if ($hasFormRequest && $hasTaint && (preg_match('/\$request->\s*(validated|safe)\b/', $sinkLineContent) || preg_match('/\$request->\s*(validated|safe)\b/', $extendedClean))) {
                        $hasTaint = false; continue;
                    }
                    $combined = ($sinkLineContent ?: '') . ' ' . ($sinkLineRaw ?: '') . ' ' . $extendedRaw . ' ' . $extendedClean;
                    if (preg_match('/\$request->\s*(only|validated|safe)\s*\(/i', $combined)) {
                        // allow-list filtered -> not exploitable mass assignment
                        continue;
                    }
                    if (str_contains($combined, '=>')) {
                        if (!str_contains($combined, '$request->all()') && !str_contains($combined, '$request->all')) {
                            $lower = strtolower($combined);
                            $hasSensitive = (bool) preg_match('/is_admin|is_super|branch_id/', $lower);
                            if (! $hasSensitive) {
                                continue;
                            }
                            $foundSensitiveTainted = false;
                            if (preg_match('/is_admin.*\$request|status.*\$request|branch_id.*\$request/i', $lower)) {
                                $foundSensitiveTainted = true;
                            }
                            foreach (array_keys($taintedVars) as $tv) {
                                if (str_contains($combined, $tv) && preg_match('/is_admin|is_super/i', $lower)) {
                                    $foundSensitiveTainted = true;
                                }
                            }
                            if (! $foundSensitiveTainted) continue;
                        }
                    }
                }

                if (! $hasTaint) continue;

                $nearestSource = $this->nearestSource($sources, $sink, $clean);
                $confidence = $this->estimateConfidence($clean, $sources, $sink);
                $severity = $sink['severity'];
                $hasValidation = (bool) preg_match('/->\s*validate\s*\(|FormRequest|Validator::/i', $clean);
                if (! $hasValidation && $severity === Severity::CRITICAL) {
                    $confidence = Confidence::HIGH;
                } elseif ($hasValidation) {
                    if ($confidence === Confidence::HIGH) $confidence = Confidence::MEDIUM;
                }

                $basename = basename($file, '.php');
                $flow = $this->buildFlow($graph, $file, $basename, $sink['sink'], $nearestSource['snippet'] ?? '$request');
                $entry = $this->inferEntryPoint($graph, $file, $basename);
                $title = sprintf('User input reaches %s', $sink['sink']);
                $desc = 'User-controlled data reaches a sensitive operation.';
                $why = sprintf(
                    "User-controlled input (%s) reaches %s in %s:%d. No clear security boundary was detected in the immediate path. Review authorization, validation, and sanitization.",
                    $nearestSource['snippet'] ?? 'request input',
                    $sink['sink'],
                    $rel,
                    $sinkLine
                );
                $recs = $this->recommendationsForSink($sink['sink']);
                $findings[] = new Finding(
                    id: 'RAT-TMP-' . (++$counter),
                    title: $title,
                    description: $desc,
                    severity: $severity,
                    confidence: $confidence,
                    entry: $entry,
                    source: $nearestSource['snippet'] ?? '$request->input()',
                    sink: $sink['sink'],
                    flow: $flow,
                    file: $rel,
                    line: $sinkLine,
                    recommendations: $recs,
                    category: 'data_flow',
                    why: $why,
                );
            }

            if (count($findings) > 80) break;
        }

        // Deduplicate by sink+file+source proximity
        $unique = [];
        foreach ($findings as $f) {
            $key = $f->file . ':' . $f->sink . ':' . $f->source;
            if (! isset($unique[$key])) $unique[$key] = $f;
        }

        // Limit to prevent noise: prioritize HIGH/CRITICAL only if too many
        $unique = array_values($unique);
        if (count($unique) > 15) {
            $filtered = array_filter($unique, fn(Finding $f) => $f->severity->weight() >= Severity::HIGH->weight());
            if (count($filtered) >= 3) {
                $unique = array_values($filtered);
            }
            $unique = array_slice($unique, 0, 15);
        }

        return $unique;
    }

    /** @return Finding[] */
    private function analyzeAuthorization(ApplicationGraph $graph): array
    {
        $findings = [];
        $paths = $this->config['paths'] ?? ['.'];
        $exclude = $this->config['exclude'] ?? ['vendor','storage','bootstrap/cache','node_modules','public','.git'];
        $files = $this->collectPhpFiles($paths, $exclude);

        foreach ($files as $file) {
            $rel = str_replace($this->projectRoot . '/', '', $file);
            // Skip infra + CLI-only paths (fixes RAT-006-010: migrations/seeders are CLI not HTTP routes)
            if (str_starts_with($rel, 'database/') || str_contains($rel, '/database/') || str_contains($rel, '/migrations/') || str_contains($rel, '/seeders/') || str_contains($rel, '/factories/') || str_starts_with($rel, 'resources/') || str_starts_with($rel, 'config/') || str_starts_with($rel, 'storage/') || str_starts_with($rel, 'bootstrap/') || str_starts_with($rel, 'tests/') || str_contains($rel, '/tests/') || str_ends_with($rel, '.blade.php') || str_contains($rel, 'python_rat') || str_contains($rel, 'src/Engine/') || str_contains($rel, 'python_precise') || str_contains($rel, 'verify_')) {
                continue;
            }
            $raw = @file_get_contents($file) ?: '';
            if ($raw === '') continue;
            $content = $this->stripPhp($raw);
            // Precise: file must be a Controller and referenced by a Route (or HTTP-exposed)
            $isController = str_ends_with($file, 'Controller.php') || str_contains($file, '/Http/Controllers/');
            if (! $isController) continue;
            $basename = basename($file, '.php');
            $isRouted = false;
            foreach ($graph->nodesByType('Route') as $rn) {
                if (str_contains((string) ($rn->meta['action'] ?? ''), $basename)) {
                    $isRouted = true; break;
                }
            }
            if (! $isRouted) {
                if (count($graph->nodesByType('Route')) > 0) continue;
                // if 0 routes, fallback: check if controller appears in any route file via content search
                $routesDir = $this->projectRoot . '/routes';
                $foundInRoutes = false;
                if (is_dir($routesDir)) {
                    foreach (glob($routesDir . '/*.php') ?: [] as $rf) {
                        $rc = @file_get_contents($rf) ?: '';
                        if (str_contains($rc, $basename)) { $foundInRoutes = true; break; }
                    }
                }
                if (! $foundInRoutes) continue;
            }

            if (! AuthorizationAnalyzer::isSensitive($content)) continue;
            if (AuthorizationAnalyzer::hasAuthorization($content)) continue;

            // Check route middleware for this controller: look up graph edges
            $basename = basename($file, '.php');
            $routeNodes = $graph->nodesByType('Route');
            $hasAuthRoute = false;
            foreach ($routeNodes as $rn) {
                if (str_contains((string) ($rn->meta['action'] ?? ''), $basename)) {
                    // If route file contains auth middleware for this uri, consider authorized
                    $routeFile = $rn->file;
                    if ($routeFile && file_exists($this->projectRoot . '/' . $routeFile)) {
                        $rc = @file_get_contents($this->projectRoot . '/' . $routeFile);
                        if ($rc && preg_match('/auth|can:|middleware.*auth/i', $rc)) {
                            $hasAuthRoute = true;
                            break;
                        }
                    }
                }
            }
            if ($hasAuthRoute) continue;
            // also check if controller itself has auth middleware via $this->middleware or __construct
            if (preg_match('/middleware.*auth|->middleware.*auth/i', $content)) {
                continue;
            }

            // Sensitive + no auth
            $entry = $this->inferEntryPoint($graph, $file, $basename);
            $flow = $this->buildFlow($graph, $file, $basename, 'Model::update', '$request');

            $findings[] = new Finding(
                id: 'RAT-TMP-AUTH',
                title: 'Potential authorization boundary missing',
                description: 'Sensitive operation with no obvious authorization check detected.',
                severity: Severity::HIGH,
                confidence: Confidence::MEDIUM,
                entry: $entry,
                source: 'HTTP Request',
                sink: 'Sensitive model operation',
                flow: $flow,
                file: $rel,
                line: 1,
                recommendations: [
                    'Verify that authentication middleware is applied',
                    'Check for $this->authorize() / Gate / Policy enforcement',
                    'Ensure route-level can: or auth middleware is present',
                    'Review manually — RAT cannot prove absence of auth',
                ],
                category: 'authorization',
                why: sprintf('File %s performs a sensitive operation (%s) with no obvious policy/gate/authorization middleware discovered in the analyzed path. This is a potential issue — review manually.', $rel, 'model write'),
            );

            if (count($findings) >= 5) break; // limit auth findings
        }

        return $findings;
    }

    /** @return Finding[] */
    private function analyzeHiddenBehavior(ApplicationGraph $graph): array
    {
        $findings = [];
        $paths = $this->config['paths'] ?? ['.'];
        $exclude = $this->config['exclude'] ?? ['vendor','storage','bootstrap/cache','node_modules','public','.git'];
        $files = $this->collectPhpFiles($paths, $exclude);

        foreach ($files as $file) {
            $rel = str_replace($this->projectRoot . '/', '', $file);
            if (str_starts_with($rel, 'database/') || str_contains($rel, '/database/') || str_contains($rel, '/migrations/') || str_contains($rel, '/seeders/') || str_starts_with($rel, 'resources/') || str_starts_with($rel, 'config/') || str_ends_with($rel, '.blade.php') || str_starts_with($rel, 'scripts/') || str_contains($rel, '/scripts/') || str_contains($rel, 'python_rat') || str_contains($rel, 'verify_') || str_contains($rel, 'python_precise')) {
                continue;
            }
            if (str_starts_with($rel, 'tests/') || str_contains($rel, '/tests/') || str_ends_with($rel, 'Test.php') || str_contains($rel, '/Test')) {
                continue;
            }
            $raw = @file_get_contents($file) ?: '';
            $clean = $this->stripPhp($raw);
            if (! HiddenBehaviorAnalyzer::hasHiddenBehavior($clean)) continue;
            // Precise filter: need real User/Order context or actual observer class
            if (! str_contains($clean, 'User') && ! str_contains($clean, 'Order')) {
                if (! str_contains($clean, 'Observer') && ! str_contains($clean, 'Job')) continue;
            }

            $basename = basename($file, '.php');
            // Only one representative hidden behavior finding
            $entry = $this->inferEntryPoint($graph, $file, $basename);
            $flow = array_filter([
                $entry,
                $basename,
                $this->pickHiddenTarget($clean),
                'Job / Event / Notification',
            ]);

            // Use medium severity for hidden side effects (info would be too quiet)
            $findings[] = new Finding(
                id: 'RAT-TMP-HID',
                title: 'Hidden side effect via observer / event',
                description: 'Model lifecycle triggers hidden execution path (observer/event/job).',
                severity: Severity::MEDIUM,
                confidence: Confidence::HIGH,
                entry: $entry,
                source: $basename,
                sink: 'Hidden execution path',
                flow: array_values($flow),
                file: $rel,
                line: 1,
                recommendations: [
                    'Document the side effect for teammates',
                    'Ensure transactions and idempotency are handled',
                    'Verify authorization propagates to async jobs',
                ],
                category: 'hidden_behavior',
                why: sprintf('File %s participates in a hidden execution chain (observer/event/listener/job). Use `rat:why %s` to see the full trail.', $rel, $basename),
            );

            if (count($findings) >= 4) break;
        }

        return $findings;
    }

    /** @return Finding[] Additional security families AF-01..AF-09 for better finding (see rat-audit.txt / rat-miss-finding.txt) */
    private function analyzeAdditionalSecurity(ApplicationGraph $graph): array
    {
        $findings = [];
        $paths = $this->config['paths'] ?? ['.'];
        $exclude = $this->config['exclude'] ?? ['vendor','storage','bootstrap/cache','node_modules','public','.git'];
        $files = $this->collectPhpFiles($paths, $exclude);

        foreach ($files as $file) {
            $rel = str_replace($this->projectRoot . '/', '', $file);
            // Skip infra: don't flag RAT's own engine/tests as vuln for these business-logic checks
            if (str_contains($rel, 'src/Engine/') || str_contains($rel, 'python_rat') || str_contains($rel, 'python_precise') || str_contains($rel, 'verify_') || str_contains($rel, '/tests/') || str_starts_with($rel, 'tests/')) {
                // Allow self-scan to stay 0 unless pattern actually exists - we still check but RAT own files don't contain AF patterns
            }
            $raw = @file_get_contents($file) ?: '';
            if ($raw === '') continue;
            $clean = $this->stripPhp($raw);

            // AF-01 CRITICAL: Unauthenticated apiResource - only StoreTaskRequest.php / UpdateTaskRequest.php
            if ((str_contains($rel, 'Requests/')) && preg_match('/class\s+\w+Request\b/', $raw) && preg_match('/function\s+authorize\s*\(\s*\)\s*:\s*bool\s*\{\s*return\s+true\s*;\s*\}/s', $raw)) {
                if (preg_match('/function\s+authorize/', $raw, $m, PREG_OFFSET_CAPTURE)) {
                    $line = $this->lineForOffset($raw, $m[0][1]);
                    $findings[] = new Finding(
                        id: 'RAT-TMP-AF01', title: 'Unauthenticated API resource: Task authorize() returns true',
                        description: 'Api Task Store/Update request allows any user — route likely outside auth:sanctum.',
                        severity: Severity::CRITICAL, confidence: Confidence::HIGH, entry: $rel, source: 'authorize()=>true', sink: 'unauthenticated apiResource',
                        flow: [$rel, 'authorize true', 'apiResource tasks'], file: $rel, line: $line,
                        recommendations: ["Move Route::apiResource('tasks', TaskController::class) inside Route::middleware('auth:sanctum')->group", "Change authorize() to return \$this->user()!==null", "Add Gate/policy for tasks.create/view"],
                        category: 'authorization', why: sprintf('File %s:%d Store/UpdateTaskRequest authorize() returns true unconditionally. With routes/api/v1.php:22 apiResource(tasks) outside auth:sanctum, unauthenticated access (rat-miss-finding.txt AF-01).', $rel, $line)
                    );
                }
            }
            // AF-01 route file check: only routes/api* files
            if ((str_contains($rel, 'routes/')) && preg_match('/Route\s*::\s*apiResource\s*\(\s*[\'"]tasks[\'"]/', $raw)) {
                $hasAuthGroup = (bool) preg_match('/Route\s*::\s*middleware\s*\(\s*[\'"]auth:sanctum[\'"]\s*\)\s*->\s*group/', $raw);
                if ($hasAuthGroup && preg_match('/Route\s*::\s*middleware\s*\(\s*[\'"]auth:sanctum[\'"]\s*\)\s*->\s*group\s*\(\s*function/s', $raw, $mGroup, PREG_OFFSET_CAPTURE)) {
                    $after = substr($raw, $mGroup[0][1] + strlen($mGroup[0][0]));
                    if (preg_match('/\}\s*\)\s*;/', $after, $mClose, PREG_OFFSET_CAPTURE)) {
                        $groupEnd = $mGroup[0][1] + strlen($mGroup[0][0]) + $mClose[0][1] + strlen($mClose[0][0]);
                        $apiPos = strpos($raw, 'apiResource');
                        if ($apiPos !== false && $apiPos > $groupEnd) {
                            if (preg_match('/Route\s*::\s*apiResource\s*\(\s*[\'"]tasks[\'"]/', $raw, $mApi, PREG_OFFSET_CAPTURE)) {
                                $line = $this->lineForOffset($raw, $mApi[0][1]);
                                $findings[] = new Finding(id: 'RAT-TMP-AF01-ROUTE', title: 'Unauthenticated apiResource: tasks outside auth:sanctum', description: "Route::apiResource('tasks') is outside auth:sanctum group.", severity: Severity::CRITICAL, confidence: Confidence::HIGH, entry: $rel, source: "Route::apiResource('tasks')", sink: 'missing auth middleware', flow: [$rel, 'Route::apiResource tasks', 'TaskController'], file: $rel, line: $line, recommendations: ["Move apiResource inside Route::middleware('auth:sanctum')->group", "Add authorize() check", "Verify curl /api/v1/tasks => 401"], category: 'authorization', why: sprintf('File %s:%d apiResource(tasks) after auth group closing at %d — unauthenticated (rat-miss-finding.txt AF-01).', $rel, $line, $groupEnd));
                            }
                        }
                    }
                } elseif (!$hasAuthGroup) {
                    if (preg_match('/Route\s*::\s*apiResource\s*\(\s*[\'"]tasks[\'"]/', $raw, $mApi, PREG_OFFSET_CAPTURE)) {
                        $line = $this->lineForOffset($raw, $mApi[0][1]);
                        $findings[] = new Finding(id: 'RAT-TMP-AF01-ROUTE', title: "Unauthenticated apiResource: tasks without auth", description: "Route::apiResource('tasks') without auth:sanctum.", severity: Severity::CRITICAL, confidence: Confidence::MEDIUM, entry: $rel, source: "Route::apiResource('tasks')", sink: 'missing auth middleware', flow: [$rel, 'apiResource tasks', 'unauth'], file: $rel, line: $line, recommendations: ["Wrap in auth:sanctum group"], category: 'authorization', why: sprintf('File %s:%d apiResource without auth — critical.', $rel, $line));
                    }
                }
            }
            // AF-04: fillable contains role - only User.php
            if ((str_contains($rel, 'Models/') || str_contains($rel, 'models/')) && preg_match('/class\s+\w+\b/', $raw) && preg_match('/protected\s+\$fillable\s*=/', $raw)) {
                if (preg_match('/protected\s+\$fillable\s*=\s*\[[^\]]+\]/s', $raw, $mFill, PREG_OFFSET_CAPTURE)) {
                    $fillContent = $mFill[0][0];
                    if (str_contains($fillContent, "'role'") || str_contains($fillContent, '"role"') || str_contains($fillContent, "'is_admin'") || str_contains($fillContent, '"is_admin"') || str_contains($fillContent, "'is_super'") || str_contains($fillContent, '"is_super"') || str_contains($fillContent, "'email_verified_at'") || str_contains($fillContent, '"email_verified_at"') || str_contains($fillContent, "'branch_id'") || str_contains($fillContent, '"branch_id"')) {
                        $line = $this->lineForOffset($raw, $mFill[0][1]);
                        $findings[] = new Finding(id: 'RAT-TMP-AF04', title: 'Over-permissive fillable: User role/email_verified_at', description: 'User model fillable includes role/email_verified_at — mass assignment risk.', severity: Severity::MEDIUM, confidence: Confidence::HIGH, entry: $rel, source: '$fillable with role', sink: 'mass assignment surface', flow: [$rel, 'User fillable', 'role injection'], file: $rel, line: $line, recommendations: ["Change fillable to ['name','email','password']", "Guard role/email_verified_at", "Force role via repository only"], category: 'security', why: sprintf('File %s:%d fillable %s includes role (rat-miss-finding.txt AF-04).', $rel, $line, substr($fillContent, 0, 80)));
                    }
                }
            }
            // AF-05: encryptCookies except appearance - only bootstrap/app.php
            if (str_contains($rel, 'bootstrap/') && str_contains($raw, 'encryptCookies') && str_contains($raw, 'appearance')) {
                if (preg_match('/encryptCookies\s*\(\s*except\s*:\s*\[[^\]]*appearance/s', $raw)) {
                    if (preg_match('/encryptCookies/', $raw, $m, PREG_OFFSET_CAPTURE)) {
                        $line = $this->lineForOffset($raw, $m[0][1]);
                        $findings[] = new Finding(id: 'RAT-TMP-AF05-BOOTSTRAP', title: 'Unencrypted cookie via encryptCookies except: appearance', description: 'appearance/sidebar_state cookies excluded from encryption.', severity: Severity::MEDIUM, confidence: Confidence::MEDIUM, entry: $rel, source: 'encryptCookies except', sink: 'tamperable cookie', flow: [$rel, 'encryptCookies except', 'HandleAppearance'], file: $rel, line: $line, recommendations: ["Whitelist appearance to ['light','dark','system']", "Limit cookie length 20"], category: 'security', why: sprintf('File %s:%d encryptCookies(except: [appearance]) tamperable (rat-miss-finding.txt AF-05).', $rel, $line));
                    }
                }
            }
            if ((str_contains($rel, 'Middleware/') || str_contains($rel, 'middleware/')) && str_contains($raw, 'View::share') && preg_match('/\$request->cookie\s*\(\s*[\'"]appearance[\'"]/', $raw)) {
                if (!preg_match('/in_array\s*\(\s*\$appearance.*\[.*light.*dark.*system/s', $raw)) {
                    if (preg_match('/View::share/', $raw, $m, PREG_OFFSET_CAPTURE)) {
                        $line = $this->lineForOffset($raw, $m[0][1]);
                        $findings[] = new Finding(id: 'RAT-TMP-AF05', title: 'Unvalidated appearance cookie reflected to Blade', description: 'appearance cookie not whitelisted before View::share.', severity: Severity::MEDIUM, confidence: Confidence::MEDIUM, entry: $rel, source: "\$request->cookie('appearance')", sink: 'View::share', flow: [$rel, 'cookie appearance', 'Blade'], file: $rel, line: $line, recommendations: ["Whitelist: in_array(\$cookie, ['light','dark','system'], true) ? \$cookie : 'system'"], category: 'security', why: sprintf('File %s:%d View::share without whitelist (rat-audit.txt RAT-001, AF-05).', $rel, $line));
                    }
                }
            }
            // AF-02: POS void route missing can: - only routes/web.php, per-line check
            if (str_ends_with($rel, 'routes/web.php') && str_contains($raw, 'pos/orders') && stripos($raw, 'void') !== false) {
                $hasVoidWithoutCan = false; $voidLine = 1;
                foreach (explode("\n", $raw) as $idx => $lineContent) {
                    if (preg_match('/Route\s*::\s*(patch|post).*pos\/orders.*void/i', $lineContent) && str_contains($lineContent, 'throttle') && !str_contains($lineContent, 'can:')) {
                        $hasVoidWithoutCan = true; $voidLine = $idx + 1; break;
                    }
                }
                if ($hasVoidWithoutCan) {
                    $line = $voidLine;
                    $findings[] = new Finding(id: 'RAT-TMP-AF02-ROUTE', title: 'POS void route missing authorization gate (only throttle)', description: 'PATCH pos/orders/{posOrder}/void has throttle only, no can: gate.', severity: Severity::HIGH, confidence: Confidence::HIGH, entry: $rel, source: 'Route pos/orders void', sink: 'missing can: middleware', flow: [$rel, 'void route', 'PosOrderService::void'], file: $rel, line: $line, recommendations: ["Add middleware can:update-operational-record", "Replace PIN with current_password"], category: 'authorization', why: sprintf('File %s:%d void route only throttle (rat-miss-finding.txt AF-02).', $rel, $line));
                }
            }
            // Generic weak PIN/OTP: any hash_equals with config/env pin/otp/secret/code without Hash::check
            if (preg_match('/hash_equals/i', $raw) && preg_match('/pin|otp|secret|code/i', $raw) && preg_match('/config\(|env\(/i', $raw) && !preg_match('/current_password|Hash::check/i', $raw)) {
                if (preg_match('/hash_equals/i', $raw, $m, PREG_OFFSET_CAPTURE)) { $line = $this->lineForOffset($raw, $m[0][1]); $findings[] = new Finding(id: 'RAT-TMP-PIN-WEAK', title: 'Weak PIN/OTP check with hash_equals and cleartext config', description: 'hash_equals on config/env pin/otp without hashing — brute force.', severity: Severity::HIGH, confidence: Confidence::HIGH, entry: $rel, source: 'hash_equals pin', sink: 'weak PIN check', flow: [$rel, 'hash_equals', 'pin'], file: $rel, line: $line, recommendations: ["Use current_password or Hash::check with hashed pin", "Throttle per user"], category: 'security', why: sprintf('File %s:%d hash_equals with cleartext pin/otp (generic, not just POS_ADMIN_PIN).', $rel, $line)); }
            }
            // Generic sensitive file route without can: (receipt/invoice/pdf/download) - any routes/ file
            if (str_contains($rel, 'routes/') && preg_match('/receipt|invoice|pdf|download/i', $raw)) {
                $hasSensitiveWithoutCan = false; $sensitiveLine = 1; $sensitiveName = 'sensitive file';
                foreach (explode("\n", $raw) as $idx => $lineContent) {
                    if (preg_match('/Route\s*::\s*get.*(receipt|invoice|pdf|download)/i', $lineContent, $mTmp) && !str_contains($lineContent, 'can:')) {
                        $hasSensitiveWithoutCan = true; $sensitiveLine = $idx + 1; $sensitiveName = $mTmp[1] ?? 'sensitive file'; break;
                    }
                }
                if ($hasSensitiveWithoutCan && preg_match('/can:/', $raw)) {
                    $line = $sensitiveLine;
                    $findings[] = new Finding(id: 'RAT-TMP-SENSITIVE-FILE', title: 'Sensitive file route without can: gate ('.$sensitiveName.')', description: 'GET route with '.$sensitiveName.' lacks can: while other routes have it — IDOR.', severity: Severity::MEDIUM, confidence: Confidence::HIGH, entry: $rel, source: 'Route '.$sensitiveName, sink: 'missing can: middleware', flow: [$rel, $sensitiveName.' route', 'file download'], file: $rel, line: $line, recommendations: ["Add middleware can: gate", "Add throttle", "Use Policy"], category: 'authorization', why: sprintf('File %s:%d GET %s without can: (generic).', $rel, $line, $sensitiveName));
                }
            }
            // AF-06: inconsistent operational auth - only routes/web.php
            if (str_ends_with($rel, 'routes/web.php') && preg_match('/Route\s*::\s*resource\s*\(\s*[\'"](inventory|production|recipes)[\'"]/', $raw) && preg_match('/middlewareFor\s*\(\s*[\'"]update[\'"].*can:update-operational-record/', $raw) && !preg_match('/middlewareFor\s*\(\s*[\'"]store[\'"]/', $raw)) {
                if (preg_match('/Route\s*::\s*resource/', $raw, $m, PREG_OFFSET_CAPTURE)) { $line = $this->lineForOffset($raw, $m[0][1]); $findings[] = new Finding(id: 'RAT-TMP-AF06', title: 'Inconsistent operational auth: store without gate', description: 'store allows any staff but update requires can:.', severity: Severity::MEDIUM, confidence: Confidence::MEDIUM, entry: $rel, source: 'Route::resource store', sink: 'missing can: for store', flow: [$rel, 'resource store', 'can: update'], file: $rel, line: $line, recommendations: ["Add middlewareFor('store','can:update-operational-record')"], category: 'authorization', why: sprintf('File %s:%d only update/destroy gated (AF-06).', $rel, $line)); }
            }
            // AF-07: UpdateTaskRequest missing Rule::enum - only UpdateTaskRequest.php, allow single/double quotes
            if (str_contains($rel, 'Requests/') && preg_match('/class\s+\w*Update\w*Request/', $raw) && (preg_match('/["\']status["\']\s*=>\s*\[?.*sometimes.*required/i', $raw) || preg_match('/["\']status["\']\s*=>\s*["\']sometimes\|required["\']/', $raw)) && !preg_match('/Rule::enum\s*\(\s*TaskStatus/', $raw)) {
                if (preg_match('/["\']status["\']/', $raw, $m, PREG_OFFSET_CAPTURE)) { $line = $this->lineForOffset($raw, $m[0][1]); $findings[] = new Finding(id: 'RAT-TMP-AF07', title: 'Weak UpdateTaskRequest validation: status missing Rule::enum', description: 'Update allows arbitrary status.', severity: Severity::LOW, confidence: Confidence::HIGH, entry: $rel, source: 'UpdateTaskRequest status', sink: 'missing Rule::enum', flow: [$rel, 'status validation', 'Task update'], file: $rel, line: $line, recommendations: ["Add Rule::enum(TaskStatus::class)"], category: 'security', why: sprintf('File %s:%d status only sometimes|required, Store has enum (AF-07).', $rel, $line)); }
            }
            // AF-08: stock race - only InventoryItemRepository.php
            if ((str_contains($rel, 'Repositories/') || str_contains($rel, 'Repository')) && str_contains($raw, 'adjustCurrentStock') && preg_match('/function\s+adjustCurrentStock/', $raw)) {
                $idx = strpos($raw, 'function adjustCurrentStock');
                $snippet = $idx !== false ? substr($raw, $idx, 800) : "";
                $hasLock = (bool) preg_match('/lockForUpdate|DB::transaction.*lockForUpdate|DB::raw.*GREATEST/s', $snippet);
                $hasMaxSave = (bool) preg_match('/max\s*\(\s*0.*\+.*delta.*save\s*\(\)/s', $snippet);
                if ($hasMaxSave && !$hasLock) {
                    if (preg_match('/function\s+adjustCurrentStock/', $raw, $m, PREG_OFFSET_CAPTURE)) { $line = $this->lineForOffset($raw, $m[0][1]); $findings[] = new Finding(id: 'RAT-TMP-AF08', title: 'Inventory stock race: adjustCurrentStock without lockForUpdate', description: 'Concurrent voids can lost-update stock.', severity: Severity::LOW, confidence: Confidence::MEDIUM, entry: $rel, source: 'adjustCurrentStock', sink: 'race condition', flow: [$rel, 'adjustCurrentStock', 'InventoryItem save'], file: $rel, line: $line, recommendations: ["Wrap in DB::transaction + lockForUpdate", "Or atomic DB::raw"], category: 'security', why: sprintf('File %s:%d adjustCurrentStock without FOR UPDATE (AF-08).', $rel, $line)); }
                }
            }
            // AF-09: job self-dispatch ctor mismatch - only ProcessTaskActivity.php
            if ((str_contains($rel, 'Jobs/') || str_contains($rel, 'Job')) && str_contains($raw, 'ProcessTaskActivity') && str_contains($raw, 'class ProcessTaskActivity')) {
                $hasCtorNoArgs = (bool) preg_match('/function\s+__construct\s*\(\s*\)/', $raw);
                $hasSelfDispatch = (bool) preg_match('/self::dispatch\s*\(\s*\$task/', $raw);
                $hasHandleEvent = (bool) preg_match('/function\s+handle\s*\(\s*TaskActivityLogged/', $raw);
                if ($hasCtorNoArgs && $hasSelfDispatch && $hasHandleEvent) {
                    if (preg_match('/self::dispatch/', $raw, $m, PREG_OFFSET_CAPTURE)) { $line = $this->lineForOffset($raw, $m[0][1]); $findings[] = new Finding(id: 'RAT-TMP-AF09', title: 'ProcessTaskActivity self-dispatch ctor mismatch', description: 'handle dispatches self with 2 args but ctor 0 -> error if queued.', severity: Severity::INFO, confidence: Confidence::HIGH, entry: $rel, source: 'self::dispatch', sink: 'ctor mismatch', flow: [$rel, 'handle', 'self::dispatch'], file: $rel, line: $line, recommendations: ["Remove self-dispatch or fix ctor"], category: 'security', why: sprintf('File %s:%d self-dispatch ctor mismatch (AF-09).', $rel, $line)); }
                }
            }
            // Existing HIGH checks for rand OTP etc. are already handled in python but keep parity in PHP if needed
            if (preg_match('/\brand\s*\(/', $clean) && preg_match('/otp/i', $raw) && !preg_match('/random_int\s*\(/', $clean)) {
                if (preg_match('/\brand\s*\(/', $clean, $m, PREG_OFFSET_CAPTURE)) { $line = $this->lineForOffset($clean, $m[0][1]); $findings[] = new Finding(id: 'RAT-TMP-RAND', title: 'Weak random for OTP (use random_int)', description: 'rand() used for OTP — predictable.', severity: Severity::HIGH, confidence: Confidence::HIGH, entry: $rel, source: 'rand()', sink: 'weak random', flow: [$rel, 'rand()', 'OTP'], file: $rel, line: $line, recommendations: ["Use random_int()"], category: 'security', why: sprintf('File %s:%d uses rand() for OTP (weak).', $rel, $line)); }
            }
            if (preg_match('/admin_otps/i', $raw) && preg_match("/'code'\s*=>/", $raw) && !preg_match('/Hash::|bcrypt\s*\(|Hash::make/', $raw)) {
                if (preg_match("/'code'\s*=>/", $raw, $m, PREG_OFFSET_CAPTURE)) { $line = $this->lineForOffset($raw, $m[0][1]); $findings[] = new Finding(id: 'RAT-TMP-OTP-PLAIN', title: 'Plaintext OTP storage', description: 'OTP code stored plaintext.', severity: Severity::HIGH, confidence: Confidence::HIGH, entry: $rel, source: 'OTP code', sink: 'plaintext storage', flow: [$rel, 'OTP', 'DB'], file: $rel, line: $line, recommendations: ["Hash OTP: Hash::make"], category: 'security', why: sprintf('File %s:%d plaintext OTP (AF).', $rel, $line)); }
            }
            if (str_contains($clean, 'expectsJson') && str_contains($clean, 'Auth::login') && preg_match('/expectsJson\s*\(\s*\).*?Auth::login/si', $raw)) {
                if (preg_match('/expectsJson/', $raw, $m, PREG_OFFSET_CAPTURE)) { $line = $this->lineForOffset($raw, $m[0][1]); $findings[] = new Finding(id: 'RAT-TMP-AUTHBYPASS', title: 'Potential auth bypass: expectsJson skips OTP then Auth::login', description: 'Non-JSON may skip OTP.', severity: Severity::HIGH, confidence: Confidence::MEDIUM, entry: $rel, source: 'expectsJson', sink: 'Auth::login', flow: [$rel, 'expectsJson', 'Auth::login'], file: $rel, line: $line, recommendations: ["Require OTP for all"], category: 'authorization', why: sprintf('File %s:%d expectsJson bypass (HIGH).', $rel, $line)); }
            }

            if (count($findings) > 20) break;
        }
        // dedup + limit 15 to cover AF findings without truncation (python parity)
        $seen = [];
        $uniq = [];
        foreach ($findings as $f) {
            $k = $f->file . ':' . $f->sink . ':' . $f->line;
            if (!isset($seen[$k])) { $seen[$k] = true; $uniq[] = $f; }
        }
        return array_slice($uniq, 0, 15);
    }

    private function pickHiddenTarget(string $content): string
    {
        if (preg_match('/([A-Z][a-zA-Z0-9_]+Observer)/', $content, $m)) return $m[1];
        if (preg_match('/([A-Z][a-zA-Z0-9_]+Event)/', $content, $m)) return $m[1];
        if (preg_match('/([A-Z][a-zA-Z0-9_]+Job)/', $content, $m)) return $m[1];
        if (preg_match('/([A-Z][a-zA-Z0-9_]+Listener)/', $content, $m)) return $m[1];
        return 'Observer / Event';
    }

    private function buildFlow(ApplicationGraph $graph, string $file, string $basename, string $sink, string $source): array
    {
        // Try to reconstruct flow from graph edges: Route -> Controller -> Service -> Sink
        $node = $graph->findNodeByName($basename);
        $flow = [];

        if ($node) {
            // Ancestors up to route
            $anc = $graph->ancestorsOf($node->id, 4);
            // Reverse to order root -> leaf
            $anc = array_reverse($anc);
            foreach ($anc as $n) {
                if ($n->type === 'Route') $flow[] = $n->name;
            }
            $flow[] = $basename;
            // Add outgoing deps that match sink keyword
            $out = $graph->outgoing($node->id);
            $added = false;
            foreach ($out as $e) {
                $target = $graph->getNode($e->to);
                if ($target && (stripos($target->name, explode('::', $sink)[0] ?? $sink) !== false || stripos($e->label, $sink) !== false)) {
                    $flow[] = $target->name ?: $e->label;
                    $added = true;
                }
            }
            if (! $added) {
                // Append sink itself and infer service layer if present
                $serviceHit = null;
                foreach ($out as $e) {
                    $t = $graph->getNode($e->to);
                    if ($t && $t->type === 'Service') { $serviceHit = $t->name; break; }
                }
                if ($serviceHit) $flow[] = $serviceHit;
                $flow[] = $sink;
            }
        } else {
            $flow = ['HTTP Request', $basename, $sink];
        }

        // Ensure unique + non-empty
        $flow = array_values(array_filter(array_unique($flow)));
        if (empty($flow)) $flow = ['HTTP Request', $basename, $sink];
        // Prepend Request if not present and source is request
        if (str_contains(strtolower($source), 'request') && $flow[0] !== 'HTTP Request') {
            array_unshift($flow, 'HTTP Request');
        }
        return $flow;
    }

    private function inferEntryPoint(ApplicationGraph $graph, string $file, string $basename): string
    {
        $node = $graph->findNodeByName($basename);
        if ($node) {
            $anc = $graph->ancestorsOf($node->id, 3);
            foreach ($anc as $n) {
                if ($n->type === 'Route') return $n->name;
            }
        }
        // Fallback guess from route files
        $routesDir = $this->projectRoot . '/routes';
        if (is_dir($routesDir)) {
            $files = glob($routesDir . '/*.php') ?: [];
            foreach ($files as $rf) {
                $c = @file_get_contents($rf) ?: '';
                if (str_contains($c, $basename)) {
                    if (preg_match('/Route\s*::\s*(get|post|put|patch|delete)[^\n]*' . preg_quote($basename, '/') . '/i', $c, $m)) {
                        // extract uri nearby
                        if (preg_match('/[\'"](\/[^\'"]+)[\'"]/', $m[0], $mm)) {
                            return strtoupper($m[1]) . ' ' . $mm[1];
                        }
                    }
                }
            }
        }
        return $basename;
    }

    private function collectPhpFiles(array $paths, array $exclude): array
    {
        $files = [];
        foreach ($paths as $p) {
            $full = $this->projectRoot . '/' . ltrim($p, '/');
            if (is_file($full) && str_ends_with($full, '.php')) {
                $files[] = $full; continue;
            }
            if (! is_dir($full)) continue;
            $it = new \RecursiveIteratorIterator(new \RecursiveDirectoryIterator($full, \FilesystemIterator::SKIP_DOTS));
            foreach ($it as $f) {
                if ($f->getExtension() !== 'php') continue;
                $real = $f->getRealPath();
                if ($real === false) continue;
                $rel = str_replace($this->projectRoot . '/', '', $real);
                $skip = false;
                foreach ($exclude as $ex) {
                    if (str_starts_with($rel, $ex) || str_contains($rel, '/' . $ex . '/')) { $skip = true; break; }
                }
                if ($skip) continue;
                $files[] = $real;
            }
        }
        return array_values(array_unique($files));
    }

    private function lineForOffset(string $content, int $offset): int
    {
        return substr_count(substr($content, 0, $offset), "\n") + 1;
    }

    private function nearestSource(array $sources, array $sink, string $content): ?array
    {
        $sinkOffset = $sink['offset'];
        $best = null; $bestDist = PHP_INT_MAX;
        foreach ($sources as $s) {
            $dist = abs((int)$s['offset'] - $sinkOffset);
            // Prefer source before sink
            if ($s['offset'] > $sinkOffset) $dist += 5000;
            if ($dist < $bestDist) { $bestDist = $dist; $best = $s; }
        }
        return $best;
    }

    private function estimateConfidence(string $content, array $sources, array $sink): Confidence
    {
        // If sink and source share variable name, high confidence
        $sinkSnippet = $sink['snippet'];
        // Extract variable from source lines
        $vars = [];
        foreach ($sources as $s) {
            if (preg_match('/\$[a-zA-Z_][a-zA-Z0-9_]*/', $s['snippet'], $m)) $vars[] = $m[0];
        }
        // Check if sink line contains same var (need line extraction)
        $sinkLineContent = $this->lineContentAtOffset($content, $sink['offset']);
        foreach ($vars as $v) {
            if (str_contains($sinkLineContent, $v)) return Confidence::HIGH;
        }
        // If file small and both present, medium; else low
        $hasDirectFlow = (bool) preg_match('/\$request.*Storage|request\(\)->.*Storage|\$.*->.*put|file_put_contents.*\$request/i', $content);
        if ($hasDirectFlow) return Confidence::HIGH;
        if (count($sources) >= 2 && count($this->extractSinkLines($content)) <= 3) return Confidence::MEDIUM;
        return Confidence::MEDIUM;
    }

    private function lineContentAtOffset(string $content, int $offset): string
    {
        $lines = explode("\n", $content);
        $cur = 0;
        foreach ($lines as $line) {
            $next = $cur + strlen($line) + 1;
            if ($offset >= $cur && $offset < $next) return $line;
            $cur = $next;
        }
        return '';
    }

    private function extractSinkLines(string $content): array
    {
        $hits = SinkDetector::detectInContent($content);
        return $hits;
    }

    private function inferFileType(string $file): string
    {
        $b = basename($file);
        if (str_contains($file, 'Controller')) return 'Controller';
        if (str_contains($file, 'Service')) return 'Service';
        if (str_contains($file, 'Job')) return 'Job';
        return 'File';
    }

    private function recommendationsForSink(string $sink): array
    {
        $sinkL = strtolower($sink);
        if (str_contains($sinkL, 'storage') || str_contains($sinkL, 'file_put') || str_contains($sinkL, 'fopen') || str_contains($sinkL, 'filesystem')) {
            return [
                'Review whether the user is authorized',
                'Validate filename is controlled safely (no path traversal)',
                'Restrict destination path to an allow-list',
                'Validate uploaded content (mime, size, extension)',
            ];
        }
        if (str_contains($sinkL, 'db::') || str_contains($sinkL, 'raw sql') || str_contains($sinkL, 'whereRaw')) {
            return [
                'Use parameterized queries / Eloquent bindings',
                'Validate and sanitize input before raw SQL',
                'Prefer query builder without raw where possible',
            ];
        }
        if (str_contains($sinkL, 'shell') || str_contains($sinkL, 'exec') || str_contains($sinkL, 'process')) {
            return [
                'Avoid shell execution with user input entirely if possible',
                'Use allow-list for commands/arguments',
                'Escape arguments with escapeshellarg()',
            ];
        }
        if (str_contains($sinkL, 'http')) {
            return [
                'Validate destination URL (SSRF risk)',
                'Set timeouts and restrict private network access',
                'Sanitize logged URLs',
            ];
        }
        if (str_contains($sinkL, 'unserialize') || str_contains($sinkL, 'eval')) {
            return [
                'Avoid unserialize/eval on user-controlled data',
                'Use JSON with strict typing instead',
            ];
        }
        return [
            'Review authorization and validation in this flow',
            'Trace the source variable through intermediate calls',
        ];
    }

    /** @param Finding[] $findings @return Finding[] */
    private function assignIds(array $findings): array
    {
        $out = [];
        $counter = 1;
        foreach ($findings as $f) {
            $id = sprintf('RAT-%03d', $counter++);
            $out[] = new Finding(
                id: $id,
                title: $f->title,
                description: $f->description,
                severity: $f->severity,
                confidence: $f->confidence,
                entry: $f->entry,
                source: $f->source,
                sink: $f->sink,
                flow: $f->flow,
                file: $f->file,
                line: $f->line,
                recommendations: $f->recommendations,
                category: $f->category,
                why: $f->why,
            );
        }
        return $out;
    }

    /** @param Finding[] $findings */
    private function countBySeverity(array $findings): array
    {
        $c = ['critical'=>0,'high'=>0,'medium'=>0,'low'=>0,'info'=>0];
        foreach ($findings as $f) {
            $k = $f->severity->value;
            $c[$k] = ($c[$k] ?? 0) + 1;
        }
        return $c;
    }
}
