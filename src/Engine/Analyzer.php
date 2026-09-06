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
            'exclude' => ['vendor','storage','bootstrap/cache','node_modules','public','.git','.idea','.vscode'],
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
