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
            $content = @file_get_contents($file) ?: '';
            if ($content === '') continue;

            $sources = SourceDetector::detectInContent($content);
            $sinks = SinkDetector::detectInContent($content);

            if (empty($sources) || empty($sinks)) continue;

            // Heuristic: if file contains both source and sink, report potential dangerous flow
            // Try to correlate via line proximity & variable taint simulation (lightweight)
            foreach ($sinks as $sink) {
                $sinkLine = $this->lineForOffset($content, $sink['offset']);
                $nearestSource = $this->nearestSource($sources, $sink, $content);

                // Confidence based on proximity and variable sharing
                $confidence = $this->estimateConfidence($content, $sources, $sink);
                $severity = $sink['severity'];

                // Bump severity if tainted request directly flows into critical sink without validation visible
                $hasValidation = (bool) preg_match('/->\s*validate\s*\(|FormRequest|Validator::/i', $content);
                if (! $hasValidation && $severity === Severity::CRITICAL) {
                    $confidence = Confidence::HIGH;
                } elseif ($hasValidation) {
                    // Lower confidence if validation present — still flag but medium
                    if ($confidence === Confidence::HIGH) $confidence = Confidence::MEDIUM;
                }

                // Build flow trace: try to infer chain from graph
                $basename = basename($file, '.php');
                $type = $this->inferFileType($file);
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

            // Cap findings per file to avoid noise — max 2
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
            $content = @file_get_contents($file) ?: '';
            if ($content === '') continue;

            // Only analyze controllers/services that look like admin or user-modifying
            if (! preg_match('/Controller|admin/i', $file) && ! str_contains($content, 'User::')) continue;

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
            $content = @file_get_contents($file) ?: '';
            if (stripos($file, 'Observer.php') === false && stripos($content, 'Observer') === false) {
                // Also look for model events
                if (! HiddenBehaviorAnalyzer::hasHiddenBehavior($content)) continue;
                // Only flag if graph shows user service touches model with observer listeners
                if (! str_contains($content, 'User') && ! str_contains($content, 'Order')) continue;
            }

            $basename = basename($file, '.php');
            // Only one representative hidden behavior finding
            $entry = $this->inferEntryPoint($graph, $file, $basename);
            $flow = array_filter([
                $entry,
                $basename,
                $this->pickHiddenTarget($content),
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
