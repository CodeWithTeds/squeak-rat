<?php

namespace Rat\Console\Commands;

use Illuminate\Console\Command;
use Rat\Support\RatBanner;
use Rat\Engine\Analyzer;
use Rat\Engine\Reporters\JsonReporter;
use Rat\Engine\Findings\Severity;
use Symfony\Component\Console\Helper\ProgressBar;
use Symfony\Component\Console\Helper\Table;

class RatCommand extends Command
{
    protected $signature = 'rat
                            {--format= : Output format (table|json|ndjson)}
                            {--json : Alias for --format=json}
                            {--ci : CI mode (non-zero exit if findings exceed threshold)}
                            {--fail-on= : Override fail_on severity (critical|high|medium|low)}
                            {--no-image : Disable rat.png inline image}
                            {--compact : Compact banner}
                            {--all : Scan whole codebase (all PHP excluding vendor/storage)}
                            {--path= : Comma-separated paths to scan (overrides config)}
                            {--security : Security scan — vulnerability & attack-surface analysis}
                            {--deep : Deep security scan — Advanced data-flow + behavior analysis}';

    protected $description = 'RAT — Laravel Security & Behavior Analyzer. Scan application.';

    public function handle(): int
    {
        $format = $this->option('format') ?: ($this->option('json') ? 'json' : 'table');
        $ci = (bool) $this->option('ci');
        $failOn = $this->option('fail-on');
        $noImage = (bool) $this->option('no-image');
        $compact = (bool) $this->option('compact');
        $all = (bool) $this->option('all');
        $pathOpt = $this->option('path');
        $security = (bool) $this->option('security');
        $deep = (bool) $this->option('deep');

        // Honor no-image for banner
        if ($noImage) {
            $_SERVER['RAT_NO_IMAGE'] = '1';
            putenv('RAT_NO_IMAGE=1');
        }

        $isJson = in_array($format, ['json','ndjson'], true);
        $isPlain = $format === 'table' && ! $this->output->isDecorated();
        $usePython = $this->shouldDelegateToPython();

        if (! $isJson && ! $usePython) {
            RatBanner::render($this->output, ! $noImage, $compact);

            if ($deep) {
                $this->output->writeln('  <fg=#8b5cf6;options=bold>🐀 RAT // DEEP SECURITY SCAN</>');
                $this->output->writeln('  <fg=#a78bfa>Advanced data-flow + behavior analysis — whole codebase, vendor excluded</>');
            } elseif ($security) {
                $this->output->writeln('  <fg=#8b5cf6;options=bold>🐀 RAT // SECURITY SCAN</>');
                $this->output->writeln('  <fg=gray>Vulnerability & attack-surface — whole codebase, vendor excluded</>');
            }
            $this->output->writeln('');
            $this->output->writeln('  <fg=#8b5cf6>Scanning application...</>');
            $this->output->writeln('');
        } elseif (! $isJson && $usePython) {
            // Python will render its own violet banner — show a brief hand-off
            if ($deep) {
                $this->output->writeln('  <fg=#8b5cf6;options=bold>🐀 RAT // DEEP SECURITY SCAN (Python)</>');
            } elseif ($security) {
                $this->output->writeln('  <fg=#8b5cf6;options=bold>🐀 RAT // SECURITY SCAN (Python)</>');
            }
        }

        $cfg = $this->loadRatConfig();
        // Decide scan scope: --deep / --security / --all / --path / interactive choice / config default
        $cfg = $this->resolveScanScope($cfg, $all, $pathOpt, $isJson, $security, $deep);

        // Prefer Python precise scanner if available — delegate after scope is resolved (keeps PHP chooser UI, runs Python engine)
        if ($this->shouldDelegateToPython()) {
            $exit = $this->delegateToPythonWithCfg($cfg, $format, $ci, $failOn, $noImage, $compact);
            if ($exit !== null) return $exit;
        }

        $analyzer = new Analyzer(getcwd(), $cfg);

        // Capture progress but render minimally if not json
        $stats = null;
        $graph = null;
        $findings = [];

        // For table mode, render scanning steps similar to flow.md
        if (! $isJson) {
            $this->renderScanningSkeleton();
        }

        $result = $analyzer->analyze(function($stage, $pct) use (&$isJson) {
            // could update progress bar if we had one
        });

        $graph = $result['graph'];
        $findings = $result['findings'];
        $stats = $result['stats'];

        if (! $isJson) {
            $this->renderStatsSection($stats);
            $this->renderFindingsSummary($findings);
            $this->renderHints();
        }

        // Machine-readable outputs
        if ($format === 'json') {
            $reporter = new JsonReporter();
            $this->output->writeln($reporter->report($findings, $stats));
        } elseif ($format === 'ndjson') {
            $reporter = new JsonReporter();
            $this->output->writeln($reporter->ndjson($findings));
        } elseif ($isJson && $format !== 'table') {
            // fallback already handled
        }

        if ($ci) {
            return $this->handleCi($findings, $failOn ?? $stats['project_root'] ?? null);
        }

        // Persist last scan for rat:show etc.
        $this->persistLastScan($findings, $stats, $graph);

        // Exit code 0 unless CI; but if critical found, still 0 for default mode (per spec, only --ci fails)
        return 0;
    }

    private function renderScanningSkeleton(): void
    {
        // We will later overwrite with real counts; show placeholder then rewrite via stats section
        // Simpler: just let renderStatsSection print counts.
    }

    private function renderStatsSection(array $stats): void
    {
        $byType = $stats['by_type'] ?? [];
        $graphStats = $stats['graph']['by_type'] ?? [];

        $this->output->writeln('  <fg=#8b5cf6>Analyzing application behavior...</>');
        $this->output->writeln('');

        // Emulate progress bar quickly — VIOLET
        $bar = new ProgressBar($this->output, 100);
        $bar->setBarCharacter('<fg=#8b5cf6>█</>');
        $bar->setEmptyBarCharacter('<fg=gray>░</>');
        $bar->setProgressCharacter('<fg=#a78bfa>█</>');
        $bar->setFormat('  <fg=#8b5cf6>%bar%</>  <fg=#a78bfa>%percent:3s%%</>');
        $bar->start();
        for ($i=0; $i<=100; $i+=20) {
            usleep(40000);
            $bar->setProgress($i);
        }
        $bar->finish();
        $this->output->writeln('');
        $this->output->writeln('');

        // Stats table-like lines mimicking flow.md
        $routes = $stats['routes'] ?? 0;
        $controllers = $byType['Controller'] ?? ($graphStats['Controller'] ?? 0);
        $models = $byType['Model'] ?? ($graphStats['Model'] ?? 0);
        $services = $byType['Service'] ?? ($graphStats['Service'] ?? 0);
        $jobs = $byType['Job'] ?? ($graphStats['Job'] ?? 0);
        $events = $byType['Event'] ?? ($graphStats['Event'] ?? 0);

        $pad = fn($label, $count) => sprintf('  <fg=gray>%s</> %s <fg=gray>%s</>', $label, str_repeat('.', max(1, 22 - strlen($label))), $count);

        $this->output->writeln($pad('Routes', $routes));
        $this->output->writeln($pad('Controllers', $controllers));
        $this->output->writeln($pad('Models', $models));
        $this->output->writeln($pad('Services', $services));
        $this->output->writeln($pad('Jobs', $jobs));
        $this->output->writeln($pad('Events', $events));
        $this->output->writeln('');
    }

    private function renderFindingsSummary(array $findings): void
    {
        $counts = ['critical'=>0,'high'=>0,'medium'=>0,'low'=>0,'info'=>0];
        foreach ($findings as $f) {
            $counts[$f->severity->value] = ($counts[$f->severity->value] ?? 0) + 1;
        }

        $this->output->writeln('  <fg=white;options=bold>Findings</>');
        $this->output->writeln('  <fg=gray>' . str_repeat('─', 46) . '</>');

        $label = fn($sev, $color, $count) => sprintf('  <fg=%s;options=bold>%-8s</> <fg=white>%d</>', $color, strtoupper($sev), $count);

        $this->output->writeln($label('CRITICAL', '#ef4444', $counts['critical']));
        $this->output->writeln($label('HIGH', '#f59e0b', $counts['high']));
        $this->output->writeln($label('MEDIUM', '#06b6d4', $counts['medium']));
        $this->output->writeln($label('LOW', '#8b5cf6', $counts['low']));
        if ($counts['info'] > 0) $this->output->writeln($label('INFO', 'gray', $counts['info']));

        $this->output->writeln('');
        if (count($findings) > 0) {
            $this->output->writeln('  <fg=gray>Run:</>');
            $this->output->writeln('    <fg=cyan>php artisan rat:show</>           <fg=gray>— list all findings</>');
            $this->output->writeln('    <fg=cyan>php artisan rat:show RAT-001</>   <fg=gray>— investigate one</>');
            $this->output->writeln('    <fg=cyan>php artisan rat:flow "POST /api/import"</> <fg=gray>— trace a route</>');
        } else {
            $this->output->writeln('  <fg=green>✓ No findings — application looks clean (within RAT’s scope).</>');
            $this->output->writeln('  <fg=gray>  Tip: `rat:why <Controller>` and `rat:impact <Model>` for exploration.</>');
        }
        $this->output->writeln('');
    }

    private function renderHints(): void
    {
        $this->output->writeln('  <fg=gray>Flags: --format=json | --format=ndjson | --ci | --fail-on=high | --no-image | --all | --path=app,routes</>');
        $this->output->writeln('  <fg=gray>Scope: by default whole codebase (excl. vendor/storage/public/.git) — use --all or choose interactively</>');
        $this->output->writeln('');
    }

    private function handleCi(array $findings, ?string $overrideFailOn): int
    {
        $failOn = $overrideFailOn ?? $this->loadRatConfig()['fail_on'] ?? 'high';
        // If override was project_root path (mistake above), fallback
        if (is_string($failOn) && str_contains($failOn, '/')) {
            $failOn = $this->loadRatConfig()['fail_on'] ?? 'high';
        }
        $threshold = Severity::tryFrom(strtolower((string)$failOn)) ?? Severity::HIGH;

        $counts = ['critical'=>0,'high'=>0,'medium'=>0,'low'=>0,'info'=>0];
        foreach ($findings as $f) {
            $counts[$f->severity->value]++;
        }

        $this->output->writeln('');
        $this->output->writeln('  <fg=white;options=bold>RAT CI CHECK</>');
        $this->output->writeln('  <fg=gray>' . str_repeat('─', 30) . '</>');
        $this->output->writeln(sprintf('  Critical: <fg=red>%d</>', $counts['critical']));
        $this->output->writeln(sprintf('  High:     <fg=yellow>%d</>', $counts['high']));
        $this->output->writeln(sprintf('  Medium:   <fg=cyan>%d</>', $counts['medium']));
        $this->output->writeln('');

        // Check baseline
        $baselinePath = $this->baselinePath();
        $baseline = null;
        if (file_exists($baselinePath)) {
            $baseline = json_decode((string) file_get_contents($baselinePath), true);
        }

        $newFindings = $findings;
        if (is_array($baseline) && isset($baseline['findings'])) {
            $baselineIds = array_map(fn($f)=> $f['id'] ?? $f, $baseline['findings']); // if baseline stores objects
            // Simpler: compare by hash of title+file+sink
            $baselineHashes = [];
            foreach ($baseline['findings'] as $bf) {
                $hash = md5(($bf['title'] ?? '') . ($bf['file'] ?? '') . ($bf['sink'] ?? ''));
                $baselineHashes[$hash] = true;
            }
            $newFindings = array_filter($findings, function($f) use ($baselineHashes) {
                $h = md5($f->title . $f->file . $f->sink);
                return ! isset($baselineHashes[$h]);
            });
        }

        $violations = array_filter($newFindings, fn($f) => $f->severity->meetsThreshold($threshold));

        if (count($violations) > 0) {
            $this->output->writeln('  <fg=red;options=bold>✗ Security threshold exceeded.</>');
            $this->output->writeln(sprintf('  <fg=gray>Threshold: %s | Violations: %d%s</>', strtoupper($threshold->value), count($violations), $baseline ? ' (new vs baseline)' : ''));
            $this->output->writeln('  <fg=gray>Exit code: 1</>');
            return 1;
        }

        $this->output->writeln('  <fg=green;options=bold>✓ CI check passed.</>');
        if ($baseline) $this->output->writeln('  <fg=gray>Only new findings counted (baseline active).</>');
        $this->output->writeln('  <fg=gray>Exit code: 0</>');
        return 0;
    }

    private function persistLastScan(array $findings, array $stats, $graph): void
    {
        $dir = getcwd() . '/storage/rat';
        if (! is_dir($dir)) @mkdir($dir, 0755, true);
        $payload = [
            'generated_at' => date('c'),
            'stats' => $stats,
            'findings' => array_map(fn($f)=> $f->toArray(), $findings),
            'graph' => $graph->toArray(),
        ];
        @file_put_contents($dir . '/last.json', json_encode($payload, JSON_PRETTY_PRINT|JSON_UNESCAPED_SLASHES));
        // Also .rat.last.json in cwd for non-laravel projects
        @file_put_contents(getcwd() . '/.rat.last.json', json_encode($payload, JSON_PRETTY_PRINT|JSON_UNESCAPED_SLASHES));
    }

    private function loadRatConfig(): array
    {
        $path = getcwd() . '/config/rat.php';
        if (file_exists($path)) {
            try {
                $cfg = require $path;
                if (is_array($cfg)) return $cfg;
            } catch (\Throwable $e) {}
        }
        return [];
    }

    private function baselinePath(): string
    {
        $cfg = $this->loadRatConfig();
        $p = $cfg['baseline'] ?? (getcwd() . '/.rat.baseline.json');
        // base_path() not available in standalone; resolve
        if (str_starts_with($p, '/') || preg_match('/^[A-Z]:\\\\/i', $p)) return $p;
        return getcwd() . '/' . ltrim($p, '/');
    }

    private function resolveScanScope(array $cfg, bool $all, ?string $pathOpt, bool $isJson, bool $security = false, bool $deep = false): array
    {
        // Explicit flags win — deep > security > all — whole codebase + advanced analysis
        if ($deep) {
            $cfg['paths'] = ['.'];
            $cfg['analysis'] = ['routes'=>true,'authorization'=>true,'data_flow'=>true,'hidden_behavior'=>true,'impact'=>true,'security'=>true,'deep'=>true];
            $cfg['depth'] = 12;
            return $cfg;
        }
        if ($security) {
            $cfg['paths'] = ['.'];
            $cfg['analysis'] = ['routes'=>true,'authorization'=>true,'data_flow'=>true,'hidden_behavior'=>true,'impact'=>true,'security'=>true];
            return $cfg;
        }
        if ($all) {
            $cfg['paths'] = ['.'];
            return $cfg;
        }
        if ($pathOpt) {
            $cfg['paths'] = array_values(array_filter(array_map('trim', explode(',', $pathOpt))));
            return $cfg;
        }
        // No explicit scope → interactive choice when TTY (user can pick whole vs lot vs config vs custom vs security)
        if (! $isJson && $this->input->isInteractive() && ! $this->option('ci') && function_exists('posix_isatty') && @posix_isatty(STDIN)) {
            $hasConfigFile = file_exists(getcwd() . '/config/rat.php');
            $this->output->writeln('  <fg=gray>Scope selection (vendor/storage/public/.git always excluded):</>');
            $options = [
                'all' => 'Whole codebase (all PHP — recommended, respects exclude)',
                'laravel' => 'Laravel lot (monolith + modular monolith + microservices monorepo)',
                'security' => 'Security scan — Vulnerability & attack-surface analysis',
                'deep' => 'Deep security scan — Advanced data-flow + behavior analysis',
            ];
            if ($hasConfigFile && ! empty($cfg['paths'])) {
                $options['config'] = 'Use config/rat.php (' . implode(', ', $cfg['paths']) . ')';
            }
            $options['custom'] = 'Custom — you type paths';
            $default = $hasConfigFile && isset($options['config']) ? 'config' : 'all';
            $choice = $this->choice('  What should RAT scan?', $options, $default);
            if ($choice === 'all') {
                $cfg['paths'] = ['.'];
            } elseif ($choice === 'laravel') {
                $cfg['paths'] = ['app','routes','config','database','resources','Modules','modules','Domain','domain','Domains','src','packages','services','Services','apps','microservices','tests'];
            } elseif ($choice === 'security') {
                $cfg['paths'] = ['.'];
                $cfg['analysis'] = ['routes'=>true,'authorization'=>true,'data_flow'=>true,'hidden_behavior'=>true,'impact'=>true,'security'=>true];
                $this->output->writeln('  <fg=#8b5cf6;options=bold>🐀 RAT // SECURITY SCAN</>');
                $this->output->writeln('  <fg=gray>[✓] injection, SQLi, command, XSS, traversal, SSRF, deserialization, upload, auth, IDOR, mass assignment, open redirect, secrets, debug, etc. — see SECURITYSCAN.md</>');
            } elseif ($choice === 'deep') {
                $cfg['paths'] = ['.'];
                $cfg['analysis'] = ['routes'=>true,'authorization'=>true,'data_flow'=>true,'hidden_behavior'=>true,'impact'=>true,'security'=>true,'deep'=>true];
                $cfg['depth'] = 12;
                $this->output->writeln('  <fg=#8b5cf6;options=bold>🐀 RAT // DEEP SECURITY SCAN</>');
                $this->output->writeln('  <fg=#a78bfa>Advanced data-flow + behavior analysis — whole codebase, vendor excluded</>');
                $this->output->writeln('  <fg=gray>[✓] Injection risks | [✓] SQL injection | [✓] Command injection | [✓] XSS | [✓] Path traversal | [✓] SSRF | [✓] Deserialization | [✓] File upload | [✓] Auth | [✓] IDOR | [✓] Mass assignment | [✓] Open redirects | [✓] Sensitive data | [✓] Hardcoded secrets | [✓] Debug mode | [✓] Dynamic execution | [✓] Rate-limit | [✓] Resource exhaustion | [✓] Queue/job | [✓] Webhook | [✓] CORS | [✓] Insecure config — see SECURITYSCAN.md</>');
            } elseif ($choice === 'config') {
            } elseif ($choice === 'config') {
                // keep cfg as is
            } elseif ($choice === 'custom') {
                $custom = $this->ask('  Enter comma-separated paths (e.g. app,Modules,packages)', 'app,routes');
                $cfg['paths'] = array_values(array_filter(array_map('trim', explode(',', $custom))));
                if (empty($cfg['paths'])) $cfg['paths'] = ['.'];
            }
            $this->output->writeln(sprintf('  <fg=gray>Scanning:</> <fg=white>%s</>', implode(', ', $cfg['paths'])));
            $this->output->writeln('');
        } else {
            // Non-interactive default: whole codebase (if no paths) or config
            if (empty($cfg['paths'])) $cfg['paths'] = ['.'];
        }
        return $cfg;
    }

    private function shouldDelegateToPython(): bool
    {
        // Check if python3 and rat.py are available — prefer Python precise scanner
        // Allow opt-out via RAT_USE_PHP=1
        if (getenv('RAT_USE_PHP') === '1' || getenv('RAT_PYTHON') === '0') return false;
        $py = $this->findPython();
        $ratPy = $this->findRatPy();
        return $py !== null && $ratPy !== null;
    }

    private function findPython(): ?string
    {
        $candidates = ['python3', 'python', 'py'];
        foreach ($candidates as $bin) {
            $out = @shell_exec(escapeshellarg($bin) . ' --version 2>&1');
            if ($out && str_contains(strtolower($out), 'python')) {
                return $bin;
            }
        }
        // also try command -v
        $which = trim((string) @shell_exec('command -v python3 2>&1'));
        if ($which && file_exists($which)) return 'python3';
        $which = trim((string) @shell_exec('which python3 2>&1'));
        if ($which && file_exists($which)) return 'python3';
        return null;
    }

    private function findRatPy(): ?string
    {
        $candidates = [];
        // Laravel app vendor path
        $candidates[] = getcwd() . '/vendor/squeak/rat/rat.py';
        // Package dev root (when running from package itself)
        $candidates[] = dirname(__DIR__, 3) . '/rat.py';
        // Fallback absolute package path
        $candidates[] = '/Applications/XAMPP/xamppfiles/htdocs/package-contribution/rat/rat.py';
        // Also check relative to project root
        $candidates[] = getcwd() . '/rat.py';
        foreach ($candidates as $p) {
            if (file_exists($p)) return $p;
        }
        return null;
    }

    private function delegateToPython(): ?int
    {
        $py = $this->findPython();
        $ratPy = $this->findRatPy();
        if (! $py || ! $ratPy) return null;

        // Build args for python: translate artisan options to python rat.py flags
        $args = [];
        $map = [
            'format' => '--format',
            'fail-on' => '--fail-on',
            'path' => '--path',
        ];
        foreach ($map as $opt => $flag) {
            $val = $this->option($opt);
            if ($val !== null && $val !== '') {
                $args[] = $flag . '=' . escapeshellarg((string) $val);
            }
        }
        // Boolean flags
        foreach (['ci','json','no-image','compact','all','security','deep'] as $b) {
            try {
                if ((bool) $this->option($b)) {
                    $args[] = '--' . $b;
                }
            } catch (\Throwable $e) {}
        }
        // Laravel lot: php has no --laravel flag, but python supports it via --laravel
        // If user selected laravel via interactive chooser, we haven't yet shown chooser — so we delegate without args and let python show its chooser
        // For non-interactive with explicit flags, we already have args; for interactive without flags, we just call python with no scope flags so it shows its own chooser

        $cmd = escapeshellarg($py) . ' ' . escapeshellarg($ratPy);
        if (! empty($args)) {
            $cmd .= ' ' . implode(' ', $args);
        }
        // Preserve color: if artisan output is decorated, pass ANSI
        // Run interactively, forwarding STDIN/STDOUT/STDERR
        $descriptors = [
            0 => STDIN,
            1 => STDOUT,
            2 => STDERR,
        ];
        // Use proc_open to forward interactivity
        $proc = @proc_open($cmd, $descriptors, $pipes, getcwd());
        if (is_resource($proc)) {
            $exit = proc_close($proc);
            return $exit;
        }
        // Fallback passthru
        @passthru($cmd, $exit);
        return $exit;
    }

    private function delegateToPythonWithCfg(array $cfg, string $format, bool $ci, ?string $failOn, bool $noImage, bool $compact): ?int
    {
        $py = $this->findPython();
        $ratPy = $this->findRatPy();
        if (! $py || ! $ratPy) return null;

        $args = [];
        // Translate resolved cfg to python flags
        $analysis = $cfg['analysis'] ?? [];
        $paths = $cfg['paths'] ?? ['.'];
        // Map cfg to flags: deep > security > all > laravel > custom
        if (! empty($analysis['deep'])) {
            $args[] = '--deep';
        } elseif (! empty($analysis['security'])) {
            $args[] = '--security';
        } elseif ($paths === ['.']) {
            $args[] = '--all';
        } elseif ($paths === ['app','routes','config','database','resources','Modules','modules','Domain','domain','Domains','src','packages','services','Services','apps','microservices','tests']) {
            $args[] = '--laravel';
        } else {
            $args[] = '--path=' . escapeshellarg(implode(',', $paths));
        }
        // Forward other options
        if ($format !== 'table') $args[] = '--format=' . escapeshellarg($format);
        if ($ci) $args[] = '--ci';
        if ($failOn) $args[] = '--fail-on=' . escapeshellarg($failOn);
        if ($noImage) $args[] = '--no-image';
        if ($compact) $args[] = '--compact';
        // json alias
        try { if ((bool) $this->option('json')) $args[] = '--json'; } catch (\Throwable $e) {}

        $cmd = escapeshellarg($py) . ' ' . escapeshellarg($ratPy) . ' ' . implode(' ', $args);
        $descriptors = [0 => STDIN, 1 => STDOUT, 2 => STDERR];
        $proc = @proc_open($cmd, $descriptors, $pipes, getcwd());
        if (is_resource($proc)) {
            $exit = proc_close($proc);
            return $exit;
        }
        @passthru($cmd, $exit);
        return $exit;
    }
}
