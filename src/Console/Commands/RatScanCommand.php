<?php

namespace Rat\Console\Commands;

use Illuminate\Console\Command;
use Rat\Support\RatBanner;
use Rat\Engine\Analyzer;
use Rat\Engine\Reporters\JsonReporter;

class RatScanCommand extends Command
{
    protected $signature = 'rat:scan
                            {--format=table : Output format (table|json|ndjson)}
                            {--ci : CI mode}
                            {--fail-on= : Override fail_on}
                            {--no-image : Disable image}
                            {--all : Scan whole codebase (all PHP excluding vendor/storage)}
                            {--path= : Comma-separated extra paths to scan}
                            {--security : Security scan — vulnerability & attack-surface analysis}
                            {--deep : Deep security scan — Advanced data-flow + behavior analysis}';

    protected $description = 'Run RAT deep scan and persist results for investigation.';

    public function handle(): int
    {
        $format = $this->option('format') ?? 'table';
        if ($format === 'json' || $format === 'ndjson') {
            // delegate json handling without banner fluff
        } else {
            RatBanner::render($this->output, ! (bool) $this->option('no-image'));
            $this->info(' RAT scan starting...');
        }

        $all = (bool) $this->option('all');
        $security = (bool) $this->option('security');
        $deep = (bool) $this->option('deep');
        $isJson = in_array($format, ['json','ndjson'], true);
        $pathOpt = $this->option('path');
        $extraPaths = $pathOpt ? explode(',', (string) $pathOpt) : [];
        $cfg = $this->loadConfig();
        // Resolve scope: --deep / --security / --all / --path, else interactive choice
        if ($deep) {
            $cfg['paths'] = ['.'];
            $cfg['analysis'] = ['routes'=>true,'authorization'=>true,'data_flow'=>true,'hidden_behavior'=>true,'impact'=>true,'security'=>true,'deep'=>true];
            $cfg['depth'] = 12;
            if (! $isJson) {
                $this->output->writeln('  <fg=#8b5cf6;options=bold>🐀 RAT // DEEP SECURITY SCAN</>');
                $this->output->writeln('  <fg=#a78bfa>Advanced data-flow + behavior analysis — whole codebase, vendor excluded</>');
            }
        } elseif ($security) {
            $cfg['paths'] = ['.'];
            $cfg['analysis'] = ['routes'=>true,'authorization'=>true,'data_flow'=>true,'hidden_behavior'=>true,'impact'=>true,'security'=>true];
            if (! $isJson) {
                $this->output->writeln('  <fg=#8b5cf6;options=bold>🐀 RAT // SECURITY SCAN</>');
                $this->output->writeln('  <fg=gray>Vulnerability & attack-surface — whole codebase, vendor excluded</>');
            }
        } elseif ($all) {
            $cfg['paths'] = ['.'];
        } elseif (! empty($extraPaths)) {
            // --path replaces if explicit, otherwise merges; here we treat as replace for clarity
            $cfg['paths'] = array_values(array_filter(array_map('trim', $extraPaths)));
        } elseif (! $isJson && $this->input->isInteractive() && ! $this->option('ci') && function_exists('posix_isatty') && @posix_isatty(STDIN)) {
            $hasConfigFile = file_exists(getcwd().'/config/rat.php');
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
            if ($choice === 'all') $cfg['paths'] = ['.'];
            elseif ($choice === 'laravel') $cfg['paths'] = ['app','routes','config','database','resources','Modules','modules','Domain','domain','Domains','src','packages','services','Services','apps','microservices','tests'];
            elseif ($choice === 'security') {
                $cfg['paths'] = ['.'];
                $cfg['analysis'] = ['routes'=>true,'authorization'=>true,'data_flow'=>true,'hidden_behavior'=>true,'impact'=>true,'security'=>true];
                $this->output->writeln('  <fg=#8b5cf6;options=bold>🐀 RAT // SECURITY SCAN</>');
            } elseif ($choice === 'deep') {
                $cfg['paths'] = ['.'];
                $cfg['analysis'] = ['routes'=>true,'authorization'=>true,'data_flow'=>true,'hidden_behavior'=>true,'impact'=>true,'security'=>true,'deep'=>true];
                $cfg['depth'] = 12;
                $this->output->writeln('  <fg=#8b5cf6;options=bold>🐀 RAT // DEEP SECURITY SCAN</>');
                $this->output->writeln('  <fg=#a78bfa>Advanced data-flow + behavior analysis — displaying what they are vulnerable for</>');
            }
            elseif ($choice === 'config') { /* keep */ }
            elseif ($choice === 'custom') {
                $custom = $this->ask('  Enter comma-separated paths (e.g. app,Modules,packages)', 'app,routes');
                $cfg['paths'] = array_values(array_filter(array_map('trim', explode(',', $custom))));
                if (empty($cfg['paths'])) $cfg['paths'] = ['.'];
            }
            $this->output->writeln(sprintf('  <fg=gray>Scanning:</> <fg=white>%s</>', implode(', ', $cfg['paths'])));
        } else {
            if (empty($cfg['paths'])) $cfg['paths'] = ['.'];
        }

        // Prefer Python precise scanner if available — delegate after scope (keeps PHP chooser UI)
        if ($this->shouldDelegateToPython()) {
            $exit = $this->delegateToPythonWithCfg($cfg, $format);
            if ($exit !== null) return $exit;
        }

        $analyzer = new Analyzer(getcwd(), $cfg);
        $result = $analyzer->analyze();

        $findings = $result['findings'];
        $stats = $result['stats'];
        $graph = $result['graph'];

        // Persist
        $this->persist($findings, $stats, $graph);

        if ($format === 'json') {
            $reporter = new JsonReporter();
            $this->output->writeln($reporter->report($findings, $stats));
            return 0;
        }
        if ($format === 'ndjson') {
            $reporter = new JsonReporter();
            $this->output->writeln($reporter->ndjson($findings));
            return 0;
        }

        // Table summary via RatCommand logic duplication simplified
        $this->output->writeln('');
        $this->output->writeln('  <fg=white;options=bold>Scan complete.</>');
        $this->output->writeln(sprintf('  Routes: %d | Files: %d | Findings: %d', $stats['routes'] ?? 0, $stats['files'] ?? 0, count($findings)));
        $this->output->writeln('');

        $counts = ['critical'=>0,'high'=>0,'medium'=>0,'low'=>0,'info'=>0];
        foreach ($findings as $f) $counts[$f->severity->value]++;

        foreach (['critical','high','medium','low'] as $sev) {
            $color = match($sev){'critical'=>'red','high'=>'yellow','medium'=>'cyan','low'=>'blue'};
            $this->output->writeln(sprintf('  <fg=%s>%s</> %d', $color, strtoupper($sev), $counts[$sev]));
        }
        $this->output->writeln('');
        $this->output->writeln('  <fg=gray>Investigate:</> <fg=cyan>php artisan rat:show RAT-001</>  <fg=gray>|</> <fg=cyan>rat:flow "POST /api/import"</>');
        $this->output->writeln('  <fg=gray>Dashboard:</>  <fg=cyan>php artisan rat:ui</>            <fg=gray>(optional web UI)</>');

        if ($this->option('ci')) {
            $failOn = $this->option('fail-on') ?? $cfg['fail_on'] ?? 'high';
            $threshold = \Rat\Engine\Findings\Severity::tryFrom(strtolower($failOn)) ?? \Rat\Engine\Findings\Severity::HIGH;
            $violations = array_filter($findings, fn($f)=> $f->severity->meetsThreshold($threshold));
            if (count($violations) > 0) {
                $this->error(' CI threshold exceeded — failing.');
                return 1;
            }
            $this->info(' CI check passed.');
        }

        return 0;
    }

    private function persist(array $findings, array $stats, $graph): void
    {
        $payload = [
            'generated_at' => date('c'),
            'stats' => $stats,
            'findings' => array_map(fn($f)=> $f->toArray(), $findings),
            'graph' => $graph->toArray(),
        ];
        $dirs = [getcwd() . '/storage/rat', getcwd() . '/.rat'];
        foreach ($dirs as $d) { if (! is_dir($d)) @mkdir($d, 0755, true); }
        @file_put_contents(getcwd() . '/storage/rat/last.json', json_encode($payload, JSON_PRETTY_PRINT|JSON_UNESCAPED_SLASHES));
        @file_put_contents(getcwd() . '/.rat.last.json', json_encode($payload, JSON_PRETTY_PRINT|JSON_UNESCAPED_SLASHES));
        @file_put_contents(getcwd() . '/.rat/last.json', json_encode($payload, JSON_PRETTY_PRINT|JSON_UNESCAPED_SLASHES));
    }

    private function loadConfig(): array
    {
        $path = getcwd() . '/config/rat.php';
        if (file_exists($path)) {
            try { $cfg = require $path; if (is_array($cfg)) return $cfg; } catch (\Throwable $e) {}
        }
        return ['fail_on'=>'high','paths'=>['.'],'exclude'=>['vendor','storage','bootstrap/cache','node_modules','public','.git','.idea','.vscode'],'analysis'=>['routes'=>true,'authorization'=>true,'data_flow'=>true,'hidden_behavior'=>true,'impact'=>true]];
    }

    private function shouldDelegateToPython(): bool
    {
        if (getenv('RAT_USE_PHP') === '1' || getenv('RAT_PYTHON') === '0') return false;
        return $this->findPython() !== null && $this->findRatPy() !== null;
    }
    private function findPython(): ?string
    {
        foreach (['python3','python','py'] as $bin) {
            $out=@shell_exec(escapeshellarg($bin).' --version 2>&1');
            if ($out && str_contains(strtolower($out),'python')) return $bin;
        }
        return null;
    }
    private function findRatPy(): ?string
    {
        $cands=[getcwd().'/vendor/squeak/rat/rat.py', dirname(__DIR__,3).'/rat.py', '/Applications/XAMPP/xamppfiles/htdocs/package-contribution/rat/rat.py', getcwd().'/rat.py'];
        foreach ($cands as $p) if (file_exists($p)) return $p;
        return null;
    }
    private function delegateToPython(): ?int
    {
        $py=$this->findPython(); $ratPy=$this->findRatPy();
        if (!$py||!$ratPy) return null;
        $args=[];
        foreach (['format','fail-on','path'] as $opt) {
            $v=$this->option($opt);
            if ($v!==null&&$v!=='') $args[]='--'.$opt.'='.escapeshellarg((string)$v);
        }
        foreach (['ci','no-image','all','security','deep'] as $b) {
            try { if ((bool)$this->option($b)) $args[]='--'.$b; } catch (\Throwable $e) {}
        }
        $cmd=escapeshellarg($py).' '.escapeshellarg($ratPy).' '.implode(' ',$args);
        $d=[0=>STDIN,1=>STDOUT,2=>STDERR];
        $proc=@proc_open($cmd,$d,$pipes,getcwd());
        if (is_resource($proc)) return proc_close($proc);
        @passthru($cmd,$exit); return $exit;
    }

    private function delegateToPythonWithCfg(array $cfg, string $format): ?int
    {
        $py=$this->findPython(); $ratPy=$this->findRatPy();
        if (!$py||!$ratPy) return null;
        $args=[];
        $analysis=$cfg['analysis'] ?? [];
        $paths=$cfg['paths'] ?? ['.'];
        if (!empty($analysis['deep'])) $args[]='--deep';
        elseif (!empty($analysis['security'])) $args[]='--security';
        elseif ($paths===['.']) $args[]='--all';
        elseif ($paths===['app','routes','config','database','resources','Modules','modules','Domain','domain','Domains','src','packages','services','Services','apps','microservices','tests']) $args[]='--laravel';
        else $args[]='--path='.escapeshellarg(implode(',',$paths));
        if ($format!=='table') $args[]='--format='.escapeshellarg($format);
        try { if ((bool)$this->option('ci')) $args[]='--ci'; } catch (\Throwable $e) {}
        try { if ($this->option('fail-on')) $args[]='--fail-on='.escapeshellarg((string)$this->option('fail-on')); } catch (\Throwable $e) {}
        try { if ((bool)$this->option('no-image')) $args[]='--no-image'; } catch (\Throwable $e) {}
        $cmd=escapeshellarg($py).' '.escapeshellarg($ratPy).' '.implode(' ',$args);
        $d=[0=>STDIN,1=>STDOUT,2=>STDERR];
        $proc=@proc_open($cmd,$d,$pipes,getcwd());
        if (is_resource($proc)) return proc_close($proc);
        @passthru($cmd,$exit); return $exit;
    }
}
