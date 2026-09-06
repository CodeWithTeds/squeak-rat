<?php

namespace Rat\Console\Commands;

use Illuminate\Console\Command;
use Rat\Support\RatBanner;

class RatShowCommand extends Command
{
    protected $signature = 'rat:show
                            {id? : Finding ID e.g. RAT-001 or severity filter (critical|high|medium|low)}
                            {--format=table : Output format (table|json)}
                            {--no-image : Disable image}';

    protected $description = 'Show findings or investigate a specific RAT finding.';

    public function handle(): int
    {
        $id = $this->argument('id');
        $format = $this->option('format') ?? 'table';
        $noImage = (bool) $this->option('no-image');

        $payload = $this->loadLastScan();
        if (! $payload) {
            $this->warn(' No previous scan found. Run `php artisan rat:scan` or `php artisan rat` first.');
            $this->line(' <fg=gray>Tip: scanning now with lightweight in-memory fallback...</>');
            // Trigger on-demand analysis instead of failing
            $analyzer = new \Rat\Engine\Analyzer(getcwd(), $this->loadConfig());
            $payload = $analyzer->analyze();
            // Normalize shape: analyzer returns ['graph'=>..., 'findings'=> Finding[], 'stats'=>...]
            // Convert findings to array shape like persisted json
            if (isset($payload['findings']) && is_object($payload['findings'][0] ?? null)) {
                $payload['findings'] = array_map(fn($f)=> $f->toArray(), $payload['findings']);
                $payload['graph'] = $payload['graph']->toArray();
            }
        }

        $findings = $payload['findings'] ?? [];
        $stats = $payload['stats'] ?? [];

        if ($format === 'json') {
            if ($id) {
                $found = $this->findFinding($findings, (string)$id);
                $out = $found ? json_encode($found, JSON_PRETTY_PRINT|JSON_UNESCAPED_SLASHES) : json_encode(['error'=>'not found','id'=>$id]);
                $this->output->writeln($out);
                return $found ? 0 : 1;
            }
            $this->output->writeln(json_encode(['findings'=>$findings,'stats'=>$stats], JSON_PRETTY_PRINT|JSON_UNESCAPED_SLASHES));
            return 0;
        }

        if (! $id) {
            return $this->showList($findings, $stats, ! $noImage);
        }

        // If id is severity filter
        $lower = strtolower((string)$id);
        if (in_array($lower, ['critical','high','medium','low','info'], true)) {
            return $this->showList(array_values(array_filter($findings, fn($f)=> strtolower($f['severity'] ?? '') === $lower)), $stats, ! $noImage, $lower);
        }

        return $this->showOne($findings, (string)$id, ! $noImage);
    }

    private function showList(array $findings, array $stats, bool $withImage, ?string $filter = null): int
    {
        if ($withImage) RatBanner::render($this->output, true, false);
        else $this->output->writeln('<fg=red;options=bold>🐀 RAT</> <fg=gray>Findings Explorer</>');

        $this->output->writeln('');

        if ($filter) {
            $this->output->writeln(sprintf('  <fg=gray>Filter:</> <fg=white;options=bold>%s</>  <fg=gray>(%d findings)</>', strtoupper($filter), count($findings)));
        } else {
            $counts = ['critical'=>0,'high'=>0,'medium'=>0,'low'=>0,'info'=>0];
            foreach ($findings as $f) $counts[strtolower($f['severity'] ?? 'info')]++;

            $this->output->writeln(sprintf('  <fg=gray>All findings:</> <fg=white>%d</>  <fg=gray>|</> <fg=red>CRITICAL %d</> <fg=yellow>HIGH %d</> <fg=cyan>MEDIUM %d</> <fg=blue>LOW %d</>', count($findings), $counts['critical'], $counts['high'], $counts['medium'], $counts['low']));
        }

        $this->output->writeln('  <fg=gray>' . str_repeat('─', 72) . '</>');
        $this->output->writeln('');

        if (empty($findings)) {
            $this->output->writeln('  <fg=green>✓ No findings for this filter.</>');
            return 0;
        }

        // Filters UI hint
        $this->output->writeln('  <fg=gray>[All] [Critical] [High] [Medium] [Low]  —  try: </><fg=cyan>rat:show high</>');
        $this->output->writeln('');

        foreach ($findings as $f) {
            $sev = strtoupper($f['severity'] ?? 'INFO');
            $color = match(strtolower($sev)){'critical'=>'red','high'=>'yellow','medium'=>'cyan','low'=>'blue', default=>'gray'};
            $id = $f['id'] ?? '?';
            $title = $f['title'] ?? $f['description'] ?? '—';
            $entry = $f['entry'] ?? '';
            $conf = strtoupper($f['confidence'] ?? 'MEDIUM');
            $file = $f['file'] ?? '';
            $line = $f['line'] ?? '';

            $this->output->writeln(sprintf('  <fg=%s;options=bold>%-8s</> <fg=white;options=bold>%s</>', $color, $sev, $id));
            $this->output->writeln(sprintf('  <fg=white>%s</>', $title));
            if ($entry) $this->output->writeln(sprintf('  <fg=gray>%s</>', $entry));
            if ($file) $this->output->writeln(sprintf('  <fg=gray>%s%s</>  <fg=gray>Confidence:</> <fg=white>%s</>', $file, $line ? ":$line" : '', $conf));
            $this->output->writeln(sprintf('  <fg=gray>→</> <fg=cyan>php artisan rat:show %s</>', $id));
            $this->output->writeln('');
        }

        $this->output->writeln('  <fg=gray>Tip: click-equivalent in terminal — copy the ID and run rat:show <ID></>');
        return 0;
    }

    private function showOne(array $findings, string $id, bool $withImage): int
    {
        $normalized = strtoupper(trim($id));
        // Allow R001 -> RAT-001
        if (preg_match('/^R0*(\d+)$/', $normalized, $m)) $normalized = sprintf('RAT-%03d', (int)$m[1]);
        if (! str_starts_with($normalized, 'RAT-')) {
            // maybe user passed RAT-001 exact
            $normalized = strtoupper($id);
        }

        $found = $this->findFinding($findings, $normalized);
        if (! $found) {
            // Try case-insensitive raw id search
            $found = $this->findFinding($findings, $id);
        }
        if (! $found) {
            $this->error(" Finding $id not found. Run `php artisan rat:show` to list all.");
            return 1;
        }

        if ($withImage) RatBanner::render($this->output, true, false);

        $sev = strtoupper($found['severity'] ?? 'INFO');
        $color = match(strtolower($sev)){'critical'=>'red','high'=>'yellow','medium'=>'cyan','low'=>'blue', default=>'gray'};
        $conf = strtoupper($found['confidence'] ?? 'HIGH');
        $entry = $found['entry'] ?? '—';
        $source = $found['source'] ?? '—';
        $sink = $found['sink'] ?? '—';
        $why = $found['why'] ?? $found['description'] ?? '';
        $flow = $found['flow'] ?? [];
        $recs = $found['recommendations'] ?? [];
        $file = $found['file'] ?? '';
        $line = $found['line'] ?? '';

        $this->output->writeln('');
        $this->output->writeln(sprintf('  <fg=%s;options=bold>🐀 %s</>  <fg=%s;options=bold>%s</>', $color, $found['id'] ?? $id, $color, $sev));
        $this->output->writeln('');
        $this->output->writeln(sprintf('  <fg=white>%s</>', $found['title'] ?? ''));
        if (! empty($found['description']) && $found['description'] !== $found['title']) {
            $this->output->writeln(sprintf('  <fg=gray>%s</>', $found['description']));
        }
        $this->output->writeln('');

        $this->output->writeln('  <fg=white;options=bold>ENTRY POINT</>');
        $this->output->writeln(sprintf('  <fg=cyan>%s</>', $entry));
        $this->output->writeln('');

        $this->output->writeln('  <fg=white;options=bold>SOURCE</>');
        $this->output->writeln(sprintf('  <fg=yellow>%s</>', $source));
        $this->output->writeln('');

        $this->output->writeln('  <fg=white;options=bold>FLOW</>');
        $this->output->writeln('');
        // Beautiful vertical flow
        $this->output->writeln('  <fg=gray>HTTP Request</>');
        $this->output->writeln('  <fg=gray>    │</>');
        foreach ($flow as $idx => $node) {
            $isLast = $idx === count($flow) - 1;
            $icon = $isLast ? '  ' : '  ';
            $boxColor = $isLast ? 'red' : 'white';
            // Box
            $this->output->writeln(sprintf('  <fg=gray>    ▼</>'));
            $this->output->writeln(sprintf('  <fg=%s>┌───────────────────┐</>', $boxColor));
            $this->output->writeln(sprintf('  <fg=%s>│ %-17s │</>', $boxColor, substr($node,0,17)));
            $this->output->writeln(sprintf('  <fg=%s>└────────┬──────────┘</>', $boxColor));
            if (! $isLast) $this->output->writeln('  <fg=gray>         │</>');
        }
        if (! empty($flow)) {
            $this->output->writeln('  <fg=gray>         ▼</>');
            $this->output->writeln('  <fg=gray>    Filesystem / Sink</>');
        }
        $this->output->writeln('');

        $this->output->writeln('  <fg=white;options=bold>WHY RAT FLAGGED THIS</>');
        $this->output->writeln('');
        $wrapped = wordwrap($why ?: 'User-controlled input reaches a sensitive sink without a clearly identified security boundary.', 68, "\n  ");
        $this->output->writeln('  <fg=gray>' . $wrapped . '</>');
        $this->output->writeln('');

        $this->output->writeln('  <fg=white;options=bold>CONFIDENCE</>');
        $bar = match($conf){'HIGH'=>'██████████████████░░','MEDIUM'=>'████████████░░░░░░░░','LOW'=>'██████░░░░░░░░░░░░░░', default=>'████████░░░░░░░░░░░░'};
        $this->output->writeln(sprintf('  <fg=cyan>%s</>  <fg=white>%s</>', $bar, $conf));
        $this->output->writeln('');

        if (! empty($recs)) {
            $this->output->writeln('  <fg=white;options=bold>RECOMMENDATION</>');
            $this->output->writeln('');
            $this->output->writeln('  <fg=gray>Review whether:</>');
            foreach ($recs as $r) {
                $this->output->writeln(sprintf('    <fg=gray>•</> <fg=white>%s</>', $r));
            }
            $this->output->writeln('');
        }

        if ($file) {
            $this->output->writeln('  <fg=white;options=bold>LOCATION</>');
            $this->output->writeln(sprintf('  <fg=gray>%s%s</>', $file, $line ? ":$line" : ''));
            $this->output->writeln('');
            // Try to show code snippet if file exists
            $abs = getcwd() . '/' . $file;
            if (file_exists($abs)) {
                $lines = @file($abs) ?: [];
                $ln = max(1, (int)$line - 2);
                $this->output->writeln('  <fg=gray>Code:</>');
                for ($i=$ln; $i < min($ln+7, count($lines)+1); $i++) {
                    $code = rtrim($lines[$i-1] ?? '');
                    $marker = $i === (int)$line ? '<fg=red>›</>' : ' ';
                    $num = str_pad((string)$i, 3, ' ', STR_PAD_LEFT);
                    $this->output->writeln(sprintf('  %s <fg=gray>%s</> %s', $marker, $num, htmlspecialchars($code)));
                }
                $this->output->writeln('');
            }
        }

        $this->output->writeln('  <fg=gray>Investigate further:</> <fg=cyan>rat:why ' . strtok($entry,' ') . '</>  <fg=gray>|</> <fg=cyan>rat:flow "' . $entry . '"</>  <fg=gray>|</> <fg=cyan>rat:impact ' . ($file ?: $entry) . '</>');
        $this->output->writeln('');

        return 0;
    }

    private function findFinding(array $findings, string $id): ?array
    {
        $needle = strtoupper(trim($id));
        foreach ($findings as $f) {
            if (strtoupper((string)($f['id'] ?? '')) === $needle) return $f;
        }
        // loose search
        foreach ($findings as $f) {
            if (strcasecmp((string)($f['id'] ?? ''), $id) === 0) return $f;
        }
        return null;
    }

    private function loadLastScan(): ?array
    {
        $candidates = [
            getcwd() . '/storage/rat/last.json',
            getcwd() . '/.rat.last.json',
            getcwd() . '/.rat/last.json',
        ];
        foreach ($candidates as $p) {
            if (file_exists($p)) {
                $data = json_decode((string) file_get_contents($p), true);
                if (is_array($data) && isset($data['findings'])) return $data;
            }
        }
        return null;
    }

    private function loadConfig(): array
    {
        $path = getcwd() . '/config/rat.php';
        if (file_exists($path)) {
            try { $cfg = require $path; if (is_array($cfg)) return $cfg; } catch (\Throwable $e) {}
        }
        return [];
    }
}
