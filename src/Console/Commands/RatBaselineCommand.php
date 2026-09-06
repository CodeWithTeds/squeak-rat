<?php

namespace Rat\Console\Commands;

use Illuminate\Console\Command;

class RatBaselineCommand extends Command
{
    protected $signature = 'rat:baseline
                            {--update : Update existing baseline}
                            {--path= : Baseline file path}';

    protected $description = 'Generate baseline so rat --ci only fails on new findings.';

    public function handle(): int
    {
        $path = $this->option('path') ?: $this->baselinePath();
        $update = (bool) $this->option('update');

        if (file_exists($path) && ! $update) {
            $this->warn(" Baseline already exists at $path — use --update to overwrite.");
            return 1;
        }

        $analyzer = new \Rat\Engine\Analyzer(getcwd(), $this->loadConfig());
        $res = $analyzer->analyze();
        $findings = $res['findings'];
        $stats = $res['stats'];

        $payload = [
            'generated_at' => date('c'),
            'tool' => 'RAT',
            'findings' => array_map(fn($f)=> $f->toArray(), $findings),
            'stats' => $stats,
        ];

        $dir = dirname($path);
        if (! is_dir($dir)) @mkdir($dir, 0755, true);
        file_put_contents($path, json_encode($payload, JSON_PRETTY_PRINT|JSON_UNESCAPED_SLASHES));

        $this->info(" Baseline written to $path (" . count($findings) . ' findings).');
        $this->line(' <fg=gray>Now `php artisan rat --ci` will only fail on new findings.</>');

        return 0;
    }

    private function baselinePath(): string
    {
        $cfg = $this->loadConfig();
        $p = $cfg['baseline'] ?? (getcwd() . '/.rat.baseline.json');
        if (str_starts_with($p, '/')) return $p;
        return getcwd() . '/' . ltrim($p, '/');
    }
    private function loadConfig(): array
    {
        $p=getcwd().'/config/rat.php'; if(file_exists($p)){try{$c=require $p; if(is_array($c)) return $c;}catch(\Throwable $e){}} return [];
    }
}
