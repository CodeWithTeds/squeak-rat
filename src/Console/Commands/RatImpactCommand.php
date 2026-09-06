<?php

namespace Rat\Console\Commands;

use Illuminate\Console\Command;
use Rat\Support\RatBanner;

class RatImpactCommand extends Command
{
    protected $signature = 'rat:impact
                            {target : File or class to analyze e.g. User.php or User}
                            {--format=table : table|json}
                            {--no-image}';

    protected $description = 'Show impact analysis for a file/class/model (dependents & blast radius).';

    public function handle(): int
    {
        $target = (string) $this->argument('target');
        $format = $this->option('format') ?? 'table';
        $noImage = (bool) $this->option('no-image');

        $payload = $this->loadLastScan();
        if (! $payload) {
            $this->warn(' No prior scan — running quick analysis...');
            $analyzer = new \Rat\Engine\Analyzer(getcwd(), $this->loadConfig());
            $res = $analyzer->analyze();
            $payload = ['graph'=>$res['graph']->toArray(), 'findings'=> array_map(fn($f)=>$f->toArray(), $res['findings']), 'stats'=>$res['stats']];
        }

        $graphData = $payload['graph'] ?? [];
        $graph = $this->hydrateGraph($graphData);

        $node = $this->findBestNode($graph, $target);
        if (! $node) {
            $base = basename($target, '.php');
            $node = $graph->findNodeByName($base) ?? $graph->findNodeByName($target);
        }

        // If target is a file path that didn't map to a node, try to find best match
        if (! $node) {
            $base = basename($target, '.php');
            // Search by file substring
            foreach ($graph->nodes() as $n) {
                if ($n->file && str_contains($n->file, $base)) { $node = $n; break; }
            }
        }

        if (! $node) {
            $this->error(" Target [$target] not found in application graph.");
            $this->line(' Try: <fg=cyan>rat:impact User</>  or  <fg=cyan>rat:impact app/Models/User.php</>');
            $this->output->writeln('');
            $this->output->writeln('  <fg=gray>Available models (sample):</>');
            foreach (array_slice($graph->nodesByType('Model'),0,10) as $n) $this->output->writeln('   <fg=cyan>'.$n->name.'</>');
            $this->output->writeln('  <fg=gray>Available controllers (sample):</>');
            foreach (array_slice($graph->nodesByType('Controller'),0,10) as $n) $this->output->writeln('   <fg=cyan>'.$n->name.'</>');
            return 1;
        }

        $impact = $graph->impactFor($node->id);

        if ($format === 'json') {
            $out = [
                'target' => $node->toArray(),
                'impact' => [
                    'direct' => array_map(fn($n)=>$n->toArray(), $impact['direct']),
                    'direct_by_type' => $impact['direct_by_type'],
                    'indirect' => array_map(fn($n)=>$n->toArray(), $impact['indirect']),
                    'indirect_by_type' => $impact['indirect_by_type'],
                    'score' => $impact['score'],
                ],
            ];
            $this->output->writeln(json_encode($out, JSON_PRETTY_PRINT|JSON_UNESCAPED_SLASHES));
            return 0;
        }

        if (! $noImage) RatBanner::render($this->output, true, false);

        $this->output->writeln('');
        $this->output->writeln('  <fg=white;options=bold>🐀 IMPACT ANALYSIS</>');
        $this->output->writeln('');
        $this->output->writeln(sprintf('  <fg=white;options=bold>%s</>  <fg=gray>%s</>  <fg=gray>%s</>', $node->name, $node->type, $node->file ?: ''));
        $this->output->writeln('');

        // Direct dependents
        $this->output->writeln('  <fg=white;options=bold>DIRECT DEPENDENTS</>');
        $this->output->writeln('  <fg=gray>' . str_repeat('─', 36) . '</>');

        $directByType = $impact['direct_by_type'] ?? [];
        $indirectByType = $impact['indirect_by_type'] ?? [];

        $typesOrder = ['Controller','Service','Job','Listener','Observer','Event','Middleware','Model','Route','Other'];
        $printedDirect = false;
        foreach ($typesOrder as $t) {
            $cnt = $directByType[$t] ?? 0;
            if ($cnt > 0) {
                $printedDirect = true;
                $label = str_pad($t . 's', 16);
                $this->output->writeln(sprintf('  <fg=gray>%s</> <fg=white;options=bold>%d</>', $label, $cnt));
            }
        }
        // Print any remaining types not in order
        foreach ($directByType as $t=>$cnt) {
            if (! in_array($t, $typesOrder, true)) {
                $this->output->writeln(sprintf('  <fg=gray>%-16s</> <fg=white;options=bold>%d</>', $t.'s', $cnt));
                $printedDirect = true;
            }
        }
        if (! $printedDirect) {
            $this->output->writeln('  <fg=gray>No direct dependents detected (orphan or low coupling).</>');
        }
        $this->output->writeln('');

        $this->output->writeln('  <fg=white;options=bold>INDIRECT</>');
        $this->output->writeln('  <fg=gray>' . str_repeat('─', 36) . '</>');
        $printedIndirect = false;
        foreach ($typesOrder as $t) {
            $cnt = $indirectByType[$t] ?? 0;
            if ($cnt > 0) {
                $printedIndirect = true;
                $label = str_pad($t . 's', 16);
                $this->output->writeln(sprintf('  <fg=gray>%s</> <fg=white>%d</>', $label, $cnt));
            }
        }
        foreach ($indirectByType as $t=>$cnt) {
            if (! in_array($t, $typesOrder, true)) {
                $this->output->writeln(sprintf('  <fg=gray>%-16s</> <fg=white>%d</>', $t.'s', $cnt));
                $printedIndirect = true;
            }
        }
        if (! $printedIndirect) {
            $this->output->writeln('  <fg=gray>No indirect impact beyond direct.</>');
        }
        $this->output->writeln('');

        $score = $impact['score'] ?? 'LOW';
        $color = match($score){'CRITICAL'=>'red','HIGH'=>'yellow','MEDIUM'=>'cyan','LOW'=>'blue', default=>'gray'};
        $bar = match($score){
            'CRITICAL'=>'████████████████████',
            'HIGH'=>'██████████████████░░',
            'MEDIUM'=>'████████████░░░░░░░░',
            'LOW'=>'██████░░░░░░░░░░░░░░',
            default=>'██░░░░░░░░░░░░░░░░░░',
        };
        $this->output->writeln('  <fg=white;options=bold>IMPACT SCORE</>');
        $this->output->writeln('');
        $this->output->writeln(sprintf('  <fg=%s>%s</>  <fg=%s;options=bold>%s</>', $color, $bar, $color, $score));
        $this->output->writeln('');

        // Direct list
        if (! empty($impact['direct'])) {
            $this->output->writeln('  <fg=gray>Direct dependents list:</>');
            foreach (array_slice($impact['direct'],0,12) as $n) {
                $this->output->writeln(sprintf('    <fg=gray>•</> <fg=white>%s</> <fg=gray>%s</>', $n->name, $n->type));
            }
            if (count($impact['direct']) > 12) $this->output->writeln('    <fg=gray>… +' . (count($impact['direct'])-12) . ' more</>');
            $this->output->writeln('');
        }

        // Visualization of affected tree (simple)
        $this->output->writeln('  <fg=gray>Affected tree (simplified):</>');
        $this->output->writeln(sprintf('  <fg=white>%s</> <fg=gray>(center)</>', $node->name));
        $this->output->writeln('  <fg=gray>    │</>');
        if (! empty($impact['direct'])) {
            $cols = array_slice($impact['direct'],0,3);
            $line = '  <fg=gray>    ├── </>' . implode('  <fg=gray>│</>  ', array_map(fn($n)=>'<fg=cyan>'.$n->name.'</>', $cols));
            $this->output->writeln($line);
            if (count($impact['direct']) > 3) $this->output->writeln('  <fg=gray>    │   … +' . (count($impact['direct'])-3) . ' more direct</>');
        }
        $this->output->writeln('');

        $this->output->writeln('  <fg=gray>Next:</> <fg=cyan>rat:why ' . $node->name . '</>  <fg=gray>|</> <fg=cyan>rat:flow "GET /' . strtolower($node->name) . '"</>');
        $this->output->writeln('');

        return 0;
    }

    private function hydrateGraph(array $data): \Rat\Engine\Graph\ApplicationGraph
    {
        $g = new \Rat\Engine\Graph\ApplicationGraph();
        foreach ($data['nodes'] ?? [] as $n) $g->addNode(new \Rat\Engine\Graph\Node($n['id'],$n['type'],$n['name'],$n['file']??'', $n['line']??0, $n['meta']??[]));
        foreach ($data['edges'] ?? [] as $e) $g->addEdge(new \Rat\Engine\Graph\Edge($e['from'],$e['to'],$e['kind'],$e['label']??'', $e['meta']??[]));
        return $g;
    }
    private function loadLastScan(): ?array
    {
        $c=[getcwd().'/storage/rat/last.json', getcwd().'/.rat.last.json', getcwd().'/.rat/last.json'];
        foreach($c as $p) if(file_exists($p)){ $d=json_decode((string)file_get_contents($p), true); if(is_array($d)&&isset($d['graph'])) return $d; }
        return null;
    }
    private function loadConfig(): array
    {
        $p=getcwd().'/config/rat.php'; if(file_exists($p)){try{$c=require $p; if(is_array($c)) return $c;}catch(\Throwable $e){}} return [];
    }

    private function findBestNode(\Rat\Engine\Graph\ApplicationGraph $graph, string $target): ?\Rat\Engine\Graph\Node
    {
        $target = trim($target);
        $base = basename($target, '.php');
        if (str_contains($target, ':')) {
            $n = $graph->getNode(strtolower($target));
            if ($n) return $n;
            foreach($graph->nodes() as $node) if ($node->id === $target) return $node;
        }
        $candidates = [];
        foreach($graph->nodes() as $node){
            if (strcasecmp($node->name, $target)===0 || strcasecmp($node->name, $base)===0) $candidates[]=$node;
            if ($node->file && strcasecmp(basename($node->file,'.php'), $base)===0) $candidates[]=$node;
        }
        if (!empty($candidates)){
            $priority=['Model'=>0,'Service'=>1,'Controller'=>2,'Job'=>3,'Observer'=>4,'Event'=>5,'Listener'=>6,'Route'=>9,'Other'=>8];
            usort($candidates, fn($a,$b)=> ($priority[$a->type]??7) <=> ($priority[$b->type]??7));
            return $candidates[0];
        }
        $lower=strtolower($target); $lowerBase=strtolower($base);
        $candidates=[];
        foreach($graph->nodes() as $node){
            if (str_contains(strtolower($node->name), $lower) || str_contains(strtolower($node->name), $lowerBase)){
                $candidates[]=$node;
            }
        }
        if (!empty($candidates)){
            usort($candidates, function($a,$b){
                $aIsRoute=$a->type==='Route'?1:0; $bIsRoute=$b->type==='Route'?1:0;
                if($aIsRoute!==$bIsRoute) return $aIsRoute <=> $bIsRoute;
                return strlen($a->name) <=> strlen($b->name);
            });
            return $candidates[0];
        }
        foreach($graph->nodes() as $node){
            if ($node->file && (str_contains(strtolower($node->file), $lower) || str_contains(strtolower($node->file), $lowerBase))) return $node;
        }
        return null;
    }
}
