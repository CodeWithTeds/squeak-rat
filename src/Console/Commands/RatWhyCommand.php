<?php

namespace Rat\Console\Commands;

use Illuminate\Console\Command;
use Rat\Support\RatBanner;

class RatWhyCommand extends Command
{
    protected $signature = 'rat:why
                            {target : Class/file to investigate e.g. UserController or User.php}
                            {--depth=6 : Graph traversal depth}
                            {--format=table : table|json}
                            {--no-image}';

    protected $description = 'Explain why a class has access to something (hidden behavior / dependency trail).';

    public function handle(): int
    {
        $target = (string) $this->argument('target');
        $depth = (int) $this->option('depth');
        $format = $this->option('format') ?? 'table';
        $noImage = (bool) $this->option('no-image');

        $payload = $this->loadLastScan();
        if (! $payload) {
            $this->warn(' No prior scan — running quick analysis for why...');
            $analyzer = new \Rat\Engine\Analyzer(getcwd(), $this->loadConfig());
            $res = $analyzer->analyze();
            $graphArr = $res['graph']->toArray();
            $payload = ['graph'=>$graphArr, 'findings'=> array_map(fn($f)=>$f->toArray(), $res['findings'])];
        }

        $graphData = $payload['graph'] ?? [];
        $graph = $this->hydrateGraph($graphData);

        $node = $this->findBestNode($graph, $target);
        if (! $node) {
            // Try file name
            $base = basename($target, '.php');
            $node = $graph->findNodeByName($base);
        }
        if (! $node) {
            $this->error(" Target [$target] not found in application graph. Try `rat:show` to see available nodes or check spelling.");
            $this->line(' <fg=gray>Tip: rat:why UserController  or  rat:why User.php  or  rat:why ImportService</>');
            // Still list candidates
            $candidates = array_slice($graph->nodes(), 0, 20);
            $this->output->writeln('');
            $this->output->writeln('  <fg=gray>Available nodes (sample):</>');
            foreach ($candidates as $n) {
                $this->output->writeln(sprintf('   <fg=cyan>%s</> <fg=gray>(%s)</>', $n->name, $n->type));
            }
            return 1;
        }

        if ($format === 'json') {
            $reachable = $graph->reachableFrom($node->id, $depth);
            $ancestors = $graph->ancestorsOf($node->id, $depth);
            $out = [
                'target' => $node->toArray(),
                'outgoing' => array_map(fn($n)=>$n->toArray(), $reachable),
                'incoming' => array_map(fn($n)=>$n->toArray(), $ancestors),
                'edges_out' => array_map(fn($e)=>$e->toArray(), $graph->outgoing($node->id)),
                'edges_in' => array_map(fn($e)=>$e->toArray(), $graph->incoming($node->id)),
            ];
            $this->output->writeln(json_encode($out, JSON_PRETTY_PRINT|JSON_UNESCAPED_SLASHES));
            return 0;
        }

        if (! $noImage) RatBanner::render($this->output, true, false);

        $this->output->writeln('');
        $this->output->writeln(sprintf('  <fg=white;options=bold>WHY DOES %s HAVE ACCESS TO ...?</>', strtoupper($node->name)));
        $this->output->writeln('');
        $this->output->writeln(sprintf('  <fg=gray>Target:</> <fg=white;options=bold>%s</> <fg=gray>(%s)  %s</>', $node->name, $node->type, $node->file ?: ''));

        // Show outgoing dependency trail
        $out = $graph->reachableFrom($node->id, $depth);
        $in = $graph->ancestorsOf($node->id, $depth);
        $edgesOut = $graph->outgoing($node->id);
        $edgesIn = $graph->incoming($node->id);

        $this->output->writeln('');
        $this->output->writeln('  <fg=white;options=bold>DEPENDENCY TRAIL (outgoing)</>');
        $this->output->writeln('  <fg=gray>' . str_repeat('─', 40) . '</>');

        if (empty($edgesOut) && empty($out)) {
            $this->output->writeln('  <fg=gray>No outgoing dependencies detected (isolated node).</>');
        } else {
            // Build flow visualization like UserController -> UserService -> CacheRepository -> Redis
            $flow = [$node->name];
            // Greedy follow first outgoing edge repeatedly for demo trail
            $curId = $node->id;
            $visited = [$curId=>true];
            for ($d=0;$d<$depth;$d++) {
                $outs = $graph->outgoing($curId);
                if (empty($outs)) break;
                $nextEdge = $outs[0];
                $nextId = $nextEdge->to;
                if (isset($visited[$nextId])) break;
                $nextNode = $graph->getNode($nextId);
                if (! $nextNode) break;
                $flow[] = $nextNode->name . ' <fg=gray>(' . $nextEdge->kind . ')</>';
                $curId = $nextId;
                $visited[$curId]=true;
            }

            // Render vertical
            foreach ($flow as $i=>$step) {
                $this->output->writeln(sprintf('  <fg=white>%s</>', $step));
                if ($i < count($flow)-1) {
                    $this->output->writeln('  <fg=gray>    ↓</>');
                }
            }

            $this->output->writeln('');
            $this->output->writeln('  <fg=gray>All outgoing edges:</>');
            foreach ($edgesOut as $e) {
                $t = $graph->getNode($e->to);
                $this->output->writeln(sprintf('    <fg=cyan>%s</> <fg=gray>%s</> <fg=white>%s</>', $node->name, $e->kind, $t ? $t->name.' ('.$t->type.')' : $e->to));
            }

            if (count($out) > count($edgesOut)) {
                $this->output->writeln('');
                $this->output->writeln(sprintf('  <fg=gray>Transitive reachable (%d):</>', count($out)));
                foreach (array_slice($out,0,10) as $n) {
                    $this->output->writeln(sprintf('    <fg=gray>•</> <fg=white>%s</> <fg=gray>%s</>', $n->name, $n->type));
                }
                if (count($out) > 10) $this->output->writeln('    <fg=gray>… +' . (count($out)-10) . ' more (increase --depth)</>');
            }
        }

        $this->output->writeln('');
        $this->output->writeln('  <fg=white;options=bold>WHO DEPENDS ON THIS?</>');
        $this->output->writeln('  <fg=gray>' . str_repeat('─', 40) . '</>');

        if (empty($edgesIn)) {
            $this->output->writeln('  <fg=gray>No incoming dependents (entry point or orphan).</>');
        } else {
            foreach ($edgesIn as $e) {
                $f = $graph->getNode($e->from);
                $this->output->writeln(sprintf('    <fg=white>%s</> <fg=gray>%s</> <fg=cyan>%s</>', $f ? $f->name.' ('.$f->type.')' : $e->from, $e->kind, $node->name));
            }
            if (! empty($in) && count($in) > count($edgesIn)) {
                $this->output->writeln(sprintf('  <fg=gray>Full ancestors (%d) — see --depth</>', count($in)));
            }
        }

        $this->output->writeln('');
        $this->output->writeln('  <fg=gray>Hidden behavior for this node: ' . (! empty($node->meta['hidden_behavior']) ? '<fg=yellow>' . implode(', ', $node->meta['hidden_behavior']) . '</>' : '<fg=gray>none detected</>') . '</>');
        $this->output->writeln('  <fg=gray>Try:</> <fg=cyan>rat:impact ' . $node->name . '</>  <fg=gray>|</> <fg=cyan>rat:flow "' . ($node->type==='Route'?$node->name: $node->name) . '"</>');
        $this->output->writeln('');

        return 0;
    }

    private function hydrateGraph(array $data): \Rat\Engine\Graph\ApplicationGraph
    {
        $g = new \Rat\Engine\Graph\ApplicationGraph();
        foreach ($data['nodes'] ?? [] as $n) {
            $g->addNode(new \Rat\Engine\Graph\Node($n['id'],$n['type'],$n['name'],$n['file']??'', $n['line']??0, $n['meta']??[]));
        }
        foreach ($data['edges'] ?? [] as $e) {
            $g->addEdge(new \Rat\Engine\Graph\Edge($e['from'],$e['to'],$e['kind'],$e['label']??'', $e['meta']??[]));
        }
        return $g;
    }

    private function loadLastScan(): ?array
    {
        $candidates = [getcwd().'/storage/rat/last.json', getcwd().'/.rat.last.json', getcwd().'/.rat/last.json'];
        foreach ($candidates as $p) {
            if (file_exists($p)) {
                $d = json_decode((string) file_get_contents($p), true);
                if (is_array($d) && isset($d['graph'])) return $d;
            }
        }
        return null;
    }
    private function loadConfig(): array
    {
        $path = getcwd().'/config/rat.php';
        if (file_exists($path)){ try{$c=require $path; if(is_array($c)) return $c;}catch(\Throwable $e){}}
        return [];
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
