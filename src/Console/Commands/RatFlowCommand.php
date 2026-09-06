<?php

namespace Rat\Console\Commands;

use Illuminate\Console\Command;
use Rat\Support\RatBanner;

class RatFlowCommand extends Command
{
    protected $signature = 'rat:flow
                            {route : Route to trace e.g. "POST /api/import" or "/api/import"}
                            {--depth=8 : Max traversal depth}
                            {--format=table : table|json}
                            {--no-image}';

    protected $description = 'Visualize the execution flow for a specific route / entry point.';

    public function handle(): int
    {
        $routeArg = (string) $this->argument('route');
        $depth = (int) $this->option('depth');
        $format = $this->option('format') ?? 'table';
        $noImage = (bool) $this->option('no-image');

        $payload = $this->loadLastScan();
        if (! $payload) {
            $this->warn(' No prior scan — running quick analysis...');
            $analyzer = new \Rat\Engine\Analyzer(getcwd(), $this->loadConfig());
            $res = $analyzer->analyze();
            $payload = ['graph'=>$res['graph']->toArray(), 'findings'=> array_map(fn($f)=>$f->toArray(), $res['findings'])];
        }

        $graphData = $payload['graph'] ?? [];
        $graph = $this->hydrateGraph($graphData);

        // Find route node: support "POST /api/import" or just uri
        $routeNode = $this->findRouteNode($graph, $routeArg);
        if (! $routeNode) {
            // Try finding any node by name fallback
            $routeNode = $graph->findNodeByName($routeArg);
        }

        if (! $routeNode) {
            $this->error(" Route [$routeArg] not found in application graph.");
            $this->line(' Available routes:');
            foreach ($graph->nodesByType('Route') as $n) {
                $this->output->writeln(sprintf('   <fg=cyan>%s</> <fg=gray>%s</>', $n->name, $n->file));
            }
            if (empty($graph->nodesByType('Route'))) {
                $this->output->writeln('  <fg=gray>(no routes detected — ensure routes/*.php exists and RAT scanned correctly)</>');
            }
            return 1;
        }

        if ($format === 'json') {
            $trace = $this->buildTrace($graph, $routeNode, $depth);
            $this->output->writeln(json_encode(['entry'=>$routeNode->toArray(),'trace'=>$trace], JSON_PRETTY_PRINT|JSON_UNESCAPED_SLASHES));
            return 0;
        }

        if (! $noImage) RatBanner::render($this->output, true, false);

        $this->output->writeln('');
        $this->output->writeln('  <fg=white;options=bold>🐀 FLOW</>');
        $this->output->writeln('');
        $this->output->writeln(sprintf('  <fg=cyan;options=bold>%s</>', $routeNode->name));
        $this->output->writeln('');

        $trace = $this->buildTrace($graph, $routeNode, $depth);

        // Render flow with branching visualization
        $this->renderFlow($routeNode, $trace);

        // Check if this route participates in any dangerous finding
        $findings = $payload['findings'] ?? [];
        $related = array_filter($findings, fn($f)=> str_contains(strtolower($f['entry'] ?? ''), strtolower($routeNode->name)) || str_contains(strtolower($f['flow'][0] ?? ''), strtolower($routeNode->name)) );
        if (! empty($related)) {
            $this->output->writeln('');
            $this->output->writeln('  <fg=red;options=bold>⚠ Potential dangerous flow</>');
            foreach ($related as $rel) {
                $this->output->writeln(sprintf('   <fg=red>%s</> <fg=white>%s</> <fg=gray>→ %s (%s)</>', $rel['id'], $rel['title'], $rel['sink'], strtolower($rel['severity'])));
                $this->output->writeln(sprintf('      <fg=gray>Source:</> <fg=yellow>%s</>  <fg=gray>Confidence:</> %s', $rel['source'], strtoupper($rel['confidence'])));
            }
            $this->output->writeln('  <fg=gray>Investigate: </><fg=cyan>rat:show ' . array_values($related)[0]['id'] . '</>');
        } else {
            $this->output->writeln('');
            $this->output->writeln('  <fg=green>✓ No dangerous flows flagged for this entry in last scan.</> <fg=gray>(still review manually)</>');
        }

        $this->output->writeln('');
        $this->output->writeln(sprintf('  <fg=gray>Depth: %d — increase with --depth=12 for deeper trace</>', $depth));
        if ($graph->hasNode('rat:meta:truncated')) {
            $this->output->writeln('  <fg=gray>Graph truncated at depth limit.</>');
        }

        return 0;
    }

    private function findRouteNode($graph, string $arg): ?\Rat\Engine\Graph\Node
    {
        $arg = trim($arg, '"\'');
        // Exact match
        foreach ($graph->nodesByType('Route') as $n) {
            if (strcasecmp($n->name, $arg) === 0) return $n;
        }
        // Contains uri
        $argLower = strtolower($arg);
        // If arg contains method + uri, try uri alone
        $uriOnly = $arg;
        if (preg_match('/^(GET|POST|PUT|PATCH|DELETE|OPTIONS)\s+(.+)$/i', $arg, $m)) {
            $uriOnly = trim($m[2]);
            $method = strtoupper($m[1]);
            foreach ($graph->nodesByType('Route') as $n) {
                if (strcasecmp($n->name, $method . ' ' . $uriOnly) === 0) return $n;
            }
        }
        foreach ($graph->nodesByType('Route') as $n) {
            if (str_contains(strtolower($n->name), $argLower) || str_contains(strtolower($n->name), strtolower($uriOnly))) return $n;
        }
        return null;
    }

    private function buildTrace($graph, $startNode, int $depth): array
    {
        // BFS with parent tracking
        $queue = [[$startNode->id, 0, null]]; // id, depth, parentEdge
        $visited = [$startNode->id => true];
        $levels = [0 => [$startNode]];
        $edges = [];

        while (! empty($queue)) {
            [$curId, $d, $parent] = array_shift($queue);
            if ($d >= $depth) continue;
            foreach ($graph->outgoing($curId) as $edge) {
                $nextId = $edge->to;
                $edges[] = ['from'=>$curId,'to'=>$nextId,'edge'=>$edge];
                if (! isset($visited[$nextId])) {
                    $visited[$nextId] = true;
                    $node = $graph->getNode($nextId);
                    if ($node) {
                        $levels[$d+1][] = $node;
                        $queue[] = [$nextId, $d+1, $edge];
                    }
                }
            }
        }
        return ['levels'=>$levels, 'edges'=>$edges];
    }

    private function renderFlow($startNode, array $trace): void
    {
        $levels = $trace['levels'];
        $edges = $trace['edges'];

        // Build id -> level map
        $levelOf = [];
        foreach ($levels as $lvl => $nodes) {
            foreach ($nodes as $n) $levelOf[$n->id] = $lvl;
        }

        // Simple vertical + branch rendering. We'll render level by level.
        // Keep visited to avoid duplicate lines for diamond graphs (render once)
        $rendered = [];

        $this->output->writeln(sprintf('  <fg=white>┌───────────────────┐</>'));
        $this->output->writeln(sprintf('  <fg=white>│ %-17s │</> <fg=gray>Route</>', substr($startNode->name,0,17)));
        $this->output->writeln(sprintf('  <fg=white>└────────┬──────────┘</>'));

        $sortedLevelKeys = array_keys($levels);
        sort($sortedLevelKeys);
        foreach ($sortedLevelKeys as $lvl) {
            if ($lvl === 0) continue;
            $nodes = $levels[$lvl];
            // Deduplicate
            $nodes = array_unique($nodes, SORT_REGULAR);

            // Draw connector from previous level
            $this->output->writeln('  <fg=gray>         │</>');
            if (count($nodes) === 1) {
                $this->output->writeln('  <fg=gray>         ▼</>');
                $n = $nodes[0];
                $color = match($n->type){'External'=>'yellow','Database'=>'blue','Filesystem'=>'red','Job'=>'magenta', default=>'white'};
                $this->output->writeln(sprintf('  <fg=%s>┌───────────────────┐</>', $color));
                $this->output->writeln(sprintf('  <fg=%s>│ %-17s │</> <fg=gray>%s</>', $color, substr($n->name,0,17), $n->type));
                $this->output->writeln(sprintf('  <fg=%s>└────────┬──────────┘</>', $color));
            } else {
                // Branching at this level
                $this->output->writeln('  <fg=gray>         ├──┬── Branch (' . count($nodes) . ')</>');
                foreach ($nodes as $n) {
                    $color = match($n->type){'External'=>'yellow','Database'=>'blue','Filesystem'=>'red', default=>'white'};
                    $this->output->writeln(sprintf('  <fg=gray>         │</>  <fg=%s>▶ %-16s</> <fg=gray>%s</>', $color, substr($n->name,0,16), $n->type));
                }
                // For simplicity, continue drawing vertical after branch (convergence not shown)
                $this->output->writeln('  <fg=gray>         │</>');
            }
        }

        // If leaf includes dangerous sink, highlight
        $hasDanger = false;
        foreach ($levels as $lvlNodes) {
            foreach ($lvlNodes as $n) {
                if (in_array($n->type, ['Filesystem','Database','External'], true) && $n->type === 'Filesystem') $hasDanger = true;
            }
        }
        if ($hasDanger) {
            // already flagged later
        }
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
        foreach ($candidates as $p) if (file_exists($p)) { $d=json_decode((string)file_get_contents($p),true); if(is_array($d) && isset($d['graph'])) return $d; }
        return null;
    }
    private function loadConfig(): array
    {
        $path=getcwd().'/config/rat.php';
        if(file_exists($path)){try{$c=require $path; if(is_array($c)) return $c;}catch(\Throwable $e){}} return [];
    }
}
