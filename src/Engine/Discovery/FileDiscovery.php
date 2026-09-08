<?php

namespace Rat\Engine\Discovery;

use Rat\Engine\Graph\ApplicationGraph;
use Rat\Engine\Graph\Node;
use Rat\Engine\Graph\Edge;
use Rat\Engine\Detection\SourceDetector;
use Rat\Engine\Detection\SinkDetector;
use Rat\Engine\Detection\AuthorizationAnalyzer;
use Rat\Engine\Detection\HiddenBehaviorAnalyzer;

class FileDiscovery
{
    public function __construct(private readonly string $projectRoot, private readonly array $config = []) {}

    /**
     * Scan app/ directory for controllers, models, services, jobs, events, etc.
     * Populates graph nodes and returns file list with meta.
     *
     * @return array{files:int, by_type:array}
     */
    public function discover(ApplicationGraph $graph): array
    {
        $paths = $this->config['paths'] ?? ['.'];
        $exclude = $this->config['exclude'] ?? ['vendor','storage','bootstrap/cache','node_modules','public','.git','.idea','.vscode','tests','tests_python','.rat'];

        $allFiles = $this->collectPhpFiles($paths, $exclude);

        $byType = [
            'Controller' => 0,
            'Model' => 0,
            'Service' => 0,
            'Job' => 0,
            'Event' => 0,
            'Listener' => 0,
            'Observer' => 0,
            'Middleware' => 0,
            'Notification' => 0,
            'Other' => 0,
        ];

        foreach ($allFiles as $file) {
            $relative = str_replace($this->projectRoot . '/', '', $file);
            $content = @file_get_contents($file) ?: '';
            $basename = basename($file, '.php');

            $type = $this->inferType($file, $content, $basename);
            $byType[$type] = ($byType[$type] ?? 0) + 1;

            // Derive node id
            $id = strtolower($type) . ':' . $basename;
            // If model/service may have same basename as controller distinct is fine; prefix type ensures unique
            if (! $graph->hasNode($id)) {
                $graph->addNode(new Node($id, $type, $basename, $relative, 1));
            }

            // Edge inference: quick dependency detection via use statements / class references
            $this->inferEdges($graph, $id, $content);

            // Also add hidden behavior nodes if observer etc
            $hidden = HiddenBehaviorAnalyzer::analyze($content);
            if (! empty($hidden)) {
                // Annotate node meta
                $node = $graph->getNode($id);
                if ($node) {
                    $node->meta['hidden_behavior'] = array_keys($hidden);
                }
            }
        }

        // Also scan models for fillable/guarded, etc for later findings
        return ['files' => count($allFiles), 'by_type' => $byType];
    }

    /** @return string[] */
    private function collectPhpFiles(array $paths, array $exclude): array
    {
        $files = [];
        foreach ($paths as $p) {
            $full = $this->projectRoot . '/' . ltrim($p, '/');
            if (! is_dir($full) && ! is_file($full)) continue;
            if (is_file($full) && str_ends_with($full, '.php')) {
                $files[] = $full;
                continue;
            }
            if (! is_dir($full)) continue;
            $it = new \RecursiveIteratorIterator(new \RecursiveDirectoryIterator($full, \FilesystemIterator::SKIP_DOTS));
            foreach ($it as $f) {
                /** @var \SplFileInfo $f */
                if ($f->getExtension() !== 'php') continue;
                $real = $f->getRealPath();
                if ($real === false) continue;
                $rel = str_replace($this->projectRoot . '/', '', $real);
                $skip = false;
                foreach ($exclude as $ex) {
                    if (str_starts_with($rel, $ex) || str_contains($rel, '/' . $ex . '/')) {
                        $skip = true; break;
                    }
                }
                if ($skip) continue;
                $files[] = $real;
            }
        }
        return array_values(array_unique($files));
    }

    private function inferType(string $file, string $content, string $basename): string
    {
        $lower = strtolower($file);
        $contentLower = strtolower($content);

        // Monolith + Modular monolith + DDD + Microservices (any path) — suffix is primary
        if (str_contains($lower, '/http/controllers') || str_ends_with($basename, 'Controller')) return 'Controller';
        // Models: monolith / modular / DDD (Entity, Aggregate, Model)
        if (str_contains($lower, '/models') || str_contains($lower, '/entities') || str_contains($lower, '/aggregates') || str_contains($lower, '/domain') && (str_contains($lower, '/entity') || str_contains($lower, '/aggregate') || str_contains($content, 'extends Model'))) return 'Model';
        if (str_contains($content, 'extends Model') || str_ends_with($basename, 'Model')) return 'Model';
        // Services: app/Services, Domain/Service, Application/Service, Modules/*/Services
        if (str_contains($lower, '/services') || str_contains($lower, '/application/services') || str_contains($lower, '/domain/') && str_contains($lower, '/service') || str_ends_with($basename, 'Service')) return 'Service';
        if (str_contains($lower, '/jobs') || str_contains($contentLower, 'shouldqueue') || str_ends_with($basename, 'Job')) return 'Job';
        if (str_contains($lower, '/events') || str_ends_with($basename, 'Event')) return 'Event';
        if (str_contains($lower, '/listeners') || str_ends_with($basename, 'Listener')) return 'Listener';
        if (str_contains($lower, '/observers') || str_ends_with($basename, 'Observer')) return 'Observer';
        if (str_contains($lower, '/middleware') || str_ends_with($basename, 'Middleware')) return 'Middleware';
        if (str_contains($lower, '/notifications') || str_ends_with($basename, 'Notification')) return 'Notification';
        if (str_contains($lower, '/mail') || str_ends_with($basename, 'Mail')) return 'Mail';
        if (str_contains($lower, '/actions') || str_contains($lower, '/handlers') || str_contains($lower, '/usecases') || str_contains($lower, '/use_cases') || str_ends_with($basename, 'Action') || str_ends_with($basename, 'Handler') || str_ends_with($basename, 'UseCase')) return 'Service';
        // Repositories, Managers, Providers (common in modular/DDD)
        if (str_ends_with($basename, 'Repository') || str_ends_with($basename, 'Manager') || str_ends_with($basename, 'Provider')) return 'Service';
        // Livewire / Inertia (monolith)
        if (str_contains($lower, '/livewire') || str_contains($lower, '/components')) return 'Controller';

        // Fallback via content heuristics (covers any architecture)
        if (str_contains($content, 'class') && str_contains($content, 'Controller')) return 'Controller';

        return 'Other';
    }

    private function inferEdges(ApplicationGraph $graph, string $fromId, string $content): void
    {
        // Detect class usages: User, Order, Service, Job dispatches etc.
        // Simple heuristic: find "New Xxx", "Xxx::", "dispatch(new Xxx"
        // Extract potential class names CamelCase
        if (preg_match_all('/\b([A-Z][a-zA-Z0-9_]+)\s*::/', $content, $m)) {
            foreach (array_unique($m[1]) as $cls) {
                if (in_array($cls, ['DB','Schema','Cache','Storage','Http','Auth','Gate','Route','Log','Str','Arr'], true)) {
                    $toId = strtolower($cls) . ':' . $cls;
                    $type = match ($cls) {
                        'Storage' => 'Filesystem',
                        'DB' => 'Database',
                        'Cache' => 'Cache',
                        'Http' => 'External',
                        default => 'Service',
                    };
                    if (! $graph->hasNode($toId)) {
                        $graph->addNode(new Node($toId, $type, $cls, '', 0));
                    }
                    $graph->addEdge(new Edge($fromId, $toId, 'DEPENDS_ON', $cls . '::'));
                } elseif (str_ends_with($cls, 'Service') || str_ends_with($cls, 'Repository') || str_ends_with($cls, 'Manager')) {
                    $toId = 'service:' . $cls;
                    if (! $graph->hasNode($toId)) {
                        $graph->addNode(new Node($toId, 'Service', $cls, '', 0));
                    }
                    $graph->addEdge(new Edge($fromId, $toId, 'CALLS', $cls));
                } elseif (str_ends_with($cls, 'Model') || in_array($cls, ['User','Order','Post','Product','Import','Payment'], true)) {
                    // heuristic models
                    $toId = 'model:' . $cls;
                    if (! $graph->hasNode($toId)) {
                        $graph->addNode(new Node($toId, 'Model', $cls, '', 0));
                    }
                    $graph->addEdge(new Edge($fromId, $toId, 'WRITES', $cls));
                }
            }
        }

        // dispatch / event
        if (preg_match_all('/dispatch\s*\(\s*new\s+([A-Z][a-zA-Z0-9_\\\\]+)/', $content, $m)) {
            foreach ($m[1] as $cls) {
                $short = basename(str_replace('\\', '/', $cls));
                $toId = 'job:' . $short;
                if (! $graph->hasNode($toId)) {
                    $graph->addNode(new Node($toId, 'Job', $short, '', 0));
                }
                $graph->addEdge(new Edge($fromId, $toId, 'DISPATCHES', $short));
            }
        }

        if (preg_match_all('/event\s*\(\s*new\s+([A-Z][a-zA-Z0-9_\\\\]+)/', $content, $m)) {
            foreach ($m[1] as $cls) {
                $short = basename(str_replace('\\', '/', $cls));
                $toId = 'event:' . $short;
                if (! $graph->hasNode($toId)) {
                    $graph->addNode(new Node($toId, 'Event', $short, '', 0));
                }
                $graph->addEdge(new Edge($fromId, $toId, 'TRIGGERS', $short));
            }
        }

        // Observer: e.g. User::observe(UserObserver::class)
        if (preg_match_all('/([A-Z][a-zA-Z0-9_]+)::observe\s*\(\s*([A-Z][a-zA-Z0-9_\\\\]+)::class/', $content, $m, PREG_SET_ORDER)) {
            foreach ($m as $match) {
                $model = $match[1];
                $observer = basename(str_replace('\\', '/', $match[2]));
                $fromM = 'model:' . $model;
                $toO = 'observer:' . $observer;
                if (! $graph->hasNode($fromM)) $graph->addNode(new Node($fromM, 'Model', $model, '', 0));
                if (! $graph->hasNode($toO)) $graph->addNode(new Node($toO, 'Observer', $observer, '', 0));
                $graph->addEdge(new Edge($fromM, $toO, 'TRIGGERS', 'observe'));
            }
        }
    }
}
