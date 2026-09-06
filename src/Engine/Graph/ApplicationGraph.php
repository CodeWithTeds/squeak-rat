<?php

namespace Rat\Engine\Graph;

class ApplicationGraph
{
    /** @var Node[] id => Node */
    private array $nodes = [];
    /** @var Edge[] */
    private array $edges = [];

    public function addNode(Node $node): void
    {
        $this->nodes[$node->id] = $node;
    }

    public function hasNode(string $id): bool { return isset($this->nodes[$id]); }

    public function getNode(string $id): ?Node { return $this->nodes[$id] ?? null; }

    /** @return Node[] */
    public function nodes(): array { return array_values($this->nodes); }

    public function addEdge(Edge $edge): void
    {
        $this->edges[] = $edge;
    }

    /** @return Edge[] */
    public function edges(): array { return $this->edges; }

    /** @return Node[] */
    public function nodesByType(string $type): array
    {
        return array_values(array_filter($this->nodes, fn(Node $n) => $n->type === $type));
    }

    /** @return Edge[] outgoing from $nodeId */
    public function outgoing(string $nodeId): array
    {
        return array_values(array_filter($this->edges, fn(Edge $e) => $e->from === $nodeId));
    }

    /** @return Edge[] incoming to $nodeId */
    public function incoming(string $nodeId): array
    {
        return array_values(array_filter($this->edges, fn(Edge $e) => $e->to === $nodeId));
    }

    /** @return Node[] reachable within depth via BFS */
    public function reachableFrom(string $startId, int $depth = 10): array
    {
        $visited = [$startId => true];
        $queue = [[$startId, 0]];
        $result = [];

        while (! empty($queue)) {
            [$cur, $d] = array_shift($queue);
            if ($d >= $depth) continue;
            foreach ($this->outgoing($cur) as $e) {
                if (! isset($visited[$e->to])) {
                    $visited[$e->to] = true;
                    $node = $this->getNode($e->to);
                    if ($node) $result[] = $node;
                    $queue[] = [$e->to, $d + 1];
                }
            }
        }
        return $result;
    }

    /** Trace ancestors (reverse reachable) */
    public function ancestorsOf(string $nodeId, int $depth = 10): array
    {
        $visited = [$nodeId => true];
        $queue = [[$nodeId, 0]];
        $result = [];
        while (! empty($queue)) {
            [$cur, $d] = array_shift($queue);
            if ($d >= $depth) continue;
            foreach ($this->incoming($cur) as $e) {
                if (! isset($visited[$e->from])) {
                    $visited[$e->from] = true;
                    $node = $this->getNode($e->from);
                    if ($node) $result[] = $node;
                    $queue[] = [$e->from, $d + 1];
                }
            }
        }
        return $result;
    }

    public function impactFor(string $nodeId): array
    {
        $direct = $this->incoming($nodeId);
        $indirect = $this->reachableFrom($nodeId, 6); // out, but impact is usually reverse; mimic both
        // For simpler UI we compute reverse dependents
        $dependents = $this->ancestorsOf($nodeId, 8);

        // Group by type
        $group = fn(array $nodes) => array_count_values(array_map(fn(Node $n) => $n->type, $nodes));
        $directNodes = array_map(fn(Edge $e) => $this->getNode($e->from), $direct);
        $directNodes = array_filter($directNodes);

        return [
            'direct' => $directNodes,
            'direct_by_type' => $group($directNodes),
            'indirect' => $dependents,
            'indirect_by_type' => $group($dependents),
            'score' => $this->impactScore(count($directNodes), count($dependents)),
        ];
    }

    private function impactScore(int $direct, int $indirect): string
    {
        $total = $direct * 3 + $indirect;
        if ($total >= 40) return 'CRITICAL';
        if ($total >= 20) return 'HIGH';
        if ($total >= 8) return 'MEDIUM';
        if ($total >= 3) return 'LOW';
        return 'INFO';
    }

    public function toArray(): array
    {
        return [
            'nodes' => array_map(fn(Node $n) => $n->toArray(), $this->nodes()),
            'edges' => array_map(fn(Edge $e) => $e->toArray(), $this->edges),
            'stats' => $this->stats(),
        ];
    }

    public function stats(): array
    {
        $types = array_count_values(array_map(fn(Node $n) => $n->type, $this->nodes()));
        return [
            'nodes' => count($this->nodes),
            'edges' => count($this->edges),
            'by_type' => $types,
        ];
    }

    /** Find node by name substring */
    public function findNodeByName(string $name): ?Node
    {
        $needle = strtolower($name);
        foreach ($this->nodes as $node) {
            if (strtolower($node->name) === $needle || str_contains(strtolower($node->name), $needle) || str_contains(strtolower($node->id), $needle)) {
                return $node;
            }
        }
        return null;
    }
}
