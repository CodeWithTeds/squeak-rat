<?php

namespace Rat\Engine\Discovery;

use Rat\Engine\Graph\ApplicationGraph;
use Rat\Engine\Graph\Node;
use Rat\Engine\Graph\Edge;

class RouteDiscovery
{
    public function __construct(private readonly string $projectRoot) {}

    /**
     * @return array{routes: array<int, array{method:string, uri:string, action:string, file:string, line:int}>, count:int}
     */
    public function discover(ApplicationGraph $graph): array
    {
        $routes = [];
        $routeFiles = $this->routeFiles();

        foreach ($routeFiles as $file) {
            $content = @file_get_contents($file);
            if ($content === false) continue;

            // Very permissive Laravel route parsing via regex — covers Route::get/post/etc, Route::resource, Route::apiResource
            // Example: Route::get('/api/import', [ImportController::class, 'import'])
            // We extract method, uri, and controller reference.

            // 1) Classic Route::verb('uri', ...)
            if (preg_match_all('/Route\s*::\s*(get|post|put|patch|delete|options|any|match)\s*\(\s*[\'"]([^\'"]+)[\'"]\s*,([^;]+)\)/i', $content, $matches, PREG_SET_ORDER | PREG_OFFSET_CAPTURE)) {
                foreach ($matches as $m) {
                    $method = strtoupper($m[1][0]);
                    $uri = $m[2][0];
                    $actionRaw = trim($m[3][0]);
                    // Extract line
                    $line = substr_count(substr($content, 0, (int) $m[0][1]), "\n") + 1;
                    $action = $this->normalizeAction($actionRaw);
                    $routes[] = ['method' => $method, 'uri' => $uri, 'action' => $action, 'file' => $file, 'line' => $line];

                    $nodeId = "route:" . $method . ":" . $uri;
                    if (! $graph->hasNode($nodeId)) {
                        $graph->addNode(new Node($nodeId, 'Route', $method . ' ' . $uri, $file, $line, ['action' => $action]));
                    }
                    // Link route -> controller
                    if ($action && str_contains($action, 'Controller')) {
                        $controllerPart = explode('@', $action)[0] ?? $action;
                        $controllerPart = trim($controllerPart, " []'\"");
                        $controllerPart = basename(str_replace('\\', '/', $controllerPart));
                        $cId = "controller:" . $controllerPart;
                        if (! $graph->hasNode($cId)) {
                            $graph->addNode(new Node($cId, 'Controller', $controllerPart, '', 0));
                        }
                        $graph->addEdge(new Edge($nodeId, $cId, 'CALLS', $action));
                    }
                }
            }

            // 2) Route::resource / apiResource
            if (preg_match_all('/Route\s*::\s*(resource|apiResource)\s*\(\s*[\'"]([^\'"]+)[\'"]\s*,\s*([^\s,\)]+)/i', $content, $matches2, PREG_SET_ORDER | PREG_OFFSET_CAPTURE)) {
                foreach ($matches2 as $m) {
                    $uri = $m[2][0];
                    $controllerRaw = $m[3][0];
                    $line = substr_count(substr($content, 0, (int) $m[0][1]), "\n") + 1;
                    $controller = trim($controllerRaw, " []'\"\\");
                    $controller = basename(str_replace('\\', '/', $controller));
                    $methods = $m[1][0] === 'apiResource' ? ['GET','POST','PUT','DELETE'] : ['GET','POST','PUT','PATCH','DELETE'];
                    foreach ($methods as $method) {
                        $nodeId = "route:" . $method . ":" . $uri;
                        if (! $graph->hasNode($nodeId)) {
                            $graph->addNode(new Node($nodeId, 'Route', $method . ' ' . $uri, $file, $line, ['action' => $controller, 'resource' => true]));
                        }
                        $cId = "controller:" . $controller;
                        if (! $graph->hasNode($cId)) {
                            $graph->addNode(new Node($cId, 'Controller', $controller, '', 0));
                        }
                        $graph->addEdge(new Edge($nodeId, $cId, 'CALLS', $controller));
                    }
                    $routes[] = ['method' => implode('|', $methods), 'uri' => $uri, 'action' => $controller, 'file' => $file, 'line' => $line];
                }
            }
        }

        return ['routes' => $routes, 'count' => count($routes)];
    }

    /** @return string[] */
    private function routeFiles(): array
    {
        // Monolith: routes/*.php
        $candidates = [
            $this->projectRoot . '/routes/web.php',
            $this->projectRoot . '/routes/api.php',
            $this->projectRoot . '/routes/channels.php',
            $this->projectRoot . '/routes/console.php',
        ];
        $files = array_filter($candidates, 'file_exists');

        // Glob patterns covering monolith, modular monolith, and microservices monorepo
        $patterns = [
            // Monolith
            $this->projectRoot . '/routes/*.php',
            // Modular monolith (nwidart/laravel-modules, etc.)
            $this->projectRoot . '/Modules/*/Routes/*.php',
            $this->projectRoot . '/Modules/*/routes/*.php',
            $this->projectRoot . '/modules/*/Routes/*.php',
            $this->projectRoot . '/modules/*/routes/*.php',
            $this->projectRoot . '/app/Modules/*/Routes/*.php',
            $this->projectRoot . '/app/Modules/*/routes/*.php',
            // DDD / Domain
            $this->projectRoot . '/Domain/*/Routes/*.php',
            $this->projectRoot . '/domain/*/Routes/*.php',
            $this->projectRoot . '/Domains/*/Routes/*.php',
            $this->projectRoot . '/src/*/Routes/*.php',
            $this->projectRoot . '/src/*/routes/*.php',
            $this->projectRoot . '/src/Domain/*/Routes/*.php',
            // Packages / plugins
            $this->projectRoot . '/packages/*/routes/*.php',
            $this->projectRoot . '/packages/*/src/routes/*.php',
            // Microservices monorepo
            $this->projectRoot . '/services/*/routes/*.php',
            $this->projectRoot . '/Services/*/Routes/*.php',
            $this->projectRoot . '/services/*/app/routes/*.php',
            $this->projectRoot . '/apps/*/routes/*.php',
            $this->projectRoot . '/microservices/*/routes/*.php',
        ];
        foreach ($patterns as $pat) {
            $glob = glob($pat) ?: [];
            foreach ($glob as $f) {
                if (! in_array($f, $files, true)) $files[] = $f;
            }
        }

        return array_values($files);
    }

    private function normalizeAction(string $raw): string
    {
        // Remove trailing ) and whitespace
        $raw = trim($raw);
        // If contains ::class
        if (preg_match('/([A-Za-z0-9_\\\\]+)::class/', $raw, $m)) {
            $class = $m[1];
            // Try to extract method: , 'method' or , "method"
            if (preg_match('/,\s*[\'"]([^\'"]+)[\'"]/', $raw, $mm)) {
                return $class . '@' . $mm[1];
            }
            return $class;
        }
        // String action 'Controller@method'
        if (preg_match('/[\'"]([^\'"]+@[^\'"]+)[\'"]/', $raw, $m)) {
            return $m[1];
        }
        // Closure or other
        if (str_contains($raw, 'function') || str_contains($raw, 'fn(')) {
            return 'Closure';
        }
        return trim($raw, " \t\n\r\0\x0B,);");
    }
}
