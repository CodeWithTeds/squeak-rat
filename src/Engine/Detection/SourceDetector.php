<?php

namespace Rat\Engine\Detection;

class SourceDetector
{
    public const SOURCES = [
        // Request
        '$request->input',
        '$request->query',
        '$request->post',
        '$request->get',
        '$request->all',
        '$request->only',
        '$request->except',
        '$request->file',
        '$request->header',
        '$request->cookie',
        '$request->server',
        '$request->bearerToken',
        'request()->input',
        'request()->query',
        'request()->all',
        'request()->file',
        // Superglobals
        '$_GET',
        '$_POST',
        '$_REQUEST',
        '$_COOKIE',
        '$_FILES',
        '$_SERVER',
        // Route params
        '$request->route',
        'Route::input',
    ];

    // Patterns for regex detection in file content
    public const SOURCE_PATTERNS = [
        '/\$request\s*->\s*(input|query|post|get|all|only|except|file|header|cookie|server|bearerToken)\s*\(/i' => '$request->input source',
        '/request\s*\(\s*\)\s*->\s*(input|all|query|file)\s*\(/i' => 'request() helper source',
        '/\$_GET|\$_POST|\$_REQUEST|\$_COOKIE|\$_FILES/i' => 'superglobal source',
        '/\$request\s*->\s*route\s*\(/i' => 'route parameter source',
        '/\$request\s*->\s*validate\s*\(/i' => 'validated request (still tainted but lower risk)',
    ];

    public static function detectInContent(string $content): array
    {
        $hits = [];
        foreach (self::SOURCE_PATTERNS as $pattern => $label) {
            if (preg_match_all($pattern, $content, $m, PREG_OFFSET_CAPTURE)) {
                foreach ($m[0] as $match) {
                    $hits[] = [
                        'snippet' => trim(substr($match[0], 0, 80)),
                        'offset' => $match[1],
                        'label' => $label,
                    ];
                }
            }
        }
        return $hits;
    }

    public static function isSourceLine(string $line): bool
    {
        foreach (self::SOURCE_PATTERNS as $pattern => $v) {
            if (preg_match($pattern, $line)) return true;
        }
        return false;
    }
}
