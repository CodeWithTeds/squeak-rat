<?php

namespace Rat\Engine\Detection;

use Rat\Engine\Findings\Severity;

class SinkDetector
{
    // Map pattern => [sink name, severity]
    public const SINKS = [
        // Filesystem
        '/Storage\s*::\s*(put|putFile|putFileAs|store|storeAs|append|prepend|copy|move|delete)\s*\(/i' => ['Storage::put', Severity::CRITICAL],
        '/\bfile_put_contents\s*\(/i' => ['file_put_contents', Severity::CRITICAL],
        '/\bfile_get_contents\s*\(/i' => ['file_get_contents', Severity::HIGH],
        '/\bfopen\s*\(/i' => ['fopen', Severity::HIGH],
        '/\bunlink\s*\(|\bmkdir\s*\(|\brmdir\s*\(|\brename\s*\(/i' => ['filesystem operation', Severity::HIGH],
        '/include\s*\(|require\s*\(|include_once|require_once/i' => ['file inclusion', Severity::CRITICAL],

        // DB / SQL
        '/DB\s*::\s*(raw|select|statement|unprepared|insert|update|delete)\s*\(/i' => ['DB::raw', Severity::CRITICAL],
        '/\bwhereRaw\s*\(|\bselectRaw\s*\(|\borderByRaw\s*\(|\bhavingRaw\s*\(/i' => ['Raw SQL', Severity::HIGH],
        '/\bDB\s*::\s*table\s*\(.*\)\s*->\s*where/i' => ['DB query', Severity::MEDIUM],

        // Process / shell
        '/\bexec\s*\(|\bshell_exec\s*\(|\bsystem\s*\(|\bpassthru\s*\(|\bproc_open\s*\(|\bpopen\s*\(/i' => ['shell execution', Severity::CRITICAL],
        '/Process\s*::\s*run|Symfony.*Process/i' => ['Process::run', Severity::CRITICAL],

        // HTTP external
        '/Http\s*::\s*(get|post|put|patch|delete|send)\s*\(/i' => ['Http::request', Severity::MEDIUM],
        '/\bGuzzle.*request|\bCurl/i' => ['HTTP client', Severity::MEDIUM],
        '/file_get_contents\s*\(.*http/i' => ['HTTP via file_get_contents', Severity::MEDIUM],

        // Dynamic code
        '/\beval\s*\(/i' => ['eval', Severity::CRITICAL],
        '/\bcall_user_func/i' => ['call_user_func', Severity::HIGH],
        '/new\s+\$[a-zA-Z_]/' => ['dynamic class instantiation', Severity::HIGH],
        '/\$[a-zA-Z_]+\s*\(\s*\$/' => ['dynamic function call', Severity::HIGH],

        // Redirect
        '/redirect\s*\(\s*\$|Redirect\s*::\s*to\s*\(.*\$/i' => ['dynamic redirect', Severity::MEDIUM],

        // Serialization
        '/\bunserialize\s*\(/i' => ['unserialize', Severity::CRITICAL],
        '/\bserialize\s*\(/i' => ['serialize', Severity::MEDIUM],

        // Mass assignment / privileged model
        '/::\s*create\s*\(|\bupdate\s*\(.*\$request/i' => ['mass assignment', Severity::HIGH],
        '/\$fillable|\$guarded/i' => ['fillable/guarded', Severity::INFO],

        // Cache / Redis
        '/Cache\s*::\s*(put|remember|forever)\s*\(/i' => ['Cache::put', Severity::LOW],
        '/Redis\s*::/i' => ['Redis', Severity::LOW],
    ];

    /**
     * @return array{snippet:string, sink:string, severity:Severity, offset:int}[]
     */
    public static function detectInContent(string $content): array
    {
        $hits = [];
        foreach (self::SINKS as $pattern => [$sink, $severity]) {
            if (preg_match_all($pattern, $content, $m, PREG_OFFSET_CAPTURE)) {
                foreach ($m[0] as $match) {
                    $hits[] = [
                        'snippet' => trim(substr($match[0], 0, 100)),
                        'sink' => $sink,
                        'severity' => $severity,
                        'offset' => $match[1],
                    ];
                }
            }
        }
        return $hits;
    }

    public static function severityForSink(string $sink): Severity
    {
        foreach (self::SINKS as $pat => [$name, $sev]) {
            if (str_contains(strtolower($sink), strtolower($name))) return $sev;
        }
        return Severity::MEDIUM;
    }
}
