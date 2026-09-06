<?php

namespace Rat\Engine\Reporters;

use Rat\Engine\Findings\Finding;

class JsonReporter implements Reporter
{
    public function report(array $findings, array $stats, array $options = []): string
    {
        $payload = [
            'tool' => 'RAT',
            'version' => '1.0.0',
            'tagline' => 'RAT follows the trail.',
            'stats' => $stats,
            'findings' => array_map(fn(Finding $f) => $f->toArray(), $findings),
        ];
        $flags = JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE;
        return json_encode($payload, $flags) . PHP_EOL;
    }

    public function ndjson(array $findings): string
    {
        $out = '';
        foreach ($findings as $f) {
            $out .= json_encode($f->toArray(), JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE) . PHP_EOL;
        }
        return $out;
    }
}
