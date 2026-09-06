<?php

namespace Rat\Engine\Detection;

class HiddenBehaviorAnalyzer
{
    public const PATTERNS = [
        'observer' => '/Observer/i',
        'event' => '/event\s*\(|Event\s*::\s*dispatch|dispatch\s*\(.*Event/i',
        'listener' => '/Listener/i',
        'job' => '/dispatch\s*\(|Dispatchable|ShouldQueue|Job/i',
        'notification' => '/Notification|->\s*notify\s*\(/i',
        'mail' => '/Mailable|Mail\s*::/i',
        'model_event' => '/::\s*created|::\s*updated|::\s*saved|::\s*deleted|booted|observe/i',
    ];

    /**
     * @return array<string, string[]> detected behaviors keyed by type
     */
    public static function analyze(string $content): array
    {
        $found = [];
        foreach (self::PATTERNS as $type => $pat) {
            if (preg_match_all($pat, $content, $m)) {
                $found[$type] = array_unique($m[0]);
            }
        }
        return $found;
    }

    public static function hasHiddenBehavior(string $content): bool
    {
        return ! empty(self::analyze($content));
    }
}
