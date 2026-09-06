<?php

namespace Rat\Engine\Detection;

class HiddenBehaviorAnalyzer
{
    // Precise patterns: require class definitions, not explicit Mail::send (fixes RAT-001/002 false hidden)
    public const PATTERNS = [
        'observer' => '/class\s+\w+Observer\b|::observe\s*\(\s*\w+Observer::class/i',
        'event' => '/class\s+\w+Event\b|Event\s*::\s*dispatch/i',
        'listener' => '/class\s+\w+Listener\b/i',
        'job' => '/class\s+\w+Job\b.*ShouldQueue|dispatch\s*\(\s*new\s+\w+Job/i',
        'notification' => '/class\s+\w+Notification\b/i',
        'mail' => '/class\s+\w+Mailable\b/i',
        'model_event' => '/::\s*created\b|::\s*updated\b|::\s*saved\b|::\s*deleted\b|booted|observe\s*\(/i',
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
