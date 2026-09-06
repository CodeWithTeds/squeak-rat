<?php

namespace Rat\Engine\Detection;

class AuthorizationAnalyzer
{
    public const AUTH_PATTERNS = [
        '/->\s*authorize\s*\(/i',
        '/\$this\s*->\s*authorize/i',
        '/Gate\s*::\s*(allows|denies|authorize)/i',
        '/\$user\s*->\s*can\s*\(/i',
        '/can\s*:\s*/i', // middleware can:xxx
        '/middleware\s*\(\s*[\'"]can:/i',
        '/middleware\s*\(\s*[\'"]auth/i',
        '/auth\s*:\s*/i',
        '/->\s*middleware\s*\(.*auth/i',
        '/Policy/i',
        '/\$request\s*->\s*user\s*\(/i',
        '/Auth\s*::/i',
    ];

    public const SENSITIVE_OPERATIONS = [
        '/::\s*update\s*\(/i',
        '/::\s*delete\s*\(/i',
        '/::\s*create\s*\(/i',
        '/User\s*::/i',
        '/->\s*delete\s*\(/i',
        '/admin/i',
    ];

    public static function hasAuthorization(string $content): bool
    {
        foreach (self::AUTH_PATTERNS as $pat) {
            if (preg_match($pat, $content)) return true;
        }
        return false;
    }

    public static function isSensitive(string $content): bool
    {
        foreach (self::SENSITIVE_OPERATIONS as $pat) {
            if (preg_match($pat, $content)) return true;
        }
        return false;
    }

    /**
     * @return string[] reasons
     */
    public static function analyzeFile(string $filePath, string $content): array
    {
        $issues = [];
        if (self::isSensitive($content) && ! self::hasAuthorization($content)) {
            $issues[] = 'No obvious policy / gate / authorization middleware was discovered in the analyzed path.';
        }
        // Check route file correlation would be done at graph level; this is file-level fallback
        return $issues;
    }
}
