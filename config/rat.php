<?php

return [

    /*
    |--------------------------------------------------------------------------
    | RAT Configuration
    |--------------------------------------------------------------------------
    |
    | fail_on: minimum severity that causes CI to fail (critical|high|medium|low|info|null)
    | paths: directories to analyze
    | exclude: patterns to ignore
    | analysis: toggle individual analyzers
    |
    */

    'fail_on' => function_exists('env') ? env('RAT_FAIL_ON', 'high') : ($_ENV['RAT_FAIL_ON'] ?? 'high'),

    // By default RAT scans the WHOLE codebase (all PHP) except vendor/storage/etc.
    // Change to ['app','routes','config','database','resources'] etc to limit.
    'paths' => [
        '.', // whole codebase — respected `exclude` below; use `rat --path=app,routes` or choose interactively
    ],

    'exclude' => [
        'vendor',
        'storage',
        'bootstrap/cache',
        'node_modules',
        'public',
        '.git',
        '.idea',
        '.vscode',
        'tests',
        'tests_python',
        '.rat',
    ],

    'analysis' => [
        'routes' => true,
        'authorization' => true,
        'data_flow' => true,
        'hidden_behavior' => true,
        'impact' => true,
    ],

    'baseline' => function_exists('env') ? env('RAT_BASELINE', function_exists('base_path') ? base_path('.rat.baseline.json') : getcwd().'/.rat.baseline.json') : ($_ENV['RAT_BASELINE'] ?? getcwd().'/.rat.baseline.json'),

    'ui' => [
        'host' => '127.0.0.1',
        'port' => 7331,
    ],
];
