<?php

namespace Rat;

use Illuminate\Support\ServiceProvider;
use Rat\Console\Commands\RatCommand;
use Rat\Console\Commands\RatScanCommand;
use Rat\Console\Commands\RatShowCommand;
use Rat\Console\Commands\RatWhyCommand;
use Rat\Console\Commands\RatFlowCommand;
use Rat\Console\Commands\RatImpactCommand;
use Rat\Console\Commands\RatBaselineCommand;
use Rat\Console\Commands\RatUiCommand;

class RatServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->mergeConfigFrom(__DIR__ . '/../config/rat.php', 'rat');
    }

    public function boot(): void
    {
        // Publish config
        $this->publishes([
            __DIR__ . '/../config/rat.php' => config_path('rat.php'),
        ], 'rat-config');

        // Publish rat.png for custom banner overrides
        $this->publishes([
            dirname(__DIR__) . '/rat.png' => public_path('rat.png'),
        ], 'rat-assets');

        if ($this->app->runningInConsole()) {
            $this->commands([
                RatCommand::class,
                RatScanCommand::class,
                RatShowCommand::class,
                RatWhyCommand::class,
                RatFlowCommand::class,
                RatImpactCommand::class,
                RatBaselineCommand::class,
                RatUiCommand::class,
            ]);
        }
    }
}
