<?php

namespace Rat\Support;

use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Console\Formatter\OutputFormatterStyle;

class RatBanner
{
    /** @var string Absolute path to rat.png distributed with package */
    public const IMAGE_PATH_CANDIDATES = [
        __DIR__ . '/../../rat.png',
        __DIR__ . '/../../resources/rat.png',
    ];

    public static function imagePath(): ?string
    {
        foreach (self::IMAGE_PATH_CANDIDATES as $p) {
            $real = realpath($p);
            if ($real && file_exists($real)) {
                return $real;
            }
        }
        // Also check project root /Applications/.../rat/rat.png when developing
        $dev = dirname(__DIR__, 2) . '/rat.png';
        if (file_exists($dev)) {
            return $dev;
        }
        return null;
    }

    public static function render(OutputInterface $output, bool $withImage = true, bool $compact = false): void
    {
        // Define styles if not already — VIOLET console theme
        $formatter = $output->getFormatter();
        if (! $formatter->hasStyle('rat')) {
            $formatter->setStyle('rat', new OutputFormatterStyle('#8b5cf6', null, ['bold'])); // violet
        }
        if (! $formatter->hasStyle('rat-dim')) {
            $formatter->setStyle('rat-dim', new OutputFormatterStyle('#a78bfa', null, [])); // violet dim
        }
        if (! $formatter->hasStyle('rat-accent')) {
            $formatter->setStyle('rat-accent', new OutputFormatterStyle('#7c3aed', null, ['bold'])); // violet accent
        }
        if (! $formatter->hasStyle('violet')) {
            $formatter->setStyle('violet', new OutputFormatterStyle('#8b5cf6', null, ['bold']));
        }

        $imageShown = false;

        if ($withImage && ! $compact) {
            $path = self::imagePath();
            if ($path) {
                // --no-image / env disables image entirely
                $disabled = getenv('RAT_NO_IMAGE') || getenv('NO_IMAGE') || isset($_SERVER['RAT_NO_IMAGE']);
                if (! $disabled) {
                    // 1) Try iTerm2/VSCode/WezTerm inline image (best quality where supported)
                    $inlineShown = false;
                    if (TerminalImage::supportsInlineImages()) {
                        // Use TerminalImage::render which sends OSC 1337 inline; harmless on non-supporting terms
                        $inlineShown = TerminalImage::render($path, $output, 36, 18);
                        // TerminalImage::render already falls back to ASCII if inline not supported,
                        // but to guarantee visibility we ALWAYS render ASCII true-color as well
                        if ($inlineShown) {
                            // Inline succeeded — still render ASCII underneath for guaranteed visibility
                            // (supporting terminals show both; plain terminals show at least ASCII)
                            $output->writeln('');
                        }
                    }
                    // 2) Always render true-color half-block ASCII of rat.png for reliable visibility
                    // This is the "use this image like ..." requirement — rat.png visible in ANY terminal with GD
                    $asciiShown = TerminalImage::renderAscii($path, $output, 36);
                    if ($asciiShown) {
                        $output->writeln('');
                        $imageShown = true;
                    } else {
                        $imageShown = $inlineShown;
                    }
                }
            }
        }

        // If image was NOT shown (GD missing, no file, or disabled), show polished VIOLET block-letter fallback header
        if (! $imageShown && ! $compact) {
            // Block-letter RAT — VIOLET theme
            $output->writeln('<fg=#8b5cf6;options=bold>  ██████╗  █████╗ ████████╗</>');
            $output->writeln('<fg=#8b5cf6;options=bold>  ██╔══██╗██╔══██╗╚══██╔══╝</>  <fg=#a78bfa;options=bold>🐀 RAT</> <fg=gray>— Laravel Security & Behavior Analyzer</>');
            $output->writeln('<fg=#8b5cf6;options=bold>  ██████╔╝███████║   ██║</>     <fg=#a78bfa>RAT follows the trail.</>');
            $output->writeln('<fg=#8b5cf6;options=bold>  ██╔══██╗██╔══██║   ██║</>');
            $output->writeln('<fg=#8b5cf6;options=bold>  ██║  ██║██║  ██║   ██║</>');
            $output->writeln('<fg=#8b5cf6;options=bold>  ╚═╝  ╚═╝╚═╝  ╚═╝   ╚═╝</>');
        } elseif ($compact) {
            // Compact single-line for --json or minimal views — VIOLET
            $output->writeln('<fg=#8b5cf6;options=bold>🐀 RAT</> <fg=gray>Laravel Application Security & Behavior Analyzer</>');
        } else {
            // Image WAS shown — still print wordmark beneath for context — VIOLET
            $output->writeln('<fg=#a78bfa;options=bold>🐀 RAT</> <fg=gray>— Laravel Security & Behavior Analyzer</>  <fg=#7c3aed>•</> <fg=gray>RAT follows the trail.</>');
        }

        if (! $compact) {
            $output->writeln(sprintf('  <fg=#7c3aed>%s</>', str_repeat('─', 58)));
        }
    }

    public static function renderPlain(): string
    {
        // For --format=json or plain text pipe capture
        return "🐀 RAT — Laravel Application Security & Behavior Analyzer (RAT follows the trail.)";
    }
}
