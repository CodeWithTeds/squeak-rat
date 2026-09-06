<?php

namespace Rat\Support;

use Symfony\Component\Console\Output\OutputInterface;

/**
 * Terminal image renderer.
 *
 * Tries modern terminal graphics protocols first, then falls back to ASCII.
 * Supports:
 *  - iTerm2 inline images (OSC 1337)
 *  - Kitty graphics protocol
 *  - Sixel (via imgcat-like fallback)
 *  - Braille / ASCII via GD
 */
class TerminalImage
{
    /**
     * Render image at given path inline in terminal if possible.
     *
     * @param string $path Absolute path to PNG/JPG
     * @param int $width Desired display width in terminal cells (approx)
     * @param int $height Desired display height in terminal cells
     */
    public static function render(string $path, OutputInterface $output, int $width = 34, int $height = 18): bool
    {
        if (! file_exists($path) || ! is_readable($path)) {
            return false;
        }

        // If explicitly disabled
        if (getenv('RAT_NO_IMAGE') || getenv('NO_IMAGE')) {
            return false;
        }

        // Respect --no-image via $_SERVER
        if (isset($_SERVER['RAT_NO_IMAGE'])) {
            return false;
        }

        // Try iTerm2 / WezTerm / VSCode inline image protocol first.
        // This is widely supported: iTerm2, WezTerm, VSCode terminal, Tabby, etc.
        if (self::supportsInlineImages()) {
            try {
                $data = base64_encode((string) file_get_contents($path));
                $filename = basename($path);
                $size = filesize($path);

                // OSC 1337;File=name=...;size=...;inline=1:... BEL
                // Also preserve aspect ratio; terminal will scale.
                $seq = sprintf(
                    "\033]1337;File=name=%s;size=%d;inline=1;width=%dpx;height=%dpx;preserveAspectRatio=1:%s\007",
                    base64_encode($filename),
                    $size,
                    $width * 8,
                    $height * 16,
                    $data
                );

                // Kitty protocol fallback — many terminals ignore unknown sequences safely.
                // We send iTerm2 sequence; it's harmless if not supported.
                $output->write($seq . PHP_EOL);

                // Also send Kitty graphics protocol for Kitty / Ghostty users
                // ESC _G a=T,f=100,t=d... ESC \
                // We intentionally keep it simple: base64 already encoded above is PNG, kitty wants base64 too.
                // Only send if TERM indicates kitty/ghostty to avoid noise.
                $term = (string) (getenv('TERM') ?: '');
                $termProgram = (string) (getenv('TERM_PROGRAM') ?: '');
                if (str_contains($term, 'kitty') || str_contains($termProgram, 'ghostty') || str_contains($termProgram, 'kitty')) {
                    $kitty = "\033_Ga=T,f=100,m=1;" . $data . "\033\\";
                    $output->write($kitty . PHP_EOL);
                }

                return true;
            } catch (\Throwable $e) {
                // fall through to ASCII
            }
        }

        // Fallback to ASCII/Braille rendering via GD
        return self::renderAscii($path, $output, $width);
    }

    public static function supportsInlineImages(): bool
    {
        // Check explicit enable
        if (getenv('RAT_FORCE_IMAGE') === '1') {
            return true;
        }

        // No image if output is piped / non-tty
        if (! self::isTty()) {
            // Still allow if user forces, otherwise don't spam pipe with binary escape
            return false;
        }

        $term = (string) (getenv('TERM') ?: '');
        $termProgram = (string) (getenv('TERM_PROGRAM') ?: '');
        $colorterm = (string) (getenv('COLORTERM') ?: '');
        $insideTmux = getenv('TMUX') !== false;

        // Known supporters
        $supporters = ['iTerm.app', 'WezTerm', 'vscode', 'Tabby', 'Hyper', 'mintty'];

        foreach ($supporters as $s) {
            if (stripos($termProgram, $s) !== false) {
                return true;
            }
        }

        // VSCode
        if (getenv('VSCODE_INJECTION') !== false || getenv('VSCODE_PID') !== false) {
            return true;
        }

        // WezTerm sets TERM_PROGRAM=WezTerm, Ghostty, Kitty
        if (str_contains($term, 'xterm-kitty') || str_contains($term, 'ghostty') || str_contains($termProgram, 'ghostty')) {
            return true;
        }

        // Modern terminals often set COLORTERM=truecolor and support it reasonably
        // Be conservative: only claim support for known programs + if RAT_FORCE_IMAGE
        // For unknown terminals, prefer ASCII to avoid garbage.
        if ($insideTmux) {
            // tmux passthrough can work but noisy — allow only if TERM_PROGRAM known
            return false;
        }

        return false;
    }

    private static function isTty(): bool
    {
        if (function_exists('posix_isatty')) {
            return @posix_isatty(STDOUT);
        }
        // stream_isatty available PHP 7.2+
        if (function_exists('stream_isatty')) {
            return @stream_isatty(STDOUT);
        }
        return true;
    }

    /**
     * Render PNG as colored ASCII/Unicode blocks using GD.
     * Uses half-block technique (▀) for doubled vertical resolution + truecolor if supported.
     */
    public static function renderAscii(string $path, OutputInterface $output, int $targetWidth = 36): bool
    {
        if (! extension_loaded('gd')) {
            return false;
        }

        $info = @getimagesize($path);
        if ($info === false) {
            return false;
        }

        $src = null;
        $ext = strtolower(pathinfo($path, PATHINFO_EXTENSION));
        try {
            if ($ext === 'png') {
                $src = @imagecreatefrompng($path);
            } elseif ($ext === 'jpg' || $ext === 'jpeg') {
                $src = @imagecreatefromjpeg($path);
            } else {
                $src = @imagecreatefromstring((string) file_get_contents($path));
            }
        } catch (\Throwable $e) {
            return false;
        }

        if (! $src) {
            return false;
        }

        $srcW = imagesx($src);
        $srcH = imagesy($src);

        // Preserve aspect: terminal cells are ~2x taller than wide, so compensate.
        // Half-block mode uses 1 char = 2 vertical pixels, so aspect ~ 1:1 roughly.
        $aspect = $srcH / $srcW;
        $targetHeight = (int) round($targetWidth * $aspect * 0.52); // 0.5 ~ char aspect
        $targetHeight = max(12, min(28, $targetHeight));
        $targetWidth = max(28, min(48, $targetWidth));

        $tmp = imagecreatetruecolor($targetWidth, $targetHeight * 2);
        // Fill with transparent bg converted to dark
        $bg = imagecolorallocate($tmp, 18, 18, 22);
        imagefill($tmp, 0, 0, $bg);
        // Preserve alpha
        imagealphablending($tmp, true);
        imagesavealpha($tmp, true);

        // Resize with resampling
        imagecopyresampled($tmp, $src, 0, 0, 0, 0, $targetWidth, $targetHeight * 2, $srcW, $srcH);
        imagedestroy($src);

        // Build output line by line using upper half + lower half -> ▀ with two colors
        // If output does not support truecolor, fall back to grayscale ASCII.
        $supportsTrueColor = self::supportsTrueColor();

        $lines = [];
        for ($y = 0; $y < $targetHeight; $y++) {
            $line = '';
            for ($x = 0; $x < $targetWidth; $x++) {
                $rgbTop = imagecolorat($tmp, $x, $y * 2);
                $r1 = ($rgbTop >> 16) & 0xFF;
                $g1 = ($rgbTop >> 8) & 0xFF;
                $b1 = $rgbTop & 0xFF;
                $a1 = ($rgbTop >> 24) & 0x7F;

                $rgbBot = imagecolorat($tmp, $x, $y * 2 + 1);
                $r2 = ($rgbBot >> 16) & 0xFF;
                $g2 = ($rgbBot >> 8) & 0xFF;
                $b2 = $rgbBot & 0xFF;
                $a2 = ($rgbBot >> 24) & 0x7F;

                // If highly transparent, treat as background
                if ($a1 > 100) {
                    $r1 = 18; $g1 = 18; $b1 = 22;
                }
                if ($a2 > 100) {
                    $r2 = 18; $g2 = 18; $b2 = 22;
                }

                // Luma check for near-black bg optimization: avoid painting bg char
                $isBgTop = $r1 < 25 && $g1 < 25 && $b1 < 30;
                $isBgBot = $r2 < 25 && $g2 < 25 && $b2 < 30;

                if ($supportsTrueColor) {
                    if ($isBgTop && $isBgBot) {
                        $line .= ' ';
                    } elseif ($isBgTop) {
                        // bottom pixel only: use lower half block ▄
                        $line .= sprintf("\033[38;2;%d;%d;%dm▄\033[0m", $r2, $g2, $b2);
                    } elseif ($isBgBot) {
                        $line .= sprintf("\033[38;2;%d;%d;%dm▀\033[0m", $r1, $g1, $b1);
                    } else {
                        // both colored: foreground = top, background = bottom using ▀
                        $line .= sprintf("\033[38;2;%d;%d;%d;48;2;%d;%d;%dm▀\033[0m", $r1, $g1, $b1, $r2, $g2, $b2);
                    }
                } else {
                    // Grayscale ASCII fallback — map brightness to chars
                    $lum = (0.2126 * $r1 + 0.7152 * $g1 + 0.0722 * $b1 + 0.2126 * $r2 + 0.7152 * $g2 + 0.0722 * $b2) / 2;
                    $chars = ' .,:;!+*%#@';
                    $idx = (int) round(($lum / 255) * (strlen($chars) - 1));
                    $c = $chars[$idx] ?? ' ';
                    // Use dim for dark
                    $line .= $c;
                }
            }
            // Trim trailing spaces for cleaner copy-paste
            $lines[] = rtrim($line) . "\033[0m";
        }

        imagedestroy($tmp);

        foreach ($lines as $l) {
            $output->writeln($l);
        }

        return true;
    }

    private static function supportsTrueColor(): bool
    {
        $ct = strtolower((string) getenv('COLORTERM'));
        if (str_contains($ct, 'truecolor') || str_contains($ct, '24bit')) {
            return true;
        }
        $term = strtolower((string) getenv('TERM'));
        if (str_contains($term, 'truecolor') || str_contains($term, '24bit') || str_contains($term, 'xterm-256color')) {
            return true;
        }
        // Assume modern terminals do
        return true;
    }

    /**
     * Detect best inline method and return name.
     */
    public static function probe(OutputInterface $output): string
    {
        if (self::supportsInlineImages()) {
            return 'iterm2-inline';
        }
        if (extension_loaded('gd')) {
            return 'half-block-truecolor';
        }
        return 'none';
    }
}
