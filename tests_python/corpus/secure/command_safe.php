<?php
namespace App\Http\Controllers;
use Illuminate\Http\Request;
use Symfony\Component\Process\Process;
class SafeFileController {
    public function list(Request $request) {
        $dir = $request->input('dir');
        // Secure: allow-list and escapeshellarg
        $allowed = ['/tmp', '/var/log'];
        if (!in_array($dir, $allowed, true)) abort(403);
        $safe = escapeshellarg($dir);
        // Better: use Process with array
        $process = new Process(['ls', $dir]);
        $process->run();
        return $process->getOutput();
    }
}
