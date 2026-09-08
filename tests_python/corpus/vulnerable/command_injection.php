<?php
namespace App\Http\Controllers;
use Illuminate\Http\Request;
class FileController {
    public function download(Request $request) {
        $file = $request->input('file');
        // Vulnerable command injection
        $out = shell_exec("cat " . $file);
        exec("ls " . $request->input('dir'));
        return $out;
    }
}
