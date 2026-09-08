<?php
namespace App\Http\Controllers;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Storage;
class UploadController {
    public function upload(Request $request) {
        $filename = $request->input('filename');
        $content = $request->input('content');
        // Vulnerable path traversal
        Storage::put($filename, $content);
        file_put_contents("/tmp/" . $filename, $content);
        return "ok";
    }
}
