<?php
namespace App\Http\Controllers;
use Illuminate\Http\Request;
class SafeUploadController {
    public function upload(Request $request) {
        $request->validate(['file' => 'required|file|mimes:jpg,png|max:2048']);
        // Secure: store with hashed name
        $path = $request->file('file')->store('uploads', 'public');
        return $path;
    }
}
