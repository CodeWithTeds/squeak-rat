<?php
namespace App\Http\Controllers;
use Illuminate\Http\Request;
class SafeDataController {
    public function load(Request $request) {
        $data = $request->input('payload');
        // Secure: json_decode instead of unserialize
        $obj = json_decode($data, true);
        return $obj;
    }
}
