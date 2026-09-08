<?php
namespace App\Http\Controllers;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Http;
class ProxyController {
    public function fetch(Request $request) {
        $url = $request->input('url');
        // Vulnerable SSRF
        $resp = Http::get($url);
        return $resp->body();
    }
}
