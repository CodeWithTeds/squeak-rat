<?php
namespace App\Http\Controllers;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Http;
class SafeProxyController {
    public function fetch(Request $request) {
        $url = $request->input('url');
        $host = parse_url($url, PHP_URL_HOST);
        $allowed = ['api.example.com', 'cdn.example.com'];
        if (!in_array($host, $allowed, true)) abort(403);
        // Also block private IPs
        if (filter_var($host, FILTER_VALIDATE_IP) && !filter_var($host, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE)) abort(403);
        return Http::get($url)->body();
    }
}
