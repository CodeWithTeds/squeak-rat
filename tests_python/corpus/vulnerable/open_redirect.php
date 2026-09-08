<?php
namespace App\Http\Controllers;
use Illuminate\Http\Request;
class RedirectController {
    public function go(Request $request) {
        $url = $request->input('next');
        // Vulnerable open redirect
        return redirect($url);
    }
}
