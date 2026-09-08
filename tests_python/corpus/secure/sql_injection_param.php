<?php
namespace App\Http\Controllers;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
class SafeSearchController {
    public function search(Request $request) {
        $query = $request->input('q');
        // Secure: parameterized
        $results = DB::select('SELECT * FROM users WHERE name = ?', [$query]);
        // Or Eloquent
        return DB::table('users')->where('name', $query)->get();
    }
}
