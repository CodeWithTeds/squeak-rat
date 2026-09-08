<?php
namespace App\Http\Controllers;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
class SearchController {
    public function search(Request $request) {
        $query = $request->input('q');
        // Vulnerable: raw SQL with user input
        $results = DB::raw("SELECT * FROM users WHERE name = '$query'");
        return $results;
    }
    public function whereRawVuln(Request $request) {
        $search = $request->query('search');
        // Vulnerable whereRaw
        return DB::table('users')->whereRaw("name = '$search'")->get();
    }
}
