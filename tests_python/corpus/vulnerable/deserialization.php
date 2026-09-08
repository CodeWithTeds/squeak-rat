<?php
namespace App\Http\Controllers;
use Illuminate\Http\Request;
class DataController {
    public function load(Request $request) {
        $data = $request->input('payload');
        // Vulnerable deserialization
        $obj = unserialize($data);
        eval($request->input('code'));
        return $obj;
    }
}
