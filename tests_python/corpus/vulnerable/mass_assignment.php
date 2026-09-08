<?php
namespace App\Http\Controllers;
use App\Models\User;
use Illuminate\Http\Request;
class UserController {
    public function store(Request $request) {
        // Vulnerable mass assignment
        User::create($request->all());
    }
    public function update(Request $request, $id) {
        $user = User::find($id);
        $user->update($request->all());
    }
}
