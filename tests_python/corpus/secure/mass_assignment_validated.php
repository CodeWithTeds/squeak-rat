<?php
namespace App\Http\Controllers;
use App\Models\User;
use Illuminate\Http\Request;
use App\Http\Requests\StoreUserRequest;
class SafeUserController {
    public function store(StoreUserRequest $request) {
        // Secure: validated + only
        User::create($request->validated());
        // Or
        User::create($request->only(['name', 'email', 'password']));
    }
}
