<?php
namespace App\Http\Controllers;
use App\Models\User;
use App\Http\Requests\StoreUserRequest;
class SafeController {
    public function store(StoreUserRequest $request) {
        // Secure: validated() is sanitized, should NOT be flagged
        User::create($request->validated());
        $data = $request->safe()->only(['name','email']);
        User::create($data);
    }
}
