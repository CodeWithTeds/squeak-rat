<?php
namespace App\Http\Controllers;
use Illuminate\Http\Request;
class SafeCommentController {
    public function show(Request $request) {
        $comment = $request->input('comment');
        // Secure: escaped
        return view('comment', ['comment' => e($comment)]);
        // Blade uses {{ $comment }} which is escaped
    }
}
