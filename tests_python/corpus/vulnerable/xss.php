<?php
namespace App\Http\Controllers;
use Illuminate\Http\Request;
class CommentController {
    public function show(Request $request) {
        $comment = $request->input('comment');
        // Vulnerable: unescaped output
        echo $comment;
        return response("<div>" . $comment . "</div>");
    }
    public function bladeUnescaped(Request $request) {
        $name = $request->input('name');
        // Simulate Blade {!! !!}
        return "{!! \$name !!}"; // in real Blade would be {!! $name !!}
    }
}
