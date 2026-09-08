<?php
class FalseLiteral {
    public function foo() {
        $msg = '$request->input()'; // string literal not code
        $c = file_get_contents('/etc/hosts');
        return $c;
    }
}
