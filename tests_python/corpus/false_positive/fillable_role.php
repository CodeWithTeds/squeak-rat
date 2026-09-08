<?php
namespace App\Models;
use Illuminate\Database\Eloquent\Model;
class User extends Model {
    protected $fillable = ['name','email','password','role','email_verified_at'];
    // Not vulnerable today: repositories force role, but flagged as hardening
}
