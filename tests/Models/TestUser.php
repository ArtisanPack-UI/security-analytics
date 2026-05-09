<?php

namespace Tests\Models;

use Illuminate\Foundation\Auth\User;

class TestUser extends User
{
    protected $table = 'users';

    protected $fillable = [
        'id',
        'name',
        'email',
        'password',
    ];
}
