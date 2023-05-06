<?php

namespace App\Http\Controllers;

use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;

class AuthController extends Controller
{
    public function register(Request $request){
        $fields = $request->validate([
            'name'=> 'required|string',
            'email'=> 'required|email|unique:users,email',
            'password'=> 'required|confirmed|string'
        ]);

        $user = User::create([
            'name'=> $fields['name'],
            'email'=> $fields['email'],
            'password'=> bcrypt($fields['password'])
        ]);

        $token = $user->createToken('main')->plainTextToken;
        $response = [
            'user' => $user,
            'token'=> $token
        ];

        return response($response, 201);
    }
    //login
    public function login(Request $request){
        $fields = $request->validate([
            'email'=> 'required|email',
            'password'=> 'required'
        ]);
    // check email
    $user = User::where('email', $fields['email'])->first();
    if(!$user || !Hash::check($fields['password'], $user->password)){
        return response([
            'message'=> 'wrong credentials'
        ], 401);
    }

        $token = $user->createToken('main')->plainTextToken;
        $response = [
            'user' => $user,
            'token'=> $token
        ];

        return response($response, 201);
    }
    public function logout(){
        Auth::user()->tokens()->delete();
        return [
            'message' => 'logged out'
        ];
    }

}
