<?php

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;
use App\Models\User;
use Illuminate\Support\Facades\Hash;
use Illuminate\Validation\ValidationException;


// Login API
Route::post('/login', function (Request $request) {
    try {
        $validated = $request->validate([
            'email' => 'required|email',
            'password' => 'required',
        ]);
    } catch (\Illuminate\Validation\ValidationException $e) {
        return response()->json(['message' => $e->validator->errors()->first()], 400);
    }

    $user = User::where('email', $request->email)->first();

    if (! $user || ! Hash::check($request->password, $user->password)) {
        throw ValidationException::withMessages([
            'email' => ['The provided credentials are incorrect.'],
        ]);
    }

    return response()->json([
        'token' => $user->createToken('auth-token')->plainTextToken
    ]);
});


// Logout API
Route::middleware('auth:sanctum')->post('/logout', function (Request $request) {
    $request->user()->tokens()->delete();
    return response()->json(['message' => 'Logged out']);
});


// Get User Info
Route::middleware('auth:sanctum')->get('/user', function (Request $request) {
    return response()->json($request->user());
});


// Register API
Route::post('/register', function (Request $request) {
    //return response()->json($request->all());

    try {
        $validated = $request->validate([
            'name' => 'required',
            'email' => 'required|email|unique:users',
            'password' => 'required|min:6',
        ]);
    } catch (\Illuminate\Validation\ValidationException $e) {
        return response()->json(['message' => $e->validator->errors()->first()], 400);
    }

    try {
        $user = User::create([
            'name' => $request->name,
            'email' => $request->email,
            'password' => Hash::make($request->password),
        ]);
    } catch (\Illuminate\Database\QueryException $e) {
        return response()->json(['message' => 'User already registered'], 409);
    }

    return response()->json([
        'token' => $user->createToken('auth-token')->plainTextToken
    ]);
});

