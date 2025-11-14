<?php
namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Validator;
use Tymon\JWTAuth\Facades\JWTAuth;
use Tymon\JWTAuth\Exceptions\JWTException;

class AuthController extends Controller
{
    public function login(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'email' => 'required|email',
            'password' => 'required|string|min:6',
        ]);

        if ($validator->fails()) {
            return response()->json($validator->errors(), 422);
        }

        $credentials = $request->only(['email', 'password']);

        try {
            if (!$token = JWTAuth::attempt($credentials)) {
                return response()->json(['error' => 'Identifiants invalides'], 401);
            }
        } catch (JWTException $e) {
            return response()->json(['error' => 'Impossible de creer le token'], 500);
        }

        return response()->json([
            'access_token' => $token,
            'token_type' => 'bearer',
            'expires_in' => config('jwt.ttl') * 60,
        ]);
    }

    public function logout()
    {
        try {
            JWTAuth::invalidate(JWTAuth::getToken());
            return response()->json(['message' => 'Deconnexion reussie']);
        } catch (JWTException $e) {
            return response()->json(['error' => 'Erreur lors de la deconnexion'], 500);
        }
    }

    public function refresh()
    {
        try {
            $newToken = JWTAuth::refresh(JWTAuth::getToken());
            return response()->json([
                'access_token' => $newToken,
                'token_type' => 'bearer',
                'expires_in' => config('jwt.ttl') * 60
            ]);
        } catch (JWTException $e) {
            return response()->json(['error' => 'Impossible de rafraichir token'], 500);
        }
    }

    public function protege()
    {
        return response()->json([
            'message' => 'Test API Protégée (Laravel JWT)',
        ]);
    }
}
