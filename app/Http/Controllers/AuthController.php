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
        try {
            $validator = Validator::make($request->all(), [
                'email' => 'required|email',
                'password' => 'required|string|min:6',
            ]);

            if ($validator->fails()) {
                return response()->json($validator->errors(), 422);
            }

            $credentials = $request->only(['email', 'password']);

            $token = JWTAuth::attempt($credentials);

            if (!$token) {
                return response()->json(['error' => 'Identifiants invalides'], 401);
            }

            // Retour simplifié sans appel à config()
            return response()->json([
                'access_token' => $token,
                'token_type' => 'bearer',
                'expires_in' => 3600,
            ]);

        } catch (JWTException $e) {
            return response()->json([
                'error' => 'Erreur JWT',
                'message' => $e->getMessage()
            ], 500);

        } catch (\Exception $e) {
            return response()->json([
                'error' => 'Erreur serveur',
                'message' => $e->getMessage(),
            ], 500);
        }
    }

    public function logout()
    {
        try {
            JWTAuth::invalidate(JWTAuth::getToken());
            return response()->json(['message' => 'Déconnexion réussie']);
        } catch (JWTException $e) {
            return response()->json(['error' => 'Erreur lors de la déconnexion'], 500);
        }
    }

    public function refresh()
    {
        try {
            $newToken = JWTAuth::refresh(JWTAuth::getToken());
            return response()->json([
                'access_token' => $newToken,
                'token_type' => 'bearer',
                'expires_in' => 3600
            ]);
        } catch (JWTException $e) {
            return response()->json(['error' => 'Impossible de rafraîchir le token'], 500);
        }
    }

    public function protege()
    {
        return response()->json([
            'message' => 'Test API Protégée (Laravel JWT)',
        ]);
    }
}
