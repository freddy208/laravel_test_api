<?php
namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Validator;
use Illuminate\Support\Facades\Log;
use Tymon\JWTAuth\Facades\JWTAuth;
use Tymon\JWTAuth\Exceptions\JWTException;

class AuthController extends Controller
{
    public function login(Request $request)
    {
        try {
            Log::info('Login attempt started', ['email' => $request->email]);

            $validator = Validator::make($request->all(), [
                'email' => 'required|email',
                'password' => 'required|string|min:6',
            ]);

            if ($validator->fails()) {
                Log::warning('Validation failed', $validator->errors()->toArray());
                return response()->json($validator->errors(), 422);
            }

            $credentials = $request->only(['email', 'password']);

            Log::info('Attempting authentication...');

            $token = JWTAuth::attempt($credentials);

            if (!$token) {
                Log::warning('Invalid credentials');
                return response()->json(['error' => 'Identifiants invalides'], 401);
            }

            Log::info('Token generated successfully');

            // Récupérer le TTL de manière sûre
            $ttl = 60; // Valeur par défaut
            try {
                $ttl = config('jwt.ttl', 60);
                Log::info('TTL retrieved', ['ttl' => $ttl]);
            } catch (\Exception $e) {
                Log::error('Failed to get TTL', ['error' => $e->getMessage()]);
            }

            Log::info('Preparing response...');

            $response = [
                'access_token' => $token,
                'token_type' => 'bearer',
                'expires_in' => $ttl * 60,
            ];

            Log::info('Login successful');

            return response()->json($response);

        } catch (JWTException $e) {
            Log::error('JWT Exception', [
                'message' => $e->getMessage(),
                'trace' => $e->getTraceAsString()
            ]);
            return response()->json([
                'error' => 'Impossible de créer le token',
                'details' => $e->getMessage()
            ], 500);

        } catch (\Exception $e) {
            Log::error('General Exception', [
                'message' => $e->getMessage(),
                'file' => $e->getFile(),
                'line' => $e->getLine(),
                'trace' => $e->getTraceAsString()
            ]);
            return response()->json([
                'error' => 'Erreur serveur',
                'message' => $e->getMessage(),
                'file' => $e->getFile(),
                'line' => $e->getLine(),
            ], 500);
        }
    }

    public function logout()
    {
        try {
            JWTAuth::invalidate(JWTAuth::getToken());
            return response()->json(['message' => 'Déconnexion réussie']);
        } catch (JWTException $e) {
            Log::error('Logout error', ['message' => $e->getMessage()]);
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
                'expires_in' => config('jwt.ttl', 60) * 60
            ]);
        } catch (JWTException $e) {
            Log::error('Refresh error', ['message' => $e->getMessage()]);
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
