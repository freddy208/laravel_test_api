<?php
use Illuminate\Support\Facades\Route;
use App\Http\Controllers\AuthController;

Route::post('/login', [AuthController::class, 'login']);
Route::middleware('auth:api')->post('/logout', [AuthController::class, 'logout']);
Route::middleware('auth:api')->get('/protege', [AuthController::class, 'protege']);
?>
