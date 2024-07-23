<?php

use App\Http\Controllers\ProfileController;
use App\Http\Controllers\Saml2Controller;
use Illuminate\Support\Facades\Route;

/*
|--------------------------------------------------------------------------
| Web Routes
|--------------------------------------------------------------------------
|
| Here is where you can register web routes for your application. These
| routes are loaded by the RouteServiceProvider and all of them will
| be assigned to the "web" middleware group. Make something great!
|
*/

Route::get('/', function () {
    return view('welcome');
});

Route::get('/dashboard', function () {
    return view('dashboard');
})->middleware(['auth', 'verified'])->name('dashboard');

Route::middleware('auth')->group(function () {
    Route::get('/profile', [ProfileController::class, 'edit'])->name('profile.edit');
    Route::patch('/profile', [ProfileController::class, 'update'])->name('profile.update');
    Route::delete('/profile', [ProfileController::class, 'destroy'])->name('profile.destroy');
});

Route::get('/saml2/metadata', [Saml2Controller::class, 'metadata'])->name('sp.metadata');
Route::post('/saml2/acs', [Saml2Controller::class, 'acs'])->name('sp.acs');
Route::get('/saml2/slo', [Saml2Controller::class, 'slo'])->name('sp.slo');
Route::get('/saml2/login', [Saml2Controller::class, 'login'])->name('login-sso');

require __DIR__.'/auth.php';
