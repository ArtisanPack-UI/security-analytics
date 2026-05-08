<?php

declare(strict_types=1);

use ArtisanPackUI\SecurityAnalytics\Http\Controllers\SecurityDashboardController;
use Illuminate\Support\Facades\Route;

Route::group([
    'prefix' => config('artisanpack.security-analytics.dashboard.prefix', 'security/analytics'),
    'middleware' => config('artisanpack.security-analytics.dashboard.middleware', ['web', 'auth']),
    'as' => 'security.analytics.',
], function () {
    Route::get('/', [SecurityDashboardController::class, 'index'])->name('index');
    Route::get('/summary', [SecurityDashboardController::class, 'summary'])->name('summary');
    Route::get('/events/live', [SecurityDashboardController::class, 'liveEvents'])->name('events.live');
    Route::get('/metrics', [SecurityDashboardController::class, 'metrics'])->name('metrics');
    Route::get('/threats', [SecurityDashboardController::class, 'threats'])->name('threats');
    Route::get('/geographic', [SecurityDashboardController::class, 'geographic'])->name('geographic');
    Route::get('/timeline', [SecurityDashboardController::class, 'timeline'])->name('timeline');
    Route::get('/anomalies', [SecurityDashboardController::class, 'anomalyStats'])->name('anomalies');
    Route::get('/incidents', [SecurityDashboardController::class, 'incidents'])->name('incidents');
    Route::post('/alerts/{alert}/acknowledge', [SecurityDashboardController::class, 'acknowledgeAlert'])->name('alerts.acknowledge');
});
