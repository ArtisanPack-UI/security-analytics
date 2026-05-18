<?php

declare(strict_types=1);

use ArtisanPackUI\SecurityAnalytics\Http\Controllers\SecurityDashboardController;
use Illuminate\Support\Facades\Route;

/*
|--------------------------------------------------------------------------
| Security Analytics Dashboard Routes
|--------------------------------------------------------------------------
|
| Two route groups:
|   1. JSON API endpoints — always loaded; no Livewire dependency. Data
|      feeds the bundled UI plus any external consumer that wants to drive
|      its own dashboard.
|   2. Livewire UI pages — only registered when Livewire is installed.
|
| Both groups respect the same `artisanpack.security-analytics.dashboard.*`
| config so consumers can disable the dashboard wholesale, change the
| prefix, or swap the middleware (e.g. add `auth` or a custom guard).
|
*/

if ( ! config( 'artisanpack.security-analytics.dashboard.enabled', true ) ) {
    return;
}

$middleware = config( 'artisanpack.security-analytics.dashboard.middleware', ['web', 'auth'] );

// --- JSON API endpoints (always available) ---------------------------------
$apiPrefix = config( 'artisanpack.security-analytics.dashboard.apiPrefix', 'security/analytics' );

Route::middleware( $middleware )
    ->prefix( $apiPrefix )
    ->name( 'security.analytics.' )
    ->group( function (): void {
        Route::get( '/', [SecurityDashboardController::class, 'index'] )->name( 'index' );
        Route::get( '/summary', [SecurityDashboardController::class, 'summary'] )->name( 'summary' );
        Route::get( '/events/live', [SecurityDashboardController::class, 'liveEvents'] )->name( 'events.live' );
        Route::get( '/metrics', [SecurityDashboardController::class, 'metrics'] )->name( 'metrics' );
        Route::get( '/threats', [SecurityDashboardController::class, 'threats'] )->name( 'threats' );
        Route::get( '/geographic', [SecurityDashboardController::class, 'geographic'] )->name( 'geographic' );
        Route::get( '/timeline', [SecurityDashboardController::class, 'timeline'] )->name( 'timeline' );
        Route::get( '/anomalies', [SecurityDashboardController::class, 'anomalyStats'] )->name( 'anomalies' );
        Route::get( '/incidents', [SecurityDashboardController::class, 'incidents'] )->name( 'incidents' );
        Route::post( '/alerts/{alert}/acknowledge', [SecurityDashboardController::class, 'acknowledgeAlert'] )->name( 'alerts.acknowledge' );
    } );

// --- Livewire UI pages (only when Livewire is installed) -------------------
if ( class_exists( \Livewire\Component::class ) ) {
    $uiPrefix = config( 'artisanpack.security-analytics.dashboard.routePrefix', 'security' );

    Route::middleware( $middleware )
        ->prefix( $uiPrefix )
        ->name( 'security.' )
        ->group( function (): void {
            Route::get( '/dashboard', \ArtisanPackUI\SecurityAnalytics\Livewire\SecurityDashboard::class )->name( 'dashboard' );
            Route::get( '/events', \ArtisanPackUI\SecurityAnalytics\Livewire\SecurityEventList::class )->name( 'events' );
            Route::get( '/stats', \ArtisanPackUI\SecurityAnalytics\Livewire\SecurityStats::class )->name( 'stats' );
            Route::get( '/suspicious-activity', \ArtisanPackUI\SecurityAnalytics\Livewire\SuspiciousActivityList::class )->name( 'suspicious-activity' );
        } );
}
