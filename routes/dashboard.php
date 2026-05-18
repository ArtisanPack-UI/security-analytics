<?php

declare(strict_types=1);

use ArtisanPackUI\SecurityAnalytics\Http\Controllers\SecurityDashboardController;
use ArtisanPackUI\SecurityAnalytics\Livewire\SecurityDashboard;
use ArtisanPackUI\SecurityAnalytics\Livewire\SecurityEventList;
use ArtisanPackUI\SecurityAnalytics\Livewire\SecurityStats;
use ArtisanPackUI\SecurityAnalytics\Livewire\SuspiciousActivityList;
use Illuminate\Support\Facades\Route;

/*
|--------------------------------------------------------------------------
| Security Analytics Dashboard Routes
|--------------------------------------------------------------------------
|
| Two route groups:
|   1. Livewire UI pages — full HTML pages backed by Livewire components.
|   2. JSON API endpoints — data feeds the UI consumes (and any external
|      consumers that want to drive their own dashboards).
|
| Both groups respect the same `artisanpack.security-analytics.dashboard.*`
| config so consumers can disable the dashboard wholesale, change the
| prefix, or swap the middleware (e.g. add `auth` or a custom guard).
|
*/

$middleware = config( 'artisanpack.security-analytics.dashboard.middleware', ['web', 'auth'] );

// --- Livewire UI pages -----------------------------------------------------
$uiPrefix = config( 'artisanpack.security-analytics.dashboard.routePrefix', 'security' );

Route::middleware( $middleware )
    ->prefix( $uiPrefix )
    ->name( 'security.' )
    ->group( function (): void {
        Route::get( '/dashboard', SecurityDashboard::class )->name( 'dashboard' );
        Route::get( '/events', SecurityEventList::class )->name( 'events' );
        Route::get( '/stats', SecurityStats::class )->name( 'stats' );
        Route::get( '/suspicious-activity', SuspiciousActivityList::class )->name( 'suspicious-activity' );
    } );

// --- JSON API endpoints ----------------------------------------------------
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
