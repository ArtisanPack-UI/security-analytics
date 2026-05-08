<?php

declare(strict_types=1);

use ArtisanPackUI\SecurityAnalytics\Livewire\SecurityDashboard;
use ArtisanPackUI\SecurityAnalytics\Livewire\SecurityEventList;
use ArtisanPackUI\SecurityAnalytics\Livewire\SecurityStats;
use Illuminate\Support\Facades\Route;

$prefix = config('artisanpack.security-analytics.dashboard.routePrefix', 'security');
$middleware = config('artisanpack.security-analytics.dashboard.middleware', ['web', 'auth']);

Route::middleware($middleware)
    ->prefix($prefix)
    ->name('security.')
    ->group(function () {
        Route::get('/dashboard', SecurityDashboard::class)->name('dashboard');
        Route::get('/events', SecurityEventList::class)->name('events');
        Route::get('/stats', SecurityStats::class)->name('stats');
    });
