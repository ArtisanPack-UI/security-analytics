<?php

declare( strict_types=1 );

use ArtisanPackUI\SecurityAnalytics\Livewire\SecurityDashboard;
use ArtisanPackUI\SecurityAnalytics\Livewire\SecurityEventList;
use ArtisanPackUI\SecurityAnalytics\Livewire\SecurityStats;
use ArtisanPackUI\SecurityAnalytics\Livewire\SuspiciousActivityList;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Livewire\Livewire;

uses( RefreshDatabase::class );

beforeEach( function (): void {
    // The Livewire components require an authenticated user (they abort 403
    // for guests). SecurityDashboard additionally checks the
    // `view-security-dashboard` ability — grant it permissively for these
    // render-smoke tests.
    Illuminate\Support\Facades\Gate::before( fn () => true );

    $this->actingAs( new class extends Illuminate\Foundation\Auth\User {
        public $id = 1;

        protected $guarded = [];

        public function getAuthIdentifier()
        {
            return 1;
        }
    } );
} );

it( 'renders the SecurityDashboard Livewire component', function (): void {
    Livewire::test( SecurityDashboard::class )
        ->assertStatus( 200 );
} );

it( 'renders the SecurityEventList Livewire component', function (): void {
    Livewire::test( SecurityEventList::class )
        ->assertStatus( 200 );
} );

it( 'renders the SecurityStats Livewire component', function (): void {
    Livewire::test( SecurityStats::class )
        ->assertStatus( 200 );
} );

it( 'renders the SuspiciousActivityList Livewire component', function (): void {
    Livewire::test( SuspiciousActivityList::class )
        ->assertStatus( 200 );
} );
