<?php

declare( strict_types=1 );

use ArtisanPackUI\SecurityAnalytics\SecurityAnalytics;

it( 'instantiates the SecurityAnalytics class', function (): void {
    expect( new SecurityAnalytics() )->toBeInstanceOf( SecurityAnalytics::class );
} );

it( 'reports its current version', function (): void {
    expect( ( new SecurityAnalytics() )->version() )->toBeString();
} );
