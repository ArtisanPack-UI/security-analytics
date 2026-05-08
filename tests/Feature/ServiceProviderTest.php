<?php

declare( strict_types=1 );

use ArtisanPackUI\SecurityAnalytics\SecurityAnalytics;

it( 'binds the security-analytics singleton', function (): void {
    expect( app( 'security-analytics' ) )->toBeInstanceOf( SecurityAnalytics::class );
} );

it( 'returns the same instance on subsequent resolutions', function (): void {
    expect( app( 'security-analytics' ) )->toBe( app( 'security-analytics' ) );
} );

it( 'exposes the security_analytics() helper', function (): void {
    expect( security_analytics() )->toBeInstanceOf( SecurityAnalytics::class );
} );
