<?php

declare( strict_types=1 );

use ArtisanPackUI\Ai\Contracts\FeatureRegistry;
use ArtisanPackUI\SecurityAnalytics\AI\Agents\AnomalySummaryAgent;
use ArtisanPackUI\SecurityAnalytics\AI\Agents\IncidentResponseAgent;
use ArtisanPackUI\SecurityAnalytics\AI\Agents\ThreatTriageAgent;
use ArtisanPackUI\SecurityAnalytics\SecurityAnalyticsServiceProvider;

it( 'exposes the three AI features via the aiFeatures() method', function (): void {
    $provider = new SecurityAnalyticsServiceProvider( app() );
    $features = $provider->aiFeatures();

    expect( $features )->toHaveKeys( [
        'security.threat_triage',
        'security.anomaly_summary',
        'security.incident_response',
    ] );

    expect( $features['security.threat_triage']['agent'] )->toBe( ThreatTriageAgent::class );
    expect( $features['security.anomaly_summary']['agent'] )->toBe( AnomalySummaryAgent::class );
    expect( $features['security.incident_response']['agent'] )->toBe( IncidentResponseAgent::class );
} );

it( 'registers all three features with the AI feature registry via auto-discovery', function (): void {
    $registry = app( FeatureRegistry::class );

    expect( $registry->get( 'security.threat_triage' ) )->not->toBeNull();
    expect( $registry->get( 'security.anomaly_summary' ) )->not->toBeNull();
    expect( $registry->get( 'security.incident_response' ) )->not->toBeNull();
} );

it( 'attributes each feature to the security-analytics package', function (): void {
    $registry = app( FeatureRegistry::class );

    expect( $registry->get( 'security.threat_triage' )->package )
        ->toBe( 'artisanpack-ui/security-analytics' );

    expect( $registry->get( 'security.anomaly_summary' )->package )
        ->toBe( 'artisanpack-ui/security-analytics' );

    expect( $registry->get( 'security.incident_response' )->package )
        ->toBe( 'artisanpack-ui/security-analytics' );
} );

it( 'has each feature toggled on by default (no persistence layer bound)', function (): void {
    $registry = app( FeatureRegistry::class );

    expect( $registry->isToggleOn( 'security.threat_triage' ) )->toBeTrue();
    expect( $registry->isToggleOn( 'security.anomaly_summary' ) )->toBeTrue();
    expect( $registry->isToggleOn( 'security.incident_response' ) )->toBeTrue();
} );
