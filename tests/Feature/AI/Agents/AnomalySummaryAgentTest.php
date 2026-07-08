<?php

declare( strict_types=1 );

use ArtisanPackUI\Ai\Contracts\CredentialResolver;
use ArtisanPackUI\Ai\Contracts\FeatureRegistry;
use ArtisanPackUI\Ai\Credentials\ChainedCredentialResolver;
use ArtisanPackUI\Ai\Credentials\Credentials;
use ArtisanPackUI\Ai\Exceptions\FeatureDisabledException;
use ArtisanPackUI\SecurityAnalytics\AI\Agents\AnomalySummaryAgent;
use ArtisanPackUI\SecurityAnalytics\Models\Anomaly;
use Illuminate\Foundation\Testing\RefreshDatabase;

uses( RefreshDatabase::class );

beforeEach( function (): void {
    /** @var ChainedCredentialResolver $resolver */
    $resolver = app( CredentialResolver::class );
    $resolver->setOverride( new Credentials(
        provider: 'anthropic',
        apiKey: 'sk-test',
        defaultModel: 'claude-haiku-4-5-20251001',
    ) );
    $resolver->useStore( fn () => null );
} );

it( 'declares the security.anomaly_summary feature key', function (): void {
    $agent = new AnomalySummaryAgent();

    expect( $agent->featureKey )->toBe( 'security.anomaly_summary' );
    expect( $agent->package )->toBe( 'artisanpack-ui/security-analytics' );
} );

it( 'declares an output schema with the five required keys', function (): void {
    $schema = ( new AnomalySummaryAgent() )->outputSchema();

    expect( $schema['required'] )->toBe( [
        'headline',
        'body',
        'top_severities',
        'top_detectors',
        'recommended_followups',
    ] );
} );

it( 'runs end-to-end for a window and returns a schema-shaped payload', function (): void {
    Anomaly::factory()->count( 3 )->create( [
        'detected_at' => now()->subHours( 2 ),
    ] );

    $result = AnomalySummaryAgent::for( 24 )->run();

    expect( $result )->toHaveKeys( [
        'headline',
        'body',
        'top_severities',
        'top_detectors',
        'recommended_followups',
    ] );
    expect( $result['headline'] )->toBeString();
    expect( $result['body'] )->toBeString();
    expect( $result['top_severities'] )->toBeArray();
} );

it( 'handles an empty window gracefully', function (): void {
    $result = AnomalySummaryAgent::for( 24 )->run();

    expect( $result['headline'] )->toContain( 'No anomalies' );
    expect( $result['top_severities'] )->toBe( [] );
    expect( $result['top_detectors'] )->toBe( [] );
} );

it( 'accepts a pre-built payload array', function (): void {
    $result = AnomalySummaryAgent::for( [
        'window_hours' => 48,
        'anomalies'    => [],
        'statistics'   => [
            'total_count' => 0,
            'by_severity' => [],
            'by_detector' => [],
        ],
    ] )->run();

    expect( $result['headline'] )->toBeString();
} );

it( 'throws InvalidArgumentException when window_hours is not an int', function (): void {
    expect( fn () => AnomalySummaryAgent::for( [
        'window_hours' => 'twelve',
        'anomalies'    => [],
        'statistics'   => [],
    ] )->run() )->toThrow( InvalidArgumentException::class );
} );

it( 'throws FeatureDisabledException when the toggle is off', function (): void {
    /** @var FeatureRegistry $registry */
    $registry = app( FeatureRegistry::class );
    $registry->disable( 'security.anomaly_summary' );

    expect( fn () => AnomalySummaryAgent::for( 24 )->run() )
        ->toThrow( FeatureDisabledException::class );
} );
