<?php

declare( strict_types=1 );

use ArtisanPackUI\Ai\Contracts\CredentialResolver;
use ArtisanPackUI\Ai\Contracts\FeatureRegistry;
use ArtisanPackUI\Ai\Credentials\ChainedCredentialResolver;
use ArtisanPackUI\Ai\Credentials\Credentials;
use ArtisanPackUI\Ai\Exceptions\FeatureDisabledException;
use ArtisanPackUI\SecurityAnalytics\AI\Agents\IncidentResponseAgent;
use ArtisanPackUI\SecurityAnalytics\Models\SecurityIncident;
use Illuminate\Foundation\Testing\RefreshDatabase;

uses( RefreshDatabase::class );

beforeEach( function (): void {
    /** @var ChainedCredentialResolver $resolver */
    $resolver = app( CredentialResolver::class );
    $resolver->setOverride( new Credentials(
        provider: 'anthropic',
        apiKey: 'sk-test',
        defaultModel: 'claude-opus-4-7',
    ) );
    $resolver->useStore( fn () => null );

    IncidentResponseAgent::fake( [] );
} );

it( 'declares the security.incident_response feature key and Opus default', function (): void {
    $agent = new IncidentResponseAgent();

    expect( $agent->featureKey )->toBe( 'security.incident_response' );
    expect( $agent->package )->toBe( 'artisanpack-ui/security-analytics' );
    expect( $agent->defaultModel )->toBe( 'claude-opus-4-7' );
} );

it( 'declares an output schema with the suggested_next_actions key', function (): void {
    $schema = ( new IncidentResponseAgent() )->outputSchema();

    expect( $schema['required'] )->toBe( [ 'suggested_next_actions' ] );

    $itemProps = $schema['properties']['suggested_next_actions']['items']['properties'];
    expect( $itemProps )->toHaveKeys( [ 'step', 'rationale', 'risk' ] );
    expect( $itemProps['risk']['enum'] )->toBe( [ 'low', 'medium', 'high' ] );
} );

it( 'runs end-to-end for a SecurityIncident id', function (): void {
    $incident = SecurityIncident::factory()->create( [
        'severity' => SecurityIncident::SEVERITY_HIGH,
        'status'   => SecurityIncident::STATUS_OPEN,
    ] );

    $result = IncidentResponseAgent::for( $incident->id )->run();

    expect( $result )->toHaveKey( 'suggested_next_actions' );
    expect( $result['suggested_next_actions'] )->toBeArray();
} );

it( 'accepts a SecurityIncident model as input', function (): void {
    $incident = SecurityIncident::factory()->create();

    $result = IncidentResponseAgent::for( $incident )->run();

    expect( $result )->toHaveKey( 'suggested_next_actions' );
} );

it( 'accepts a pre-serialized array payload', function (): void {
    $result = IncidentResponseAgent::for( [
        'incident'  => [ 'id' => 1, 'severity' => 'high', 'status' => 'open' ],
        'timeline'  => [],
        'playbooks' => [],
    ] )->run();

    expect( $result )->toHaveKey( 'suggested_next_actions' );
} );

it( 'throws InvalidArgumentException for an unknown SecurityIncident id', function (): void {
    expect( fn () => IncidentResponseAgent::for( 99999 )->run() )
        ->toThrow( InvalidArgumentException::class );
} );

it( 'throws FeatureDisabledException when the toggle is off', function (): void {
    /** @var FeatureRegistry $registry */
    $registry = app( FeatureRegistry::class );
    $registry->disable( 'security.incident_response' );

    $incident = SecurityIncident::factory()->create();

    expect( fn () => IncidentResponseAgent::for( $incident->id )->run() )
        ->toThrow( FeatureDisabledException::class );
} );
