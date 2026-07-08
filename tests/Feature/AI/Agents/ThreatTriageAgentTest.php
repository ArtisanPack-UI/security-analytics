<?php

declare( strict_types=1 );

use ArtisanPackUI\Ai\Contracts\CredentialResolver;
use ArtisanPackUI\Ai\Contracts\FeatureRegistry;
use ArtisanPackUI\Ai\Credentials\ChainedCredentialResolver;
use ArtisanPackUI\Ai\Credentials\Credentials;
use ArtisanPackUI\Ai\Events\AgentUsageRecorded;
use ArtisanPackUI\Ai\Exceptions\FeatureDisabledException;
use ArtisanPackUI\SecurityAnalytics\AI\Agents\ThreatTriageAgent;
use ArtisanPackUI\SecurityAnalytics\Models\SecurityEvent;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Event;

uses( RefreshDatabase::class );

beforeEach( function (): void {
    /** @var ChainedCredentialResolver $resolver */
    $resolver = app( CredentialResolver::class );
    $resolver->setOverride( new Credentials(
        provider: 'anthropic',
        apiKey: 'sk-test',
        defaultModel: 'claude-sonnet-4-6',
    ) );
    $resolver->useStore( fn () => null );
} );

it( 'declares the security.threat_triage feature key', function (): void {
    $agent = new ThreatTriageAgent();

    expect( $agent->featureKey )->toBe( 'security.threat_triage' );
    expect( $agent->package )->toBe( 'artisanpack-ui/security-analytics' );
    expect( $agent->defaultModel )->toBe( 'claude-sonnet-4-6' );
} );

it( 'declares an output schema with the four required keys', function (): void {
    $schema = ( new ThreatTriageAgent() )->outputSchema();

    expect( $schema['type'] )->toBe( 'object' );
    expect( $schema['required'] )->toBe( [
        'severity',
        'summary',
        'recommended_actions',
        'related_events',
    ] );
    expect( $schema['properties']['severity']['enum'] )->toBe(
        [ 'info', 'low', 'medium', 'high', 'critical' ],
    );
} );

it( 'runs end-to-end for a SecurityEvent id and returns a schema-shaped payload', function (): void {
    $event = SecurityEvent::create( [
        'event_type'  => SecurityEvent::TYPE_AUTHENTICATION,
        'event_name'  => 'login.failed',
        'severity'    => SecurityEvent::SEVERITY_WARNING,
        'ip_address'  => '203.0.113.10',
        'user_id'     => 42,
        'details'     => [ 'reason' => 'bad_password' ],
        'fingerprint' => 'fp-abc',
    ] );

    $result = ThreatTriageAgent::for( $event->id )->run();

    expect( $result )->toHaveKeys( [ 'severity', 'summary', 'recommended_actions', 'related_events' ] );
    expect( $result['severity'] )->toBeIn( [ 'info', 'low', 'medium', 'high', 'critical' ] );
    expect( $result['summary'] )->toBeString();
    expect( $result['recommended_actions'] )->toBeArray();
    expect( $result['related_events'] )->toBeArray();
} );

it( 'accepts a SecurityEvent model as input', function (): void {
    $event = SecurityEvent::create( [
        'event_type' => SecurityEvent::TYPE_API_ACCESS,
        'event_name' => 'api.rate_limit',
        'severity'   => SecurityEvent::SEVERITY_ERROR,
        'ip_address' => '203.0.113.20',
    ] );

    $result = ThreatTriageAgent::for( $event )->run();

    expect( $result )->toHaveKey( 'severity' );
} );

it( 'accepts a pre-serialized array payload', function (): void {
    $result = ThreatTriageAgent::for( [
        'event' => [
            'id'         => 999,
            'event_name' => 'external.event',
            'severity'   => 'high',
        ],
        'related' => [],
        'context' => [],
    ] )->run();

    expect( $result )->toHaveKey( 'severity' );
} );

it( 'throws InvalidArgumentException for an unknown SecurityEvent id', function (): void {
    expect( fn () => ThreatTriageAgent::for( 99999 )->run() )
        ->toThrow( InvalidArgumentException::class );
} );

it( 'throws FeatureDisabledException when the toggle is off', function (): void {
    /** @var FeatureRegistry $registry */
    $registry = app( FeatureRegistry::class );
    $registry->disable( 'security.threat_triage' );

    $event = SecurityEvent::create( [
        'event_type' => SecurityEvent::TYPE_AUTHENTICATION,
        'event_name' => 'login.failed',
        'severity'   => SecurityEvent::SEVERITY_INFO,
        'ip_address' => '203.0.113.30',
    ] );

    expect( fn () => ThreatTriageAgent::for( $event->id )->run() )
        ->toThrow( FeatureDisabledException::class );
} );

it( 'dispatches AgentUsageRecorded after a successful run', function (): void {
    Event::fake( [ AgentUsageRecorded::class ] );

    $event = SecurityEvent::create( [
        'event_type' => SecurityEvent::TYPE_AUTHENTICATION,
        'event_name' => 'login.failed',
        'severity'   => SecurityEvent::SEVERITY_WARNING,
        'ip_address' => '203.0.113.40',
    ] );

    ThreatTriageAgent::for( $event->id )->run();

    Event::assertDispatched(
        AgentUsageRecorded::class,
        fn ( AgentUsageRecorded $e ) => 'security.threat_triage' === $e->featureKey
            && 'artisanpack-ui/security-analytics' === $e->package,
    );
} );
