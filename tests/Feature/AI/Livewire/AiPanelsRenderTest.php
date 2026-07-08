<?php

declare( strict_types=1 );

use ArtisanPackUI\Ai\Contracts\CredentialResolver;
use ArtisanPackUI\Ai\Contracts\FeatureRegistry;
use ArtisanPackUI\Ai\Credentials\ChainedCredentialResolver;
use ArtisanPackUI\Ai\Credentials\Credentials;
use ArtisanPackUI\SecurityAnalytics\Livewire\AnomalySummaryPanel;
use ArtisanPackUI\SecurityAnalytics\Livewire\IncidentResponsePanel;
use ArtisanPackUI\SecurityAnalytics\Livewire\ThreatTriagePanel;
use ArtisanPackUI\SecurityAnalytics\Models\SecurityEvent;
use ArtisanPackUI\SecurityAnalytics\Models\SecurityIncident;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Livewire\Livewire;

uses( RefreshDatabase::class );

beforeEach( function (): void {
    Illuminate\Support\Facades\Gate::before( fn () => true );

    $this->actingAs( new class extends Illuminate\Foundation\Auth\User {
        public $id = 1;

        protected $guarded = [];

        public function getAuthIdentifier()
        {
            return 1;
        }
    } );

    /** @var ChainedCredentialResolver $resolver */
    $resolver = app( CredentialResolver::class );
    $resolver->setOverride( new Credentials(
        provider: 'anthropic',
        apiKey: 'sk-test',
        defaultModel: 'claude-sonnet-4-6',
    ) );
    $resolver->useStore( fn () => null );
} );

it( 'renders the ThreatTriagePanel', function (): void {
    Livewire::test( ThreatTriagePanel::class )
        ->assertStatus( 200 )
        ->assertSee( 'Threat triage' );
} );

it( 'renders the AnomalySummaryPanel', function (): void {
    Livewire::test( AnomalySummaryPanel::class )
        ->assertStatus( 200 )
        ->assertSee( 'Anomaly summary' );
} );

it( 'renders the IncidentResponsePanel', function (): void {
    Livewire::test( IncidentResponsePanel::class )
        ->assertStatus( 200 )
        ->assertSee( 'Incident response suggestions' );
} );

it( 'marks each panel as available when the feature is enabled and credentials resolve', function (): void {
    Livewire::test( ThreatTriagePanel::class )
        ->assertSet( 'available', true )
        ->assertSet( 'toggleOn', true );

    Livewire::test( AnomalySummaryPanel::class )
        ->assertSet( 'available', true )
        ->assertSet( 'toggleOn', true );

    Livewire::test( IncidentResponsePanel::class )
        ->assertSet( 'available', true )
        ->assertSet( 'toggleOn', true );
} );

it( 'marks each panel as unavailable and toggleOn=false when the feature is disabled', function (): void {
    /** @var FeatureRegistry $registry */
    $registry = app( FeatureRegistry::class );

    $registry->disable( 'security.threat_triage' );
    $registry->disable( 'security.anomaly_summary' );
    $registry->disable( 'security.incident_response' );

    Livewire::test( ThreatTriagePanel::class )
        ->assertSet( 'available', false )
        ->assertSet( 'toggleOn', false );

    Livewire::test( AnomalySummaryPanel::class )
        ->assertSet( 'available', false )
        ->assertSet( 'toggleOn', false );

    Livewire::test( IncidentResponsePanel::class )
        ->assertSet( 'available', false )
        ->assertSet( 'toggleOn', false );
} );

it( 'reports an error when triage is called without an event id', function (): void {
    Livewire::test( ThreatTriagePanel::class )
        ->call( 'triage' )
        ->assertSet( 'error', 'Select a security event to triage.' );
} );

it( 'populates the triage result when called with a valid event id', function (): void {
    $event = SecurityEvent::create( [
        'event_type' => SecurityEvent::TYPE_AUTHENTICATION,
        'event_name' => 'login.failed',
        'severity'   => SecurityEvent::SEVERITY_WARNING,
        'ip_address' => '203.0.113.50',
    ] );

    Livewire::test( ThreatTriagePanel::class, [ 'eventId' => $event->id ] )
        ->call( 'triage' )
        ->assertSet( 'error', null )
        ->assertSet( 'result.severity', fn ( $severity ) => in_array( $severity, [ 'info', 'low', 'medium', 'high', 'critical' ], true ) );
} );

it( 'rejects an out-of-range anomaly summary window', function (): void {
    Livewire::test( AnomalySummaryPanel::class )
        ->set( 'windowHours', 0 )
        ->call( 'generate' )
        ->assertSet( 'error', 'Window must be between 1 and 720 hours.' );

    Livewire::test( AnomalySummaryPanel::class )
        ->set( 'windowHours', 1000 )
        ->call( 'generate' )
        ->assertSet( 'error', 'Window must be between 1 and 720 hours.' );
} );

it( 'populates the anomaly summary result on generate', function (): void {
    Livewire::test( AnomalySummaryPanel::class )
        ->set( 'windowHours', 24 )
        ->call( 'generate' )
        ->assertSet( 'error', null )
        ->assertSet( 'result.headline', fn ( $headline ) => is_string( $headline ) && '' !== $headline );
} );

it( 'reports an error when suggest is called without an incident id', function (): void {
    Livewire::test( IncidentResponsePanel::class )
        ->call( 'suggest' )
        ->assertSet( 'error', 'Select an incident to advise on.' );
} );

it( 'populates the incident response result on suggest', function (): void {
    $incident = SecurityIncident::factory()->create();

    Livewire::test( IncidentResponsePanel::class, [ 'incidentId' => $incident->id ] )
        ->call( 'suggest' )
        ->assertSet( 'error', null )
        ->assertSet( 'result.suggested_next_actions', fn ( $actions ) => is_array( $actions ) );
} );
