<?php

declare( strict_types=1 );

namespace Tests\Unit\Analytics\Models;

use ArtisanPackUI\SecurityAnalytics\Models\Anomaly;
use ArtisanPackUI\SecurityAnalytics\Models\SecurityIncident;
use Tests\Unit\Analytics\AnalyticsTestCase;

class SecurityIncidentModelTest extends AnalyticsTestCase
{
    public function test_it_can_create_incident(): void
    {
        $incident = SecurityIncident::factory()->create( [
            'title'    => 'Suspicious login spike',
            'severity' => SecurityIncident::SEVERITY_HIGH,
            'status'   => SecurityIncident::STATUS_OPEN,
        ] );

        $this->assertDatabaseHas( 'security_incidents', [
            'id'       => $incident->id,
            'title'    => 'Suspicious login spike',
            'severity' => SecurityIncident::SEVERITY_HIGH,
        ] );
    }

    public function test_it_generates_incident_number_on_create(): void
    {
        $incident = SecurityIncident::factory()->create( ['incident_number' => null] );

        $this->assertNotNull( $incident->incident_number );
        $this->assertMatchesRegularExpression( '/^INC-\d{4}-\d{6}$/', $incident->incident_number );
    }

    public function test_it_increments_incident_number_sequence(): void
    {
        $first  = SecurityIncident::factory()->create( ['incident_number' => null] );
        $second = SecurityIncident::factory()->create( ['incident_number' => null] );

        $this->assertNotEquals( $first->incident_number, $second->incident_number );
    }

    public function test_it_sets_opened_at_on_create(): void
    {
        $incident = SecurityIncident::factory()->create( ['opened_at' => null] );

        $this->assertInstanceOf( \Carbon\Carbon::class, $incident->opened_at );
    }

    public function test_it_casts_json_attributes(): void
    {
        $incident = SecurityIncident::factory()->create( [
            'affected_users' => [1, 2],
            'affected_ips'   => ['203.0.113.1'],
            'actions_taken'  => [['action' => 'notify']],
        ] );

        $this->assertIsArray( $incident->affected_users );
        $this->assertIsArray( $incident->affected_ips );
        $this->assertIsArray( $incident->actions_taken );
    }

    public function test_it_checks_status_helpers(): void
    {
        $open   = SecurityIncident::factory()->create( ['status' => SecurityIncident::STATUS_OPEN] );
        $closed = SecurityIncident::factory()->create( ['status' => SecurityIncident::STATUS_CLOSED] );

        $this->assertTrue( $open->isOpen() );
        $this->assertTrue( $open->isActive() );
        $this->assertFalse( $open->isClosed() );

        $this->assertTrue( $closed->isClosed() );
        $this->assertFalse( $closed->isActive() );
    }

    public function test_it_transitions_through_lifecycle(): void
    {
        $incident = SecurityIncident::factory()->create( ['status' => SecurityIncident::STATUS_OPEN] );

        $incident->investigate();
        $this->assertEquals( SecurityIncident::STATUS_INVESTIGATING, $incident->status );

        $incident->contain();
        $this->assertEquals( SecurityIncident::STATUS_CONTAINED, $incident->status );
        $this->assertInstanceOf( \Carbon\Carbon::class, $incident->contained_at );

        $incident->resolve( 'Credential reset' );
        $this->assertEquals( SecurityIncident::STATUS_RESOLVED, $incident->status );
        $this->assertEquals( 'Credential reset', $incident->root_cause );
        $this->assertInstanceOf( \Carbon\Carbon::class, $incident->resolved_at );

        $incident->close( 'Enforce MFA' );
        $this->assertEquals( SecurityIncident::STATUS_CLOSED, $incident->status );
        $this->assertEquals( 'Enforce MFA', $incident->lessons_learned );
        $this->assertInstanceOf( \Carbon\Carbon::class, $incident->closed_at );
    }

    public function test_it_assigns_to_a_user(): void
    {
        $incident = SecurityIncident::factory()->create( ['assigned_to' => null] );

        $incident->assignTo( 99 );

        $this->assertEquals( 99, $incident->assigned_to );
    }

    public function test_it_adds_actions(): void
    {
        $incident = SecurityIncident::factory()->create( ['actions_taken' => null] );

        $incident->addAction( 'blocked_ip', ['ip' => '203.0.113.1'] );

        $this->assertCount( 1, $incident->actions_taken );
        $this->assertEquals( 'blocked_ip', $incident->actions_taken[0]['action'] );
        $this->assertEquals( '203.0.113.1', $incident->actions_taken[0]['details']['ip'] );
    }

    public function test_it_adds_affected_users_without_duplicates(): void
    {
        $incident = SecurityIncident::factory()->create( ['affected_users' => null] );

        $incident->addAffectedUser( 1 );
        $incident->addAffectedUser( 1 );
        $incident->addAffectedUser( 2 );

        $this->assertEquals( [1, 2], array_values( $incident->affected_users ) );
    }

    public function test_it_adds_affected_ips_without_duplicates(): void
    {
        $incident = SecurityIncident::factory()->create( ['affected_ips' => null] );

        $incident->addAffectedIp( '203.0.113.1' );
        $incident->addAffectedIp( '203.0.113.1' );
        $incident->addAffectedIp( '203.0.113.2' );

        $this->assertEquals( ['203.0.113.1', '203.0.113.2'], array_values( $incident->affected_ips ) );
    }

    public function test_it_calculates_time_to_contain_and_resolve(): void
    {
        $incident = SecurityIncident::factory()->create( [
            'opened_at'    => now()->subMinutes( 60 ),
            'contained_at' => now()->subMinutes( 30 ),
            'resolved_at'  => now(),
        ] );

        $this->assertEquals( 30, $incident->getTimeToContain() );
        $this->assertEquals( 60, $incident->getTimeToResolve() );
    }

    public function test_it_returns_null_times_when_timestamps_missing(): void
    {
        $incident = SecurityIncident::factory()->create( [
            'contained_at' => null,
            'resolved_at'  => null,
        ] );

        $this->assertNull( $incident->getTimeToContain() );
        $this->assertNull( $incident->getTimeToResolve() );
    }

    public function test_it_relates_to_source_anomaly(): void
    {
        $anomaly  = Anomaly::factory()->create();
        $incident = SecurityIncident::factory()->create( ['source_anomaly_id' => $anomaly->id] );

        $this->assertInstanceOf( Anomaly::class, $incident->sourceAnomaly );
        $this->assertEquals( $anomaly->id, $incident->sourceAnomaly->id );
    }

    public function test_it_scopes_active_open_and_status(): void
    {
        SecurityIncident::factory()->create( ['status' => SecurityIncident::STATUS_OPEN] );
        SecurityIncident::factory()->create( ['status' => SecurityIncident::STATUS_INVESTIGATING] );
        SecurityIncident::factory()->create( ['status' => SecurityIncident::STATUS_CLOSED] );

        $this->assertEquals( 2, SecurityIncident::active()->count() );
        $this->assertEquals( 1, SecurityIncident::open()->count() );
        $this->assertEquals( 1, SecurityIncident::status( SecurityIncident::STATUS_CLOSED )->count() );
    }

    public function test_it_scopes_severity_and_critical(): void
    {
        SecurityIncident::factory()->count( 2 )->create( ['severity' => SecurityIncident::SEVERITY_CRITICAL] );
        SecurityIncident::factory()->create( ['severity' => SecurityIncident::SEVERITY_LOW] );

        $this->assertEquals( 2, SecurityIncident::severity( SecurityIncident::SEVERITY_CRITICAL )->count() );
        $this->assertEquals( 2, SecurityIncident::critical()->count() );
    }

    public function test_it_scopes_assigned_and_unassigned(): void
    {
        SecurityIncident::factory()->create( ['assigned_to' => 5] );
        SecurityIncident::factory()->count( 2 )->create( ['assigned_to' => null] );

        $this->assertEquals( 1, SecurityIncident::assignedTo( 5 )->count() );
        $this->assertEquals( 2, SecurityIncident::unassigned()->count() );
    }
}
