<?php

declare( strict_types=1 );

namespace Tests\Unit\Analytics\Models;

use ArtisanPackUI\SecurityAnalytics\Models\Anomaly;
use Tests\Unit\Analytics\AnalyticsTestCase;

class AnomalyModelTest extends AnalyticsTestCase
{
    public function test_it_can_create_anomaly(): void
    {
        $anomaly = Anomaly::factory()->create( [
            'detector'    => 'brute_force',
            'category'    => Anomaly::CATEGORY_AUTHENTICATION,
            'severity'    => Anomaly::SEVERITY_HIGH,
            'score'       => 85.5,
            'description' => 'Brute force attack detected',
        ] );

        $this->assertDatabaseHas( 'anomalies', [
            'id'       => $anomaly->id,
            'detector' => 'brute_force',
            'category' => Anomaly::CATEGORY_AUTHENTICATION,
            'severity' => Anomaly::SEVERITY_HIGH,
        ] );
    }

    public function test_it_casts_score_to_float(): void
    {
        $anomaly = Anomaly::factory()->create( [
            'score' => 75.5,
        ] );

        $this->assertIsFloat( $anomaly->score );
        $this->assertEquals( 75.5, $anomaly->score );
    }

    public function test_it_casts_metadata_to_array(): void
    {
        $anomaly = Anomaly::factory()->create( [
            'metadata' => ['key' => 'value', 'nested' => ['a' => 1]],
        ] );

        $this->assertIsArray( $anomaly->metadata );
        $this->assertEquals( 'value', $anomaly->metadata['key'] );
        $this->assertEquals( 1, $anomaly->metadata['nested']['a'] );
    }

    public function test_it_casts_dates(): void
    {
        $anomaly = Anomaly::factory()->create( [
            'detected_at' => now(),
            'resolved_at' => now()->addHour(),
        ] );

        $this->assertInstanceOf( \Carbon\Carbon::class, $anomaly->detected_at );
        $this->assertInstanceOf( \Carbon\Carbon::class, $anomaly->resolved_at );
    }

    public function test_it_checks_if_resolved(): void
    {
        $unresolved = Anomaly::factory()->create( [
            'resolved_at' => null,
        ] );

        $resolved = Anomaly::factory()->create( [
            'resolved_at' => now(),
        ] );

        $this->assertFalse( $unresolved->isResolved() );
        $this->assertTrue( $resolved->isResolved() );
    }

    public function test_it_checks_if_critical(): void
    {
        $critical = Anomaly::factory()->create( [
            'severity' => Anomaly::SEVERITY_CRITICAL,
        ] );

        $high = Anomaly::factory()->create( [
            'severity' => Anomaly::SEVERITY_HIGH,
        ] );

        $this->assertTrue( $critical->isCritical() );
        $this->assertFalse( $high->isCritical() );
    }

    public function test_it_checks_if_high_severity(): void
    {
        $critical = Anomaly::factory()->create( [
            'severity' => Anomaly::SEVERITY_CRITICAL,
        ] );

        $high = Anomaly::factory()->create( [
            'severity' => Anomaly::SEVERITY_HIGH,
        ] );

        $medium = Anomaly::factory()->create( [
            'severity' => Anomaly::SEVERITY_MEDIUM,
        ] );

        $this->assertTrue( $critical->isHighSeverity() );
        $this->assertTrue( $high->isHighSeverity() );
        $this->assertFalse( $medium->isHighSeverity() );
    }

    public function test_it_can_resolve_anomaly(): void
    {
        $anomaly = Anomaly::factory()->create( [
            'resolved_at' => null,
        ] );

        $anomaly->resolve( 123, 'Fixed by admin' );

        $this->assertTrue( $anomaly->isResolved() );
        $this->assertEquals( 123, $anomaly->resolved_by );
        $this->assertEquals( 'Fixed by admin', $anomaly->resolution_notes );
    }

    public function test_it_gets_and_sets_metadata(): void
    {
        $anomaly = Anomaly::factory()->create( [
            'metadata' => ['existing' => 'value'],
        ] );

        $this->assertEquals( 'value', $anomaly->getMetadata( 'existing' ) );
        $this->assertEquals( 'default', $anomaly->getMetadata( 'missing', 'default' ) );

        $anomaly->setMetadata( 'new_key', 'new_value' );
        $this->assertEquals( 'new_value', $anomaly->getMetadata( 'new_key' ) );
    }

    public function test_it_scopes_unresolved(): void
    {
        Anomaly::factory()->count( 3 )->create( ['resolved_at' => null] );
        Anomaly::factory()->count( 2 )->create( ['resolved_at' => now()] );

        $this->assertEquals( 3, Anomaly::unresolved()->count() );
    }

    public function test_it_scopes_resolved(): void
    {
        Anomaly::factory()->count( 3 )->create( ['resolved_at' => null] );
        Anomaly::factory()->count( 2 )->create( ['resolved_at' => now()] );

        $this->assertEquals( 2, Anomaly::resolved()->count() );
    }

    public function test_it_scopes_by_severity(): void
    {
        Anomaly::factory()->create( ['severity' => Anomaly::SEVERITY_CRITICAL] );
        Anomaly::factory()->count( 2 )->create( ['severity' => Anomaly::SEVERITY_HIGH] );
        Anomaly::factory()->count( 3 )->create( ['severity' => Anomaly::SEVERITY_MEDIUM] );

        $this->assertEquals( 1, Anomaly::severity( Anomaly::SEVERITY_CRITICAL )->count() );
        $this->assertEquals( 2, Anomaly::severity( Anomaly::SEVERITY_HIGH )->count() );
    }

    public function test_it_scopes_high_severity(): void
    {
        Anomaly::factory()->create( ['severity' => Anomaly::SEVERITY_CRITICAL] );
        Anomaly::factory()->create( ['severity' => Anomaly::SEVERITY_HIGH] );
        Anomaly::factory()->count( 3 )->create( ['severity' => Anomaly::SEVERITY_MEDIUM] );

        $this->assertEquals( 2, Anomaly::highSeverity()->count() );
    }

    public function test_it_scopes_by_detector(): void
    {
        Anomaly::factory()->count( 2 )->create( ['detector' => 'brute_force'] );
        Anomaly::factory()->create( ['detector' => 'geo_velocity'] );

        $this->assertEquals( 2, Anomaly::detector( 'brute_force' )->count() );
        $this->assertEquals( 1, Anomaly::detector( 'geo_velocity' )->count() );
    }

    public function test_it_scopes_by_category(): void
    {
        Anomaly::factory()->count( 2 )->create( ['category' => Anomaly::CATEGORY_AUTHENTICATION] );
        Anomaly::factory()->create( ['category' => Anomaly::CATEGORY_THREAT] );

        $this->assertEquals( 2, Anomaly::category( Anomaly::CATEGORY_AUTHENTICATION )->count() );
    }

    public function test_it_scopes_for_user(): void
    {
        Anomaly::factory()->count( 3 )->create( ['user_id' => 1] );
        Anomaly::factory()->count( 2 )->create( ['user_id' => 2] );

        $this->assertEquals( 3, Anomaly::forUser( 1 )->count() );
        $this->assertEquals( 2, Anomaly::forUser( 2 )->count() );
    }

    public function test_it_scopes_for_ip(): void
    {
        Anomaly::factory()->count( 2 )->create( ['ip_address' => '192.168.1.1'] );
        Anomaly::factory()->create( ['ip_address' => '10.0.0.1'] );

        $this->assertEquals( 2, Anomaly::forIp( '192.168.1.1' )->count() );
    }

    public function test_it_gets_severity_weight(): void
    {
        $testCases = [
            Anomaly::SEVERITY_CRITICAL => 5,
            Anomaly::SEVERITY_HIGH     => 4,
            Anomaly::SEVERITY_MEDIUM   => 3,
            Anomaly::SEVERITY_LOW      => 2,
            Anomaly::SEVERITY_INFO     => 1,
        ];

        foreach ( $testCases as $severity => $expectedWeight ) {
            $anomaly = Anomaly::factory()->create( ['severity' => $severity] );
            $this->assertEquals( $expectedWeight, $anomaly->getSeverityWeight() );
        }
    }

    public function test_it_has_category_constants(): void
    {
        $this->assertEquals( 'statistical', Anomaly::CATEGORY_STATISTICAL );
        $this->assertEquals( 'behavioral', Anomaly::CATEGORY_BEHAVIORAL );
        $this->assertEquals( 'rule_based', Anomaly::CATEGORY_RULE_BASED );
        $this->assertEquals( 'authentication', Anomaly::CATEGORY_AUTHENTICATION );
        $this->assertEquals( 'threat', Anomaly::CATEGORY_THREAT );
        $this->assertEquals( 'access', Anomaly::CATEGORY_ACCESS );
        $this->assertEquals( 'data', Anomaly::CATEGORY_DATA );
    }

    public function test_it_has_severity_constants(): void
    {
        $this->assertEquals( 'info', Anomaly::SEVERITY_INFO );
        $this->assertEquals( 'low', Anomaly::SEVERITY_LOW );
        $this->assertEquals( 'medium', Anomaly::SEVERITY_MEDIUM );
        $this->assertEquals( 'high', Anomaly::SEVERITY_HIGH );
        $this->assertEquals( 'critical', Anomaly::SEVERITY_CRITICAL );
    }
}
