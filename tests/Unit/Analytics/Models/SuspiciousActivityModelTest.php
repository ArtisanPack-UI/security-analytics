<?php

declare( strict_types=1 );

namespace Tests\Unit\Analytics\Models;

use ArtisanPackUI\SecurityAnalytics\Models\SuspiciousActivity;
use Tests\Unit\Analytics\AnalyticsTestCase;

class SuspiciousActivityModelTest extends AnalyticsTestCase
{
    public function test_it_can_create_suspicious_activity(): void
    {
        $activity = $this->makeActivity();

        $this->assertDatabaseHas( 'suspicious_activities', [
            'id'       => $activity->id,
            'type'     => SuspiciousActivity::TYPE_BRUTE_FORCE,
            'severity' => SuspiciousActivity::SEVERITY_HIGH,
        ] );
    }

    public function test_it_does_not_use_timestamps(): void
    {
        $this->assertFalse( ( new SuspiciousActivity() )->timestamps );
    }

    public function test_it_casts_attributes(): void
    {
        $activity = $this->makeActivity( [
            'risk_score' => 60.25,
            'location'   => ['country' => 'US'],
            'details'    => ['attempts' => 5],
            'resolved'   => false,
        ] );

        $this->assertIsFloat( $activity->risk_score );
        $this->assertIsArray( $activity->location );
        $this->assertIsArray( $activity->details );
        $this->assertIsBool( $activity->resolved );
        $this->assertInstanceOf( \Carbon\Carbon::class, $activity->created_at );
    }

    public function test_it_sets_defaults_on_create(): void
    {
        $activity = SuspiciousActivity::create( [
            'type'       => SuspiciousActivity::TYPE_ANOMALOUS_LOGIN,
            'severity'   => SuspiciousActivity::SEVERITY_MEDIUM,
            'ip_address' => '203.0.113.2',
            'details'    => [],
        ] );

        $this->assertInstanceOf( \Carbon\Carbon::class, $activity->created_at );
        $this->assertEquals( [], $activity->details );
    }

    public function test_it_resolves_the_activity(): void
    {
        $activity = $this->makeActivity( ['resolved' => false] );

        $activity->resolve( 42 );

        $this->assertTrue( $activity->resolved );
        $this->assertEquals( 42, $activity->resolved_by );
        $this->assertInstanceOf( \Carbon\Carbon::class, $activity->resolved_at );
    }

    public function test_it_checks_severity_helpers(): void
    {
        $critical = $this->makeActivity( ['severity' => SuspiciousActivity::SEVERITY_CRITICAL] );
        $high     = $this->makeActivity( ['severity' => SuspiciousActivity::SEVERITY_HIGH] );
        $medium   = $this->makeActivity( ['severity' => SuspiciousActivity::SEVERITY_MEDIUM] );
        $low      = $this->makeActivity( ['severity' => SuspiciousActivity::SEVERITY_LOW] );

        $this->assertTrue( $critical->isCritical() );
        $this->assertTrue( $high->isHigh() );
        $this->assertTrue( $medium->isMedium() );
        $this->assertTrue( $low->isLow() );

        $this->assertFalse( $high->isCritical() );
    }

    public function test_it_gets_type_description(): void
    {
        $bruteForce = $this->makeActivity( ['type' => SuspiciousActivity::TYPE_BRUTE_FORCE] );
        $unknown    = $this->makeActivity( ['type' => 'custom_thing'] );

        $this->assertEquals( 'Brute Force Attack', $bruteForce->getTypeDescription() );
        $this->assertEquals( 'Custom Thing', $unknown->getTypeDescription() );
    }

    public function test_it_gets_severity_color(): void
    {
        $this->assertEquals( 'red', $this->makeActivity( ['severity' => SuspiciousActivity::SEVERITY_CRITICAL] )->getSeverityColor() );
        $this->assertEquals( 'orange', $this->makeActivity( ['severity' => SuspiciousActivity::SEVERITY_HIGH] )->getSeverityColor() );
        $this->assertEquals( 'yellow', $this->makeActivity( ['severity' => SuspiciousActivity::SEVERITY_MEDIUM] )->getSeverityColor() );
        $this->assertEquals( 'gray', $this->makeActivity( ['severity' => SuspiciousActivity::SEVERITY_LOW] )->getSeverityColor() );
    }

    public function test_it_gets_a_detail_value(): void
    {
        $activity = $this->makeActivity( ['details' => ['attempts' => 12, 'window' => '5m']] );

        $this->assertEquals( 12, $activity->getDetail( 'attempts' ) );
        $this->assertEquals( '5m', $activity->getDetail( 'window' ) );
        $this->assertNull( $activity->getDetail( 'missing' ) );
    }

    public function test_it_scopes_unresolved(): void
    {
        $this->makeActivity( ['resolved' => false] );
        $this->makeActivity( ['resolved' => false] );
        $this->makeActivity( ['resolved' => true] );

        $this->assertEquals( 2, SuspiciousActivity::unresolved()->count() );
    }

    public function test_it_scopes_by_type_and_ip(): void
    {
        $this->makeActivity( ['type' => SuspiciousActivity::TYPE_BRUTE_FORCE, 'ip_address' => '203.0.113.1'] );
        $this->makeActivity( ['type' => SuspiciousActivity::TYPE_TOR_DETECTED, 'ip_address' => '203.0.113.2'] );

        $this->assertEquals( 1, SuspiciousActivity::ofType( SuspiciousActivity::TYPE_TOR_DETECTED )->count() );
        $this->assertEquals( 1, SuspiciousActivity::fromIp( '203.0.113.1' )->count() );
    }

    public function test_it_scopes_minimum_severity(): void
    {
        $this->makeActivity( ['severity' => SuspiciousActivity::SEVERITY_LOW] );
        $this->makeActivity( ['severity' => SuspiciousActivity::SEVERITY_MEDIUM] );
        $this->makeActivity( ['severity' => SuspiciousActivity::SEVERITY_HIGH] );
        $this->makeActivity( ['severity' => SuspiciousActivity::SEVERITY_CRITICAL] );

        $this->assertEquals( 3, SuspiciousActivity::minimumSeverity( SuspiciousActivity::SEVERITY_MEDIUM )->count() );
        $this->assertEquals( 1, SuspiciousActivity::minimumSeverity( SuspiciousActivity::SEVERITY_CRITICAL )->count() );
    }

    public function test_it_scopes_recent(): void
    {
        $this->makeActivity( ['created_at' => now()->subHours( 2 )] );
        $this->makeActivity( ['created_at' => now()->subDays( 3 )] );

        $this->assertEquals( 1, SuspiciousActivity::recent( 24 )->count() );
    }

    /**
     * @param  array<string, mixed>  $overrides
     */
    private function makeActivity( array $overrides = [] ): SuspiciousActivity
    {
        return SuspiciousActivity::create( array_merge( [
            'type'       => SuspiciousActivity::TYPE_BRUTE_FORCE,
            'severity'   => SuspiciousActivity::SEVERITY_HIGH,
            'risk_score' => 75.5,
            'ip_address' => '203.0.113.1',
            'details'    => ['attempts' => 10],
        ], $overrides ) );
    }
}
