<?php

declare( strict_types=1 );

namespace Tests\Unit\Analytics\Models;

use ArtisanPackUI\SecurityAnalytics\Models\ThreatIndicator;
use Tests\Unit\Analytics\AnalyticsTestCase;

class ThreatIndicatorModelTest extends AnalyticsTestCase
{
    public function test_it_can_create_threat_indicator(): void
    {
        $indicator = ThreatIndicator::factory()->create( [
            'type'        => ThreatIndicator::TYPE_IP,
            'value'       => '198.51.100.10',
            'threat_type' => ThreatIndicator::THREAT_BRUTEFORCE,
        ] );

        $this->assertDatabaseHas( 'threat_indicators', [
            'id'          => $indicator->id,
            'type'        => ThreatIndicator::TYPE_IP,
            'value'       => '198.51.100.10',
            'threat_type' => ThreatIndicator::THREAT_BRUTEFORCE,
        ] );
    }

    public function test_it_casts_attributes(): void
    {
        $indicator = ThreatIndicator::factory()->create( [
            'confidence' => 75,
            'metadata'   => ['reports' => 10],
            'expires_at' => now()->addDays( 5 ),
        ] );

        $this->assertIsInt( $indicator->confidence );
        $this->assertIsArray( $indicator->metadata );
        $this->assertInstanceOf( \Carbon\Carbon::class, $indicator->first_seen_at );
        $this->assertInstanceOf( \Carbon\Carbon::class, $indicator->last_seen_at );
        $this->assertInstanceOf( \Carbon\Carbon::class, $indicator->expires_at );
    }

    public function test_it_maps_confidence_to_severity_on_create(): void
    {
        $critical = ThreatIndicator::factory()->create( ['confidence' => 90, 'severity' => null] );
        $medium   = ThreatIndicator::factory()->create( ['confidence' => 45, 'severity' => null] );
        $info     = ThreatIndicator::factory()->create( ['confidence' => 5, 'severity' => null] );

        $this->assertEquals( ThreatIndicator::SEVERITY_CRITICAL, $critical->severity );
        $this->assertEquals( ThreatIndicator::SEVERITY_MEDIUM, $medium->severity );
        $this->assertEquals( ThreatIndicator::SEVERITY_INFO, $info->severity );
    }

    public function test_it_defaults_seen_timestamps_on_create(): void
    {
        $indicator = ThreatIndicator::factory()->create( [
            'first_seen_at' => null,
            'last_seen_at'  => null,
        ] );

        $this->assertInstanceOf( \Carbon\Carbon::class, $indicator->first_seen_at );
        $this->assertInstanceOf( \Carbon\Carbon::class, $indicator->last_seen_at );
    }

    public function test_it_checks_expiry_and_active_state(): void
    {
        $expired = ThreatIndicator::factory()->create( ['expires_at' => now()->subDay()] );
        $active  = ThreatIndicator::factory()->create( ['expires_at' => now()->addDay()] );
        $never   = ThreatIndicator::factory()->create( ['expires_at' => null] );

        $this->assertTrue( $expired->isExpired() );
        $this->assertFalse( $expired->isActive() );

        $this->assertFalse( $active->isExpired() );
        $this->assertTrue( $active->isActive() );

        $this->assertFalse( $never->isExpired() );
        $this->assertTrue( $never->isActive() );
    }

    public function test_it_updates_last_seen(): void
    {
        $indicator = ThreatIndicator::factory()->create( ['last_seen_at' => now()->subWeek()] );

        $indicator->updateLastSeen();

        $this->assertTrue( $indicator->last_seen_at->isAfter( now()->subMinute() ) );
    }

    public function test_it_gets_and_sets_metadata(): void
    {
        $indicator = ThreatIndicator::factory()->create( ['metadata' => ['reports' => 3]] );

        $this->assertEquals( 3, $indicator->getMetadata( 'reports' ) );
        $this->assertEquals( 'default', $indicator->getMetadata( 'missing', 'default' ) );

        $indicator->setMetadata( 'source_id', 'abc' );
        $this->assertEquals( 'abc', $indicator->getMetadata( 'source_id' ) );
    }

    public function test_it_scopes_by_type_and_threat_type(): void
    {
        ThreatIndicator::factory()->count( 2 )->create( ['type' => ThreatIndicator::TYPE_IP, 'threat_type' => ThreatIndicator::THREAT_MALWARE] );
        ThreatIndicator::factory()->create( ['type' => ThreatIndicator::TYPE_DOMAIN, 'threat_type' => ThreatIndicator::THREAT_PHISHING] );

        $this->assertEquals( 2, ThreatIndicator::ofType( ThreatIndicator::TYPE_IP )->count() );
        $this->assertEquals( 1, ThreatIndicator::threatType( ThreatIndicator::THREAT_PHISHING )->count() );
    }

    public function test_it_scopes_active_and_expired(): void
    {
        ThreatIndicator::factory()->create( ['expires_at' => now()->addDay()] );
        ThreatIndicator::factory()->create( ['expires_at' => null] );
        ThreatIndicator::factory()->create( ['expires_at' => now()->subDay()] );

        $this->assertEquals( 2, ThreatIndicator::active()->count() );
        $this->assertEquals( 1, ThreatIndicator::expired()->count() );
    }

    public function test_it_scopes_from_source_and_high_confidence(): void
    {
        ThreatIndicator::factory()->create( ['source' => 'virustotal', 'confidence' => 90] );
        ThreatIndicator::factory()->create( ['source' => 'internal', 'confidence' => 30] );

        $this->assertEquals( 1, ThreatIndicator::fromSource( 'virustotal' )->count() );
        $this->assertEquals( 1, ThreatIndicator::highConfidence( 80 )->count() );
    }

    public function test_it_finds_active_indicator_by_value(): void
    {
        ThreatIndicator::factory()->create( [
            'type'       => ThreatIndicator::TYPE_IP,
            'value'      => '203.0.113.5',
            'expires_at' => now()->addWeek(),
        ] );

        $found   = ThreatIndicator::findActive( ThreatIndicator::TYPE_IP, '203.0.113.5' );
        $missing = ThreatIndicator::findActive( ThreatIndicator::TYPE_IP, '203.0.113.99' );

        $this->assertInstanceOf( ThreatIndicator::class, $found );
        $this->assertNull( $missing );
    }

    public function test_it_does_not_find_expired_indicator(): void
    {
        ThreatIndicator::factory()->create( [
            'type'       => ThreatIndicator::TYPE_IP,
            'value'      => '203.0.113.6',
            'expires_at' => now()->subDay(),
        ] );

        $this->assertNull( ThreatIndicator::findActive( ThreatIndicator::TYPE_IP, '203.0.113.6' ) );
    }
}
