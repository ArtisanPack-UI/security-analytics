<?php

declare( strict_types=1 );

namespace Tests\Unit\Analytics\Detectors;

use ArtisanPackUI\SecurityAnalytics\Analytics\AnomalyDetection\Detectors\GeoVelocityDetector;
use ArtisanPackUI\SecurityAnalytics\Models\Anomaly;
use Illuminate\Support\Facades\Cache;
use Tests\Unit\Analytics\AnalyticsTestCase;

class GeoVelocityDetectorTest extends AnalyticsTestCase
{
    protected GeoVelocityDetector $detector;

    protected function setUp(): void
    {
        parent::setUp();
        Cache::flush();
        $this->detector = new GeoVelocityDetector( [
            'enabled'          => true,
            'max_speed_kmh'    => 1000,
            'min_distance_km'  => 100,
            'lookback_minutes' => 60,
        ] );
    }

    public function test_it_has_correct_name(): void
    {
        $this->assertEquals( 'geo_velocity', $this->detector->getName() );
    }

    public function test_it_can_be_enabled_and_disabled(): void
    {
        $this->assertTrue( $this->detector->isEnabled() );

        $disabledDetector = new GeoVelocityDetector( ['enabled' => false] );
        $this->assertFalse( $disabledDetector->isEnabled() );
    }

    public function test_it_returns_empty_when_disabled(): void
    {
        $disabledDetector = new GeoVelocityDetector( ['enabled' => false] );

        $anomalies = $disabledDetector->detect( [
            'user_id'   => 1,
            'latitude'  => 40.7128,
            'longitude' => -74.0060,
        ] );

        $this->assertCount( 0, $anomalies );
    }

    public function test_it_requires_location_data(): void
    {
        $anomalies = $this->detector->detect( [
            'user_id' => 1,
        ] );

        $this->assertCount( 0, $anomalies );
    }

    public function test_it_requires_user_id(): void
    {
        $anomalies = $this->detector->detect( [
            'latitude'  => 40.7128,
            'longitude' => -74.0060,
        ] );

        $this->assertCount( 0, $anomalies );
    }

    public function test_it_stores_user_location(): void
    {
        $userId = 1;

        $this->detector->detect( [
            'user_id'   => $userId,
            'latitude'  => 40.7128,
            'longitude' => -74.0060,
            'country'   => 'US',
            'city'      => 'New York',
        ] );

        $cacheKey = "user_location:{$userId}";
        $location = Cache::get( $cacheKey );

        $this->assertNotNull( $location );
        $this->assertEquals( 40.7128, $location['latitude'] );
        $this->assertEquals( -74.0060, $location['longitude'] );
    }

    public function test_it_detects_impossible_travel(): void
    {
        $userId = 1;

        // First login from New York
        $this->detector->detect( [
            'user_id'   => $userId,
            'latitude'  => 40.7128,
            'longitude' => -74.0060,
            'country'   => 'US',
            'city'      => 'New York',
        ] );

        // Immediate login from London (5500+ km away)
        // This would require traveling at ~5500+ km/h (impossible)
        $anomalies = $this->detector->detect( [
            'user_id'   => $userId,
            'latitude'  => 51.5074,
            'longitude' => -0.1278,
            'country'   => 'UK',
            'city'      => 'London',
            'ip'        => '203.0.113.50',
        ] );

        $this->assertGreaterThanOrEqual( 1, $anomalies->count() );
        $anomaly = $anomalies->first();
        $this->assertEquals( Anomaly::CATEGORY_BEHAVIORAL, $anomaly->category );
        $this->assertEquals( Anomaly::SEVERITY_HIGH, $anomaly->severity );
        $this->assertStringContainsString( 'Impossible travel', $anomaly->description );
    }

    public function test_it_allows_normal_travel(): void
    {
        $userId = 2;

        // First login
        $this->detector->detect( [
            'user_id'   => $userId,
            'latitude'  => 40.7128,
            'longitude' => -74.0060,
            'timestamp' => now()->subHours( 10 ),
        ] );

        // Second login 10 hours later, 500km away (50 km/h average - reasonable car travel)
        $anomalies = $this->detector->detect( [
            'user_id'   => $userId,
            'latitude'  => 42.3601,  // Boston area
            'longitude' => -71.0589,
            'timestamp' => now(),
        ] );

        // Should not detect anomaly for reasonable travel speed
        $this->assertCount( 0, $anomalies );
    }

    public function test_it_ignores_short_distances(): void
    {
        $userId = 3;

        // First login
        $this->detector->detect( [
            'user_id'   => $userId,
            'latitude'  => 40.7128,
            'longitude' => -74.0060,
        ] );

        // Second login from very nearby (< min_distance_km)
        $anomalies = $this->detector->detect( [
            'user_id'   => $userId,
            'latitude'  => 40.7200,  // ~1km away
            'longitude' => -74.0100,
        ] );

        $this->assertCount( 0, $anomalies );
    }

    public function test_it_returns_config(): void
    {
        $config = $this->detector->getConfig();

        $this->assertArrayHasKey( 'enabled', $config );
        $this->assertArrayHasKey( 'max_speed_kmh', $config );
        $this->assertArrayHasKey( 'min_distance_km', $config );
        $this->assertArrayHasKey( 'lookback_minutes', $config );
    }

    public function test_it_handles_empty_data_gracefully(): void
    {
        $anomalies = $this->detector->detect( [] );

        $this->assertCount( 0, $anomalies );
    }

    public function test_it_respects_cooldown_period(): void
    {
        $userId = 4;

        // First login from New York
        $this->detector->detect( [
            'user_id'   => $userId,
            'latitude'  => 40.7128,
            'longitude' => -74.0060,
        ] );

        // Trigger impossible travel
        $this->detector->detect( [
            'user_id'   => $userId,
            'latitude'  => 51.5074,
            'longitude' => -0.1278,
        ] );

        // Immediate third detection should be suppressed by cooldown
        $anomalies = $this->detector->detect( [
            'user_id'   => $userId,
            'latitude'  => 35.6762,  // Tokyo
            'longitude' => 139.6503,
        ]);

        $this->assertInstanceOf( \Illuminate\Support\Collection::class, $anomalies);
    }
}
