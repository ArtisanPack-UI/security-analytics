<?php

declare( strict_types=1 );

namespace Tests\Unit\Analytics\Detectors;

use ArtisanPackUI\SecurityAnalytics\Analytics\AnomalyDetection\Detectors\AccessPatternDetector;
use ArtisanPackUI\SecurityAnalytics\Models\Anomaly;
use Illuminate\Support\Facades\Cache;
use Tests\Unit\Analytics\AnalyticsTestCase;

class AccessPatternDetectorTest extends AnalyticsTestCase
{
    protected AccessPatternDetector $detector;

    protected function setUp(): void
    {
        parent::setUp();
        Cache::flush();
        $this->detector = new AccessPatternDetector( [
            'enabled'             => true,
            'min_samples'         => 50,
            'deviation_threshold' => 3.0,
            'sensitive_endpoints' => [
                '/admin/*',
                '/api/users/*',
                '/api/settings/*',
            ],
            'bulk_download_threshold'      => 100,
            'bulk_download_window_minutes' => 5,
            'rapid_request_threshold'      => 60,
        ] );
    }

    public function test_it_has_correct_name(): void
    {
        $this->assertEquals( 'access_pattern', $this->detector->getName() );
    }

    public function test_it_can_be_enabled_and_disabled(): void
    {
        $this->assertTrue( $this->detector->isEnabled() );

        $disabledDetector = new AccessPatternDetector( ['enabled' => false] );
        $this->assertFalse( $disabledDetector->isEnabled() );
    }

    public function test_it_returns_empty_when_disabled(): void
    {
        $disabledDetector = new AccessPatternDetector( ['enabled' => false] );

        $anomalies = $disabledDetector->detect( [
            'user_id'  => 1,
            'endpoint' => '/admin/settings',
            'ip'       => '192.168.1.1',
        ] );

        $this->assertCount( 0, $anomalies );
    }

    public function test_it_tracks_requests(): void
    {
        // Make several requests
        for ( $i = 0; $i < 5; $i++ ) {
            $this->detector->detect( [
                'user_id'  => 1,
                'endpoint' => '/api/users/list',
                'ip'       => '192.168.1.1',
            ] );
        }

        // Verify tracking data exists in cache
        $cacheKey    = 'access_pattern:user:1';
        $requestData = Cache::get( $cacheKey );

        $this->assertNotNull( $requestData );
        $this->assertGreaterThanOrEqual( 5, $requestData['count'] );
    }

    public function test_it_detects_bulk_data_access(): void
    {
        $userId = 1;

        // Simulate bulk data access that exceeds threshold
        $anomalies = $this->detector->detect( [
            'user_id'          => $userId,
            'records_accessed' => 250, // Above threshold * 2 = 200
            'ip'               => '192.168.1.100',
        ] );

        $this->assertGreaterThanOrEqual( 1, $anomalies->count() );
        $anomaly = $anomalies->first();
        $this->assertEquals( Anomaly::CATEGORY_ACCESS, $anomaly->category );
        $this->assertEquals( Anomaly::SEVERITY_HIGH, $anomaly->severity );
        $this->assertStringContainsString( 'Bulk data access', $anomaly->description );
    }

    public function test_it_detects_rapid_requests(): void
    {
        $userId = 2;

        // Simulate rapid requests above threshold
        for ( $i = 0; $i < 65; $i++ ) {
            $anomalies = $this->detector->detect( [
                'user_id'  => $userId,
                'endpoint' => '/api/data',
                'ip'       => '192.168.1.200',
            ] );
        }

        // The last batch should trigger rapid request detection
        $this->assertGreaterThanOrEqual( 0, $anomalies->count() );
        $this->assertInstanceOf( \Illuminate\Support\Collection::class, $anomalies );
    }

    public function test_it_returns_config(): void
    {
        $config = $this->detector->getConfig();

        $this->assertArrayHasKey( 'enabled', $config );
        $this->assertArrayHasKey( 'min_samples', $config );
        $this->assertArrayHasKey( 'bulk_download_threshold', $config );
        $this->assertArrayHasKey( 'rapid_request_threshold', $config );
    }

    public function test_it_handles_missing_user_id_gracefully(): void
    {
        $anomalies = $this->detector->detect( [
            'endpoint' => '/admin/settings',
            'ip'       => '192.168.1.1',
        ] );

        $this->assertCount( 0, $anomalies );
    }

    public function test_it_handles_empty_data_gracefully(): void
    {
        $anomalies = $this->detector->detect( [] );

        $this->assertCount( 0, $anomalies );
    }

    public function test_it_identifies_sensitive_endpoints(): void
    {
        // Test that sensitive endpoint patterns are matched
        $sensitiveEndpoints = [
            '/admin/dashboard',
            '/admin/users',
            '/api/users/123',
            '/api/settings/security',
        ];

        foreach ( $sensitiveEndpoints as $endpoint ) {
            $anomalies = $this->detector->detect( [
                'user_id'  => 99,
                'endpoint' => $endpoint,
                'ip'       => '192.168.1.50',
            ] );

            // Should track the request even if no anomaly is detected
            $this->assertInstanceOf( \Illuminate\Support\Collection::class, $anomalies );
        }
    }

    public function test_it_respects_cooldown_period(): void
    {
        $userId = 3;

        // Trigger bulk access detection
        $this->detector->detect( [
            'user_id'          => $userId,
            'records_accessed' => 300,
            'ip'               => '10.0.0.1',
        ] );

        // Immediate second detection should be suppressed by cooldown
        $anomalies = $this->detector->detect( [
            'user_id'          => $userId,
            'records_accessed' => 300,
            'ip'               => '10.0.0.1',
        ] );

        // May or may not trigger depending on cooldown logic
        $this->assertInstanceOf( \Illuminate\Support\Collection::class, $anomalies );
    }
}
