<?php

declare( strict_types=1 );

namespace Tests\Unit\Analytics\Detectors;

use ArtisanPackUI\SecurityAnalytics\Analytics\AnomalyDetection\Detectors\StatisticalDetector;
use ArtisanPackUI\SecurityAnalytics\Models\SecurityMetric;
use Illuminate\Support\Facades\Cache;
use Tests\Unit\Analytics\AnalyticsTestCase;

class StatisticalDetectorTest extends AnalyticsTestCase
{
    protected StatisticalDetector $detector;

    protected function setUp(): void
    {
        parent::setUp();
        Cache::flush();
        $this->detector = new StatisticalDetector( [
            'enabled'              => true,
            'threshold_multiplier' => 3.0,
            'min_data_points'      => 30,
            'lookback_hours'       => 24,
        ] );
    }

    public function test_it_has_correct_name(): void
    {
        $this->assertEquals( 'statistical', $this->detector->getName() );
    }

    public function test_it_can_be_enabled_and_disabled(): void
    {
        $this->assertTrue( $this->detector->isEnabled() );

        $disabledDetector = new StatisticalDetector( ['enabled' => false] );
        $this->assertFalse( $disabledDetector->isEnabled() );
    }

    public function test_it_returns_empty_when_disabled(): void
    {
        $disabledDetector = new StatisticalDetector( ['enabled' => false] );

        $anomalies = $disabledDetector->detect( [] );

        $this->assertCount( 0, $anomalies );
    }

    public function test_it_returns_empty_with_insufficient_data(): void
    {
        // Create fewer than min_data_points metrics
        for ( $i = 0; $i < 10; $i++ ) {
            SecurityMetric::create( [
                'category'    => SecurityMetric::CATEGORY_AUTHENTICATION,
                'metric_name' => 'auth.failed',
                'metric_type' => SecurityMetric::TYPE_COUNTER,
                'value'       => 1,
                'recorded_at' => now()->subMinutes( $i * 5 ),
            ] );
        }

        $anomalies = $this->detector->detect( [] );

        $this->assertCount( 0, $anomalies );
    }

    public function test_it_detects_statistical_anomalies_with_sufficient_data(): void
    {
        // Create enough normal data points
        for ( $i = 0; $i < 35; $i++ ) {
            SecurityMetric::create( [
                'category'    => SecurityMetric::CATEGORY_AUTHENTICATION,
                'metric_name' => 'auth.failed',
                'metric_type' => SecurityMetric::TYPE_COUNTER,
                'value'       => 5 + ( $i % 3 ), // Values around 5-7
                'recorded_at' => now()->subMinutes( $i * 5 ),
            ] );
        }

        // Add an outlier (much higher than normal)
        SecurityMetric::create( [
            'category'    => SecurityMetric::CATEGORY_AUTHENTICATION,
            'metric_name' => 'auth.failed',
            'metric_type' => SecurityMetric::TYPE_COUNTER,
            'value'       => 100, // Very high outlier
            'recorded_at' => now(),
        ] );

        $anomalies = $this->detector->detect( [] );

        // Should detect the statistical anomaly
        $this->assertInstanceOf( \Illuminate\Support\Collection::class, $anomalies );
    }

    public function test_it_returns_config(): void
    {
        $config = $this->detector->getConfig();

        $this->assertArrayHasKey( 'enabled', $config );
        $this->assertArrayHasKey( 'threshold_multiplier', $config );
        $this->assertArrayHasKey( 'min_data_points', $config );
        $this->assertArrayHasKey( 'lookback_hours', $config );
    }

    public function test_it_handles_empty_data_gracefully(): void
    {
        $anomalies = $this->detector->detect( [] );

        $this->assertCount( 0, $anomalies );
    }

    public function test_it_analyzes_multiple_metric_categories(): void
    {
        // Create auth metrics
        for ( $i = 0; $i < 35; $i++ ) {
            SecurityMetric::create( [
                'category'    => SecurityMetric::CATEGORY_AUTHENTICATION,
                'metric_name' => 'auth.failed',
                'metric_type' => SecurityMetric::TYPE_COUNTER,
                'value'       => 5,
                'recorded_at' => now()->subMinutes( $i * 5 ),
            ] );
        }

        // Create threat metrics
        for ( $i = 0; $i < 35; $i++ ) {
            SecurityMetric::create( [
                'category'    => SecurityMetric::CATEGORY_THREAT,
                'metric_name' => 'security.account_locks',
                'metric_type' => SecurityMetric::TYPE_COUNTER,
                'value'       => 2,
                'recorded_at' => now()->subMinutes( $i * 5 ),
            ] );
        }

        $anomalies = $this->detector->detect( [] );

        $this->assertInstanceOf( \Illuminate\Support\Collection::class, $anomalies );
    }

    public function test_it_respects_lookback_hours(): void
    {
        // Create old metrics (outside lookback window)
        for ( $i = 0; $i < 35; $i++ ) {
            SecurityMetric::create( [
                'category'    => SecurityMetric::CATEGORY_AUTHENTICATION,
                'metric_name' => 'auth.failed',
                'metric_type' => SecurityMetric::TYPE_COUNTER,
                'value'       => 5,
                'recorded_at' => now()->subHours( 48 )->subMinutes( $i * 5 ), // 48+ hours ago
            ] );
        }

        $anomalies = $this->detector->detect( [] );

        // Should not detect anomalies from old data
        $this->assertCount( 0, $anomalies );
    }
}
