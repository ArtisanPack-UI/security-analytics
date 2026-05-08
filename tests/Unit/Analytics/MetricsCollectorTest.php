<?php

declare( strict_types=1 );

namespace Tests\Unit\Analytics;

use ArtisanPackUI\SecurityAnalytics\Analytics\MetricsCollector;
use ArtisanPackUI\SecurityAnalytics\Models\SecurityMetric;

class MetricsCollectorTest extends AnalyticsTestCase
{
    protected MetricsCollector $collector;

    protected function setUp(): void
    {
        parent::setUp();
        $this->collector = new MetricsCollector;
    }

    public function test_it_records_counter_metric(): void
    {
        $this->collector->counter( 'auth.login', 1, SecurityMetric::CATEGORY_AUTHENTICATION );

        $this->assertDatabaseHas( 'security_metrics', [
            'metric_name' => 'auth.login',
            'metric_type' => SecurityMetric::TYPE_COUNTER,
            'category'    => SecurityMetric::CATEGORY_AUTHENTICATION,
            'value'       => 1,
        ] );
    }

    public function test_it_records_gauge_metric(): void
    {
        $this->collector->gauge( 'active_sessions', 42, SecurityMetric::CATEGORY_SYSTEM );

        $this->assertDatabaseHas( 'security_metrics', [
            'metric_name' => 'active_sessions',
            'metric_type' => SecurityMetric::TYPE_GAUGE,
            'category'    => SecurityMetric::CATEGORY_SYSTEM,
            'value'       => 42,
        ] );
    }

    public function test_it_records_timing_metric(): void
    {
        $this->collector->timing( 'auth.duration', 150.5, SecurityMetric::CATEGORY_PERFORMANCE );

        $this->assertDatabaseHas( 'security_metrics', [
            'metric_name' => 'auth.duration',
            'metric_type' => SecurityMetric::TYPE_TIMING,
            'category'    => SecurityMetric::CATEGORY_PERFORMANCE,
            'value'       => 150.5,
        ] );
    }

    public function test_it_times_callback_execution(): void
    {
        $result = $this->collector->time( 'operation', function () {
            usleep( 10000 ); // 10ms

            return 'result';
        } );

        $this->assertEquals( 'result', $result );

        $metric = SecurityMetric::where( 'metric_name', 'operation' )->first();
        $this->assertNotNull( $metric );
        $this->assertGreaterThan( 0, $metric->value );
    }

    public function test_it_batches_metrics_when_enabled(): void
    {
        $this->collector->enableBatching( 5 );

        $this->collector->counter( 'test.metric', 1 );
        $this->collector->counter( 'test.metric', 2 );

        // Should not be in database yet
        $this->assertDatabaseMissing( 'security_metrics', ['metric_name' => 'test.metric'] );

        // Add more to trigger flush
        $this->collector->counter( 'test.metric', 3 );
        $this->collector->counter( 'test.metric', 4 );
        $this->collector->counter( 'test.metric', 5 );

        // Now should be flushed
        $this->assertEquals( 5, SecurityMetric::where( 'metric_name', 'test.metric' )->count() );
    }

    public function test_it_flushes_buffer_on_disable(): void
    {
        $this->collector->enableBatching( 100 );
        $this->collector->counter( 'test.metric', 1 );
        $this->collector->counter( 'test.metric', 2 );

        $this->assertDatabaseMissing( 'security_metrics', ['metric_name' => 'test.metric'] );

        $this->collector->disableBatching();

        $this->assertEquals( 2, SecurityMetric::where( 'metric_name', 'test.metric' )->count() );
    }

    public function test_it_records_auth_event(): void
    {
        $this->collector->recordAuthEvent( 'login', true, ['user_id' => 1] );

        $metric = SecurityMetric::where( 'metric_name', 'auth.login' )
            ->where( 'category', SecurityMetric::CATEGORY_AUTHENTICATION )
            ->first();

        $this->assertNotNull( $metric );
        $this->assertTrue( $metric->tags['success'] );
        $this->assertEquals( 1, $metric->tags['user_id'] );
    }

    public function test_it_records_threat_event(): void
    {
        $this->collector->recordThreatEvent( 'brute_force', 'high', ['ip' => '192.168.1.1'] );

        $metric = SecurityMetric::where( 'metric_name', 'threat.brute_force' )
            ->where( 'category', SecurityMetric::CATEGORY_THREAT )
            ->first();

        $this->assertNotNull( $metric );
        $this->assertEquals( 'high', $metric->tags['severity'] );
    }

    public function test_it_aggregates_metrics(): void
    {
        $this->collector->counter( 'test.metric', 10, SecurityMetric::CATEGORY_AUTHENTICATION );
        $this->collector->counter( 'test.metric', 20, SecurityMetric::CATEGORY_AUTHENTICATION );
        $this->collector->counter( 'test.metric', 30, SecurityMetric::CATEGORY_AUTHENTICATION );

        $aggregated = $this->collector->getAggregatedMetrics(
            SecurityMetric::CATEGORY_AUTHENTICATION,
            now()->subHour(),
            now(),
            ['metric_name' => 'test.metric'],
        );

        $this->assertEquals( 3, $aggregated['count'] );
        $this->assertEquals( 60, $aggregated['sum'] );
        $this->assertEquals( 20, $aggregated['avg'] );
        $this->assertEquals( 10, $aggregated['min'] );
        $this->assertEquals( 30, $aggregated['max'] );
    }

    public function test_it_cleans_up_old_metrics(): void
    {
        // Create old metric
        SecurityMetric::create( [
            'metric_name' => 'old.metric',
            'metric_type' => SecurityMetric::TYPE_COUNTER,
            'category'    => SecurityMetric::CATEGORY_SYSTEM,
            'value'       => 1,
            'recorded_at' => now()->subDays( 100 ),
        ] );

        // Create recent metric
        $this->collector->counter( 'new.metric', 1 );

        $deleted = $this->collector->cleanup( 90 );

        $this->assertEquals( 1, $deleted );
        $this->assertDatabaseMissing( 'security_metrics', ['metric_name' => 'old.metric'] );
        $this->assertDatabaseHas( 'security_metrics', ['metric_name' => 'new.metric'] );
    }
}
