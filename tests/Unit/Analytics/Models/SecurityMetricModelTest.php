<?php

declare( strict_types=1 );

namespace Tests\Unit\Analytics\Models;

use ArtisanPackUI\SecurityAnalytics\Models\SecurityMetric;
use Tests\Unit\Analytics\AnalyticsTestCase;

class SecurityMetricModelTest extends AnalyticsTestCase
{
    public function test_it_can_create_security_metric(): void
    {
        $metric = SecurityMetric::factory()->create( [
            'category'    => SecurityMetric::CATEGORY_AUTHENTICATION,
            'metric_name' => 'failed_logins',
            'metric_type' => SecurityMetric::TYPE_COUNTER,
        ] );

        $this->assertDatabaseHas( 'security_metrics', [
            'id'          => $metric->id,
            'category'    => SecurityMetric::CATEGORY_AUTHENTICATION,
            'metric_name' => 'failed_logins',
        ] );
    }

    public function test_it_casts_attributes(): void
    {
        $metric = SecurityMetric::factory()->create( [
            'tags'        => ['environment' => 'production'],
            'recorded_at' => now(),
        ] );

        $this->assertIsArray( $metric->tags );
        $this->assertInstanceOf( \Carbon\Carbon::class, $metric->recorded_at );
        // Decimal cast returns a string representation with fixed precision.
        $this->assertEqualsWithDelta( (float) $metric->value, (float) $metric->fresh()->value, 0.0000001 );
    }

    public function test_it_gets_tag_values(): void
    {
        $metric = SecurityMetric::factory()->create( [
            'tags' => ['environment' => 'staging', 'host' => 'web-1'],
        ] );

        $this->assertEquals( 'staging', $metric->getTag( 'environment' ) );
        $this->assertEquals( 'web-1', $metric->getTag( 'host' ) );
        $this->assertEquals( 'fallback', $metric->getTag( 'region', 'fallback' ) );
    }

    public function test_it_checks_for_tag_presence(): void
    {
        $metric = SecurityMetric::factory()->create( [
            'tags' => ['environment' => 'production'],
        ] );

        $this->assertTrue( $metric->hasTag( 'environment' ) );
        $this->assertFalse( $metric->hasTag( 'region' ) );
    }

    public function test_it_scopes_by_category_metric_and_type(): void
    {
        SecurityMetric::factory()->count( 2 )->create( [
            'category'    => SecurityMetric::CATEGORY_API,
            'metric_name' => 'api_requests',
            'metric_type' => SecurityMetric::TYPE_COUNTER,
        ] );
        SecurityMetric::factory()->create( [
            'category'    => SecurityMetric::CATEGORY_SYSTEM,
            'metric_name' => 'cpu_load',
            'metric_type' => SecurityMetric::TYPE_GAUGE,
        ] );

        $this->assertEquals( 2, SecurityMetric::category( SecurityMetric::CATEGORY_API )->count() );
        $this->assertEquals( 2, SecurityMetric::metric( 'api_requests' )->count() );
        $this->assertEquals( 2, SecurityMetric::metricName( 'api_requests' )->count() );
        $this->assertEquals( 1, SecurityMetric::ofType( SecurityMetric::TYPE_GAUGE )->count() );
    }

    public function test_it_scopes_between_dates(): void
    {
        SecurityMetric::factory()->create( ['recorded_at' => now()->subHours( 2 )] );
        SecurityMetric::factory()->create( ['recorded_at' => now()->subHours( 10 )] );

        $count = SecurityMetric::between( now()->subHours( 5 ), now() )->count();

        $this->assertEquals( 1, $count );
    }

    public function test_it_scopes_with_tag(): void
    {
        SecurityMetric::factory()->create( ['tags' => ['environment' => 'production']] );
        SecurityMetric::factory()->create( ['tags' => ['environment' => 'staging']] );

        $this->assertEquals( 1, SecurityMetric::withTag( 'environment', 'production' )->count() );
        $this->assertEquals( 2, SecurityMetric::withTag( 'environment' )->count() );
    }
}
