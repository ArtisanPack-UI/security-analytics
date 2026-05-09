<?php

declare( strict_types=1 );

namespace Tests\Unit\Analytics;

use ArtisanPackUI\SecurityAnalytics\Analytics\Dashboard\DashboardDataProvider;
use ArtisanPackUI\SecurityAnalytics\Models\AlertHistory;
use ArtisanPackUI\SecurityAnalytics\Models\Anomaly;
use ArtisanPackUI\SecurityAnalytics\Models\SecurityIncident;
use ArtisanPackUI\SecurityAnalytics\Models\SecurityMetric;
use ArtisanPackUI\SecurityAnalytics\Models\ThreatIndicator;

class DashboardDataProviderTest extends AnalyticsTestCase
{
    protected DashboardDataProvider $provider;

    protected function setUp(): void
    {
        parent::setUp();
        $this->provider = new DashboardDataProvider();
    }

    public function test_it_returns_complete_dashboard_data(): void
    {
        $data = $this->provider->getDashboardData( 24 );

        $this->assertArrayHasKey( 'overview', $data );
        $this->assertArrayHasKey( 'threat_summary', $data );
        $this->assertArrayHasKey( 'authentication_activity', $data );
        $this->assertArrayHasKey( 'anomaly_feed', $data );
        $this->assertArrayHasKey( 'incident_status', $data );
        $this->assertArrayHasKey( 'alert_summary', $data );
        $this->assertArrayHasKey( 'top_threats', $data );
        $this->assertArrayHasKey( 'geographic_data', $data );
        $this->assertArrayHasKey( 'generated_at', $data );
    }

    public function test_it_gets_overview_statistics(): void
    {
        // Create test data
        SecurityMetric::factory()->count( 5 )->create( ['recorded_at' => now()->subHours( 2 )] );
        Anomaly::factory()->count( 3 )->create( ['detected_at' => now()->subHours( 2 )] );
        Anomaly::factory()->critical()->create( ['detected_at' => now()->subHours( 2 )] );
        SecurityIncident::factory()->open()->create();
        ThreatIndicator::factory()->active()->count( 2 )->create();

        $overview = $this->provider->getOverview( 24 );

        $this->assertEquals( 5, $overview['total_events'] );
        $this->assertEquals( 4, $overview['anomalies_detected'] );
        $this->assertEquals( 1, $overview['active_incidents'] );
        $this->assertEquals( 2, $overview['threat_indicators'] );
        $this->assertEquals( 1, $overview['critical_anomalies'] );
        $this->assertEquals( 24, $overview['period_hours'] );
    }

    public function test_it_gets_threat_summary(): void
    {
        Anomaly::factory()->create( ['detected_at' => now()->subHours( 2 ), 'severity' => 'critical', 'category' => Anomaly::CATEGORY_THREAT] );
        Anomaly::factory()->count( 2 )->create( ['detected_at' => now()->subHours( 2 ), 'severity' => 'high', 'category' => Anomaly::CATEGORY_AUTHENTICATION] );
        Anomaly::factory()->count( 3 )->create( ['detected_at' => now()->subHours( 2 ), 'severity' => 'medium'] );

        $summary = $this->provider->getThreatSummary( 24 );

        $this->assertArrayHasKey( 'by_severity', $summary );
        $this->assertArrayHasKey( 'by_category', $summary );
        $this->assertArrayHasKey( 'by_detector', $summary );
        $this->assertArrayHasKey( 'trend', $summary );

        $this->assertEquals( 1, $summary['by_severity']['critical'] );
        $this->assertEquals( 2, $summary['by_severity']['high'] );
        $this->assertEquals( 3, $summary['by_severity']['medium'] );
    }

    public function test_it_gets_authentication_activity(): void
    {
        // Create authentication metrics
        SecurityMetric::factory()->authentication()->create( [
            'metric_name' => 'auth.attempts',
            'value'       => 100,
            'recorded_at' => now()->subHours( 2 ),
        ] );

        SecurityMetric::factory()->authentication()->create( [
            'metric_name' => 'auth.login',
            'value'       => 80,
            'tags'        => ['success' => true],
            'recorded_at' => now()->subHours( 2 ),
        ] );

        SecurityMetric::factory()->authentication()->create( [
            'metric_name' => 'auth.failed',
            'value'       => 20,
            'recorded_at' => now()->subHours( 2 ),
        ] );

        $activity = $this->provider->getAuthenticationActivity( 24 );

        $this->assertArrayHasKey( 'total_attempts', $activity );
        $this->assertArrayHasKey( 'successful_logins', $activity );
        $this->assertArrayHasKey( 'failed_logins', $activity );
        $this->assertArrayHasKey( 'lockouts', $activity );
        $this->assertArrayHasKey( 'success_rate', $activity );
        $this->assertArrayHasKey( 'hourly_activity', $activity );
    }

    public function test_it_gets_anomaly_feed(): void
    {
        Anomaly::factory()->count( 5 )->create( ['detected_at' => now()->subHours( 2 )] );
        Anomaly::factory()->count( 3 )->create( ['detected_at' => now()->subDays( 2 )] ); // Outside range

        $feed = $this->provider->getAnomalyFeed( 24, 10 );

        $this->assertCount( 5, $feed );

        $firstAnomaly = $feed[0];
        $this->assertArrayHasKey( 'id', $firstAnomaly );
        $this->assertArrayHasKey( 'category', $firstAnomaly );
        $this->assertArrayHasKey( 'severity', $firstAnomaly );
        $this->assertArrayHasKey( 'description', $firstAnomaly );
        $this->assertArrayHasKey( 'score', $firstAnomaly );
        $this->assertArrayHasKey( 'detected_at', $firstAnomaly );
        $this->assertArrayHasKey( 'is_resolved', $firstAnomaly );
    }

    public function test_it_gets_incident_status(): void
    {
        SecurityIncident::factory()->open()->count( 2 )->create();
        SecurityIncident::factory()->investigating()->create();
        SecurityIncident::factory()->contained()->create();
        SecurityIncident::factory()->resolved()->create();
        SecurityIncident::factory()->closed()->count( 3 )->create();

        $status = $this->provider->getIncidentStatus();

        $this->assertEquals( 8, $status['total'] );
        $this->assertEquals( 2, $status['by_status']['open'] );
        $this->assertEquals( 1, $status['by_status']['investigating'] );
        $this->assertEquals( 1, $status['by_status']['contained'] );
        $this->assertEquals( 1, $status['by_status']['resolved'] );
        $this->assertEquals( 3, $status['by_status']['closed'] );
        $this->assertArrayHasKey( 'by_severity', $status );
        $this->assertArrayHasKey( 'unassigned', $status );
        $this->assertArrayHasKey( 'avg_time_to_resolve', $status );
    }

    public function test_it_gets_alert_summary(): void
    {
        AlertHistory::factory()->count( 3 )->create( [
            'status'     => AlertHistory::STATUS_SENT,
            'created_at' => now()->subHours( 2 ),
        ] );
        AlertHistory::factory()->count( 2 )->create( [
            'status'     => AlertHistory::STATUS_ACKNOWLEDGED,
            'created_at' => now()->subHours( 2 ),
        ] );
        AlertHistory::factory()->create( [
            'status'     => AlertHistory::STATUS_FAILED,
            'created_at' => now()->subHours( 2 ),
        ] );

        $summary = $this->provider->getAlertSummary( 24 );

        $this->assertEquals( 6, $summary['total'] );
        $this->assertArrayHasKey( 'by_status', $summary );
        $this->assertArrayHasKey( 'by_channel', $summary );
        $this->assertEquals( 3, $summary['unacknowledged'] );
        $this->assertEquals( 1, $summary['failed'] );
    }

    public function test_it_gets_top_threats(): void
    {
        Anomaly::factory()->create( ['detected_at' => now()->subHours( 2 ), 'score' => 95] );
        Anomaly::factory()->create( ['detected_at' => now()->subHours( 2 ), 'score' => 85] );
        Anomaly::factory()->create( ['detected_at' => now()->subHours( 2 ), 'score' => 75] );
        Anomaly::factory()->create( ['detected_at' => now()->subHours( 2 ), 'score' => 50] );
        Anomaly::factory()->create( ['detected_at' => now()->subHours( 2 ), 'score' => 30] );

        $threats = $this->provider->getTopThreats( 24, 3 );

        $this->assertCount( 3, $threats );
        $this->assertEquals( 95, $threats[0]['score'] );
        $this->assertEquals( 85, $threats[1]['score'] );
        $this->assertEquals( 75, $threats[2]['score'] );
    }

    public function test_it_gets_geographic_data(): void
    {
        ThreatIndicator::factory()->active()->create( ['metadata' => ['country' => 'US']] );
        ThreatIndicator::factory()->active()->create( ['metadata' => ['country' => 'US']] );
        ThreatIndicator::factory()->active()->create( ['metadata' => ['country' => 'CN']] );

        Anomaly::factory()->create( [
            'detected_at' => now()->subHours( 2 ),
            'metadata'    => ['country' => 'RU'],
        ] );

        $geoData = $this->provider->getGeographicData( 24 );

        $this->assertArrayHasKey( 'threats_by_country', $geoData );
        $this->assertArrayHasKey( 'anomalies_by_country', $geoData );
    }

    public function test_it_calculates_trend_correctly(): void
    {
        // Create anomalies in current period
        Anomaly::factory()->count( 10 )->create( ['detected_at' => now()->subHours( 12 )] );

        // Create anomalies in previous period
        Anomaly::factory()->count( 5 )->create( ['detected_at' => now()->subHours( 36 )] );

        $summary = $this->provider->getThreatSummary( 24 );

        $this->assertArrayHasKey( 'trend', $summary );
        $this->assertEquals( 10, $summary['trend']['current'] );
        $this->assertEquals( 5, $summary['trend']['previous'] );
        $this->assertEquals( 100, $summary['trend']['change_percent'] ); // 100% increase
        $this->assertEquals( 'up', $summary['trend']['direction'] );
    }

    public function test_it_handles_empty_data(): void
    {
        $overview = $this->provider->getOverview( 24 );

        $this->assertEquals( 0, $overview['total_events'] );
        $this->assertEquals( 0, $overview['anomalies_detected'] );
        $this->assertEquals( 0, $overview['active_incidents'] );
    }

    public function test_it_respects_hours_parameter(): void
    {
        // Create anomaly within 6 hours
        Anomaly::factory()->create( ['detected_at' => now()->subHours( 3 )] );

        // Create anomaly outside 6 hours but within 24 hours
        Anomaly::factory()->create( ['detected_at' => now()->subHours( 12 )] );

        $overview6h  = $this->provider->getOverview( 6 );
        $overview24h = $this->provider->getOverview( 24 );

        $this->assertEquals( 1, $overview6h['anomalies_detected'] );
        $this->assertEquals( 2, $overview24h['anomalies_detected'] );
    }
}
