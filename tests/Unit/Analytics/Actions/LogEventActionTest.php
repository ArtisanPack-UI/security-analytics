<?php

declare( strict_types=1 );

namespace Tests\Unit\Analytics\Actions;

use ArtisanPackUI\SecurityAnalytics\Analytics\IncidentResponse\Actions\LogEventAction;
use ArtisanPackUI\SecurityAnalytics\Models\Anomaly;
use ArtisanPackUI\SecurityAnalytics\Models\SecurityIncident;
use Tests\Unit\Analytics\AnalyticsTestCase;

class LogEventActionTest extends AnalyticsTestCase
{
    protected LogEventAction $action;

    protected function setUp(): void
    {
        parent::setUp();
        $this->action = new LogEventAction();
    }

    public function test_it_has_correct_name(): void
    {
        $this->assertEquals( 'log_event', $this->action->getName() );
    }

    public function test_it_logs_anomaly_successfully(): void
    {
        $anomaly = Anomaly::factory()->create( [
            'severity'    => Anomaly::SEVERITY_HIGH,
            'description' => 'Test anomaly',
        ] );

        $result = $this->action->execute( $anomaly );

        $this->assertTrue( $result['success'] );
        $this->assertEquals( 'security', $result['data']['channel'] );
    }

    public function test_it_logs_to_custom_channel(): void
    {
        $anomaly = Anomaly::factory()->create();

        $result = $this->action->execute( $anomaly, null, [
            'channel' => 'audit',
        ] );

        $this->assertTrue( $result['success'] );
        $this->assertEquals( 'audit', $result['data']['channel'] );
    }

    public function test_it_maps_critical_severity_to_critical_level(): void
    {
        $anomaly = Anomaly::factory()->create( [
            'severity' => Anomaly::SEVERITY_CRITICAL,
        ] );

        $result = $this->action->execute( $anomaly );

        $this->assertTrue( $result['success'] );
        $this->assertEquals( 'critical', $result['data']['level'] );
    }

    public function test_it_maps_high_severity_to_error_level(): void
    {
        $anomaly = Anomaly::factory()->create( [
            'severity' => Anomaly::SEVERITY_HIGH,
        ] );

        $result = $this->action->execute( $anomaly );

        $this->assertTrue( $result['success'] );
        $this->assertEquals( 'error', $result['data']['level'] );
    }

    public function test_it_maps_medium_severity_to_warning_level(): void
    {
        $anomaly = Anomaly::factory()->create( [
            'severity' => Anomaly::SEVERITY_MEDIUM,
        ] );

        $result = $this->action->execute( $anomaly );

        $this->assertTrue( $result['success'] );
        $this->assertEquals( 'warning', $result['data']['level'] );
    }

    public function test_it_maps_low_severity_to_notice_level(): void
    {
        $anomaly = Anomaly::factory()->create( [
            'severity' => Anomaly::SEVERITY_LOW,
        ] );

        $result = $this->action->execute( $anomaly );

        $this->assertTrue( $result['success'] );
        $this->assertEquals( 'notice', $result['data']['level'] );
    }

    public function test_it_maps_info_severity_to_info_level(): void
    {
        $anomaly = Anomaly::factory()->create( [
            'severity' => Anomaly::SEVERITY_INFO,
        ] );

        $result = $this->action->execute( $anomaly );

        $this->assertTrue( $result['success'] );
        $this->assertEquals( 'info', $result['data']['level'] );
    }

    public function test_it_uses_custom_log_level(): void
    {
        $anomaly = Anomaly::factory()->create( [
            'severity' => Anomaly::SEVERITY_LOW,
        ] );

        $result = $this->action->execute( $anomaly, null, [
            'level' => 'alert',
        ] );

        $this->assertTrue( $result['success'] );
        $this->assertEquals( 'alert', $result['data']['level'] );
    }

    public function test_it_works_with_incident(): void
    {
        $anomaly  = Anomaly::factory()->create();
        $incident = SecurityIncident::factory()->create();

        $result = $this->action->execute( $anomaly, $incident );

        $this->assertTrue( $result['success'] );
    }
}
