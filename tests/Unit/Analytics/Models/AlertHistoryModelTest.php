<?php

declare( strict_types=1 );

namespace Tests\Unit\Analytics\Models;

use ArtisanPackUI\SecurityAnalytics\Models\AlertHistory;
use ArtisanPackUI\SecurityAnalytics\Models\AlertRule;
use Tests\Unit\Analytics\AnalyticsTestCase;

class AlertHistoryModelTest extends AnalyticsTestCase
{
    public function test_it_can_create_alert_history(): void
    {
        $alert = AlertHistory::factory()->create( [
            'channel'  => 'email',
            'severity' => AlertHistory::SEVERITY_HIGH,
            'status'   => AlertHistory::STATUS_PENDING,
        ] );

        $this->assertDatabaseHas( 'alert_history', [
            'id'       => $alert->id,
            'channel'  => 'email',
            'severity' => AlertHistory::SEVERITY_HIGH,
            'status'   => AlertHistory::STATUS_PENDING,
        ] );
    }

    public function test_it_casts_dates(): void
    {
        $alert = AlertHistory::factory()->create( [
            'sent_at'         => now(),
            'acknowledged_at' => now()->addMinute(),
        ] );

        $this->assertInstanceOf( \Carbon\Carbon::class, $alert->sent_at );
        $this->assertInstanceOf( \Carbon\Carbon::class, $alert->acknowledged_at );
    }

    public function test_it_checks_status_helpers(): void
    {
        $pending      = AlertHistory::factory()->create( ['status' => AlertHistory::STATUS_PENDING] );
        $sent         = AlertHistory::factory()->create( ['status' => AlertHistory::STATUS_SENT] );
        $failed       = AlertHistory::factory()->create( ['status' => AlertHistory::STATUS_FAILED] );
        $acknowledged = AlertHistory::factory()->create( ['status' => AlertHistory::STATUS_ACKNOWLEDGED] );

        $this->assertTrue( $pending->isPending() );
        $this->assertTrue( $sent->isSent() );
        $this->assertTrue( $failed->isFailed() );
        $this->assertTrue( $acknowledged->isAcknowledged() );

        $this->assertFalse( $pending->isSent() );
        $this->assertFalse( $sent->isFailed() );
    }

    public function test_it_marks_as_sent(): void
    {
        $alert = AlertHistory::factory()->create( [
            'status'  => AlertHistory::STATUS_PENDING,
            'sent_at' => null,
        ] );

        $alert->markAsSent();

        $this->assertTrue( $alert->isSent() );
        $this->assertInstanceOf( \Carbon\Carbon::class, $alert->fresh()->sent_at );
    }

    public function test_it_marks_as_failed(): void
    {
        $alert = AlertHistory::factory()->create( ['status' => AlertHistory::STATUS_PENDING] );

        $alert->markAsFailed( 'SMTP connection refused' );

        $this->assertTrue( $alert->isFailed() );
        $this->assertEquals( 'SMTP connection refused', $alert->error_message );
    }

    public function test_it_acknowledges_the_alert(): void
    {
        $alert = AlertHistory::factory()->create( ['status' => AlertHistory::STATUS_SENT] );

        $alert->acknowledge( 42 );

        $this->assertTrue( $alert->isAcknowledged() );
        $this->assertEquals( 42, $alert->acknowledged_by );
        $this->assertInstanceOf( \Carbon\Carbon::class, $alert->acknowledged_at );
    }

    public function test_it_belongs_to_a_rule(): void
    {
        $rule  = AlertRule::factory()->create();
        $alert = AlertHistory::factory()->create( ['rule_id' => $rule->id] );

        $this->assertInstanceOf( AlertRule::class, $alert->rule );
        $this->assertEquals( $rule->id, $alert->rule->id );
    }

    public function test_it_scopes_by_status(): void
    {
        AlertHistory::factory()->count( 2 )->create( ['status' => AlertHistory::STATUS_PENDING] );
        AlertHistory::factory()->create( ['status' => AlertHistory::STATUS_SENT] );

        $this->assertEquals( 2, AlertHistory::status( AlertHistory::STATUS_PENDING )->count() );
        $this->assertEquals( 2, AlertHistory::pending()->count() );
        $this->assertEquals( 1, AlertHistory::sent()->count() );
    }

    public function test_it_scopes_failed(): void
    {
        AlertHistory::factory()->count( 3 )->create( ['status' => AlertHistory::STATUS_FAILED] );
        AlertHistory::factory()->create( ['status' => AlertHistory::STATUS_SENT] );

        $this->assertEquals( 3, AlertHistory::failed()->count() );
    }

    public function test_it_scopes_by_channel_and_severity(): void
    {
        AlertHistory::factory()->count( 2 )->create( ['channel' => 'slack', 'severity' => AlertHistory::SEVERITY_CRITICAL] );
        AlertHistory::factory()->create( ['channel' => 'email', 'severity' => AlertHistory::SEVERITY_LOW] );

        $this->assertEquals( 2, AlertHistory::channel( 'slack' )->count() );
        $this->assertEquals( 2, AlertHistory::severity( AlertHistory::SEVERITY_CRITICAL )->count() );
    }

    public function test_it_scopes_unacknowledged(): void
    {
        AlertHistory::factory()->create( ['status' => AlertHistory::STATUS_PENDING] );
        AlertHistory::factory()->create( ['status' => AlertHistory::STATUS_SENT] );
        AlertHistory::factory()->create( ['status' => AlertHistory::STATUS_ACKNOWLEDGED] );

        $this->assertEquals( 2, AlertHistory::unacknowledged()->count() );
    }
}
