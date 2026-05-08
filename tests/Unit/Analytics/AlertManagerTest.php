<?php

declare( strict_types=1 );

namespace Tests\Unit\Analytics;

use ArtisanPackUI\SecurityAnalytics\Analytics\Alerting\AlertManager;
use ArtisanPackUI\SecurityAnalytics\Analytics\Alerting\Channels\EmailChannel;
use ArtisanPackUI\SecurityAnalytics\Analytics\Alerting\Contracts\AlertChannelInterface;
use ArtisanPackUI\SecurityAnalytics\Models\AlertHistory;
use ArtisanPackUI\SecurityAnalytics\Models\AlertRule;
use ArtisanPackUI\SecurityAnalytics\Models\Anomaly;
use ReflectionMethod;

class AlertManagerTest extends AnalyticsTestCase
{
    protected AlertManager $manager;

    protected function setUp(): void
    {
        parent::setUp();
        $this->manager = new AlertManager( [
            'enabled' => true,
        ] );
    }

    public function test_it_registers_default_channels(): void
    {
        $this->assertNotNull( $this->manager->getChannel( 'email' ) );
        $this->assertNotNull( $this->manager->getChannel( 'slack' ) );
        $this->assertNotNull( $this->manager->getChannel( 'pagerduty' ) );
    }

    public function test_it_can_register_custom_channel(): void
    {
        $customChannel = new class implements AlertChannelInterface {
            public function getName(): string
            {
                return 'custom';
            }

            public function isEnabled(): bool
            {
                return true;
            }

            public function send( Anomaly $anomaly, AlertRule $rule, array $recipients ): array
            {
                return ['success' => true];
            }

            public function getConfig(): array
            {
                return [];
            }
        };

        $this->manager->registerChannel( $customChannel );

        $this->assertNotNull( $this->manager->getChannel( 'custom' ) );
    }

    public function test_email_channel_builds_correct_subject(): void
    {
        $channel = new EmailChannel( [
            'enabled'        => true,
            'subject_prefix' => '[TEST]',
        ] );

        $anomaly = Anomaly::factory()->make( [
            'severity' => 'critical',
            'category' => Anomaly::CATEGORY_THREAT,
        ] );

        $rule = AlertRule::factory()->make( [
            'name' => 'Test Rule',
        ] );

        // Use reflection to test protected method
        $method = new ReflectionMethod( $channel, 'buildSubject' );
        $method->setAccessible( true );

        $subject = $method->invoke( $channel, $anomaly, $rule );

        $this->assertStringContainsString( '[TEST]', $subject );
        $this->assertStringContainsString( '[CRITICAL]', $subject );
        $this->assertStringContainsString( 'Test Rule', $subject );
    }

    public function test_it_gets_statistics(): void
    {
        AlertHistory::create( [
            'rule_id'    => 1,
            'anomaly_id' => 1,
            'severity'   => 'high',
            'channel'    => 'email',
            'status'     => AlertHistory::STATUS_SENT,
            'message'    => 'Test alert',
            'sent_at'    => now(),
        ] );

        AlertHistory::create( [
            'rule_id'       => 1,
            'anomaly_id'    => 2,
            'severity'      => 'medium',
            'channel'       => 'slack',
            'status'        => AlertHistory::STATUS_FAILED,
            'message'       => 'Failed alert',
            'error_message' => 'Connection error',
        ] );

        $stats = $this->manager->getStatistics( 7 );

        $this->assertEquals( 2, $stats['total_alerts'] );
        $this->assertEquals( 50, $stats['success_rate'] );
        $this->assertArrayHasKey( 'by_status', $stats );
        $this->assertArrayHasKey( 'by_channel', $stats );
    }

    public function test_it_gets_unacknowledged_alerts(): void
    {
        AlertHistory::create( [
            'rule_id'    => 1,
            'anomaly_id' => 1,
            'severity'   => 'high',
            'channel'    => 'email',
            'status'     => AlertHistory::STATUS_SENT,
            'message'    => 'Pending alert',
        ] );

        AlertHistory::create( [
            'rule_id'         => 1,
            'anomaly_id'      => 2,
            'severity'        => 'high',
            'channel'         => 'email',
            'status'          => AlertHistory::STATUS_ACKNOWLEDGED,
            'message'         => 'Acknowledged alert',
            'acknowledged_at' => now(),
        ] );

        $unacknowledged = $this->manager->getUnacknowledged();

        $this->assertCount( 1, $unacknowledged );
        $this->assertEquals( 'Pending alert', $unacknowledged->first()->message );
    }

    public function test_it_acknowledges_alert(): void
    {
        $alert = AlertHistory::create( [
            'rule_id'    => 1,
            'anomaly_id' => 1,
            'severity'   => 'high',
            'channel'    => 'email',
            'status'     => AlertHistory::STATUS_SENT,
            'message'    => 'Test alert',
        ] );

        $result = $this->manager->acknowledge( $alert->id, 1 );

        $this->assertTrue( $result );

        $alert->refresh();
        $this->assertTrue( $alert->isAcknowledged() );
        $this->assertEquals( 1, $alert->acknowledged_by );
    }

    public function test_it_bulk_acknowledges_alerts(): void
    {
        $alerts = AlertHistory::factory()->count( 3 )->create( [
            'status' => AlertHistory::STATUS_SENT,
        ] );

        $ids   = $alerts->pluck( 'id' )->toArray();
        $count = $this->manager->bulkAcknowledge( $ids, 1 );

        $this->assertEquals( 3, $count );
        $this->assertEquals( 0, AlertHistory::unacknowledged()->count() );
    }

    public function test_it_returns_false_for_nonexistent_alert(): void
    {
        $result = $this->manager->acknowledge( 9999);

        $this->assertFalse( $result);
    }
}
