<?php

declare( strict_types=1 );

namespace Tests\Unit\Analytics;

use ArtisanPackUI\SecurityAnalytics\Analytics\IncidentResponse\Actions\BlockIpAction;
use ArtisanPackUI\SecurityAnalytics\Analytics\IncidentResponse\Actions\BlockUserAction;
use ArtisanPackUI\SecurityAnalytics\Analytics\IncidentResponse\IncidentResponder;
use ArtisanPackUI\SecurityAnalytics\Models\Anomaly;
use ArtisanPackUI\SecurityAnalytics\Models\SecurityIncident;
use Illuminate\Support\Facades\Cache;

class IncidentResponderTest extends AnalyticsTestCase
{
    protected IncidentResponder $responder;

    protected function setUp(): void
    {
        parent::setUp();
        $this->responder = new IncidentResponder;
    }

    public function test_it_registers_default_actions(): void
    {
        $this->assertNotNull( $this->responder->getAction( 'block_ip' ) );
        $this->assertNotNull( $this->responder->getAction( 'block_user' ) );
        $this->assertNotNull( $this->responder->getAction( 'notify_admin' ) );
        $this->assertNotNull( $this->responder->getAction( 'log_event' ) );
        $this->assertNotNull( $this->responder->getAction( 'revoke_sessions' ) );
        $this->assertNotNull( $this->responder->getAction( 'require_2fa' ) );
    }

    public function test_block_ip_action_blocks_ip(): void
    {
        $ip      = '192.168.1.100';
        $anomaly = Anomaly::factory()->create( [
            'ip_address' => $ip,
            'metadata'   => ['ip' => $ip],
        ] );

        $action = new BlockIpAction;
        $result = $action->execute( $anomaly, null, ['duration_hours' => 24] );

        $this->assertTrue( $result['success'] );
        $this->assertTrue( BlockIpAction::isBlocked( $ip ) );

        $blockInfo = BlockIpAction::getBlockInfo( $ip );
        $this->assertNotNull( $blockInfo );
        $this->assertEquals( $anomaly->id, $blockInfo['anomaly_id'] );
    }

    public function test_block_ip_action_unblocks_ip(): void
    {
        Cache::put( 'blocked_ip:192.168.1.100', ['reason' => 'test'], 3600 );

        $this->assertTrue( BlockIpAction::isBlocked( '192.168.1.100' ) );

        BlockIpAction::unblock( '192.168.1.100' );

        $this->assertFalse( BlockIpAction::isBlocked( '192.168.1.100' ) );
    }

    public function test_block_user_action_requires_approval(): void
    {
        $action = new BlockUserAction;

        $this->assertTrue( $action->requiresApproval() );
    }

    public function test_it_creates_incident_for_high_severity_anomaly(): void
    {
        $anomaly = Anomaly::factory()->create( [
            'severity' => 'critical',
            'category' => Anomaly::CATEGORY_THREAT,
        ] );

        $result = $this->responder->respond( $anomaly, ['log_event'] );

        $this->assertNotNull( $result['incident_id'] );

        $incident = SecurityIncident::find( $result['incident_id'] );
        $this->assertNotNull( $incident );
        $this->assertEquals( SecurityIncident::STATUS_OPEN, $incident->status );
    }

    public function test_it_does_not_create_incident_for_low_severity(): void
    {
        $responder = new IncidentResponder( [
            'min_severity_for_incident' => 'high',
        ] );

        $anomaly = Anomaly::factory()->create( [
            'severity' => 'low',
        ] );

        $result = $responder->respond( $anomaly, ['log_event'] );

        $this->assertNull( $result['incident_id'] );
    }

    public function test_it_validates_action_config(): void
    {
        $action = new BlockIpAction;

        $errors = $action->validate( ['ip' => 'invalid-ip'] );
        $this->assertNotEmpty( $errors );

        $errors = $action->validate( ['ip' => '192.168.1.1'] );
        $this->assertEmpty( $errors );
    }

    public function test_it_queues_action_requiring_approval(): void
    {
        $anomaly = Anomaly::factory()->create( [
            'user_id' => 1,
        ] );

        $result = $this->responder->executeAction( 'block_user', $anomaly );

        $this->assertFalse( $result['success'] );
        $this->assertTrue( $result['pending_approval'] );
        $this->assertArrayHasKey( 'approval_id', $result );
    }

    public function test_it_approves_pending_action(): void
    {
        $anomaly = Anomaly::factory()->create( [
            'user_id' => 1,
        ] );

        // Queue the action
        $queueResult = $this->responder->executeAction( 'block_user', $anomaly, null, ['user_id' => 1] );
        $approvalId  = $queueResult['approval_id'];

        // Approve it
        $result = $this->responder->approve( $approvalId, 999 );

        $this->assertTrue( $result['success'] );
        $this->assertEquals( 999, $result['approved_by'] );
    }

    public function test_it_rejects_pending_action(): void
    {
        $anomaly = Anomaly::factory()->create( [
            'user_id' => 1,
        ] );

        // Queue the action
        $queueResult = $this->responder->executeAction( 'block_user', $anomaly, null, ['user_id' => 1] );
        $approvalId  = $queueResult['approval_id'];

        // Reject it
        $result = $this->responder->reject( $approvalId, 999, 'Not needed' );

        $this->assertTrue( $result['success'] );
        $this->assertTrue( $result['rejected'] );
        $this->assertEquals( 'Not needed', $result['reason'] );
    }

    public function test_it_returns_error_for_unknown_action(): void
    {
        $anomaly = Anomaly::factory()->create();

        $result = $this->responder->executeAction( 'unknown_action', $anomaly );

        $this->assertFalse( $result['success'] );
        $this->assertStringContainsString( 'Unknown action', $result['message'] );
    }

    public function test_it_returns_error_for_expired_approval(): void
    {
        $result = $this->responder->approve( 'nonexistent_approval_id' );

        $this->assertFalse( $result['success'] );
        $this->assertStringContainsString( 'not found', $result['message'] );
    }
}
