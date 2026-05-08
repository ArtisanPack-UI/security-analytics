<?php

declare( strict_types=1 );

namespace Tests\Unit\Analytics\Actions;

use ArtisanPackUI\SecurityAnalytics\Analytics\IncidentResponse\Actions\BlockIpAction;
use ArtisanPackUI\SecurityAnalytics\Models\Anomaly;
use ArtisanPackUI\SecurityAnalytics\Models\SecurityIncident;
use Illuminate\Support\Facades\Cache;
use Tests\Unit\Analytics\AnalyticsTestCase;

class BlockIpActionTest extends AnalyticsTestCase
{
    protected BlockIpAction $action;

    protected function setUp(): void
    {
        parent::setUp();
        Cache::flush();
        $this->action = new BlockIpAction();
    }

    public function test_it_has_correct_name(): void
    {
        $this->assertEquals( 'block_ip', $this->action->getName() );
    }

    public function test_it_blocks_ip_from_anomaly(): void
    {
        $ip      = '192.168.1.100';
        $anomaly = Anomaly::factory()->create( [
            'ip_address'  => $ip,
            'description' => 'Brute force attack detected',
        ] );

        $result = $this->action->execute( $anomaly );

        $this->assertTrue( $result['success'] );
        $this->assertStringContainsString( $ip, $result['message'] );
        $this->assertTrue( BlockIpAction::isBlocked( $ip ) );
    }

    public function test_it_blocks_ip_from_config(): void
    {
        $anomaly = Anomaly::factory()->create( [
            'ip_address' => '10.0.0.1',
        ] );

        $result = $this->action->execute( $anomaly, null, [
            'ip'             => '203.0.113.50',
            'duration_hours' => 48,
        ] );

        $this->assertTrue( $result['success'] );
        $this->assertTrue( BlockIpAction::isBlocked( '203.0.113.50' ) );
        $this->assertFalse( BlockIpAction::isBlocked( '10.0.0.1' ) );
    }

    public function test_it_fails_without_ip(): void
    {
        $anomaly = Anomaly::factory()->create( [
            'ip_address' => null,
            'metadata'   => [], // Remove any metadata IP too
        ] );

        $result = $this->action->execute( $anomaly );

        $this->assertFalse( $result['success'] );
        $this->assertStringContainsString( 'No IP address', $result['message'] );
    }

    public function test_it_sets_correct_duration(): void
    {
        $ip      = '192.168.1.200';
        $anomaly = Anomaly::factory()->create( [
            'ip_address' => $ip,
        ] );

        $result = $this->action->execute( $anomaly, null, [
            'duration_hours' => 12,
        ] );

        $this->assertTrue( $result['success'] );
        $this->assertEquals( 12, $result['data']['duration_hours'] );
    }

    public function test_it_stores_block_info(): void
    {
        $ip      = '192.168.1.150';
        $anomaly = Anomaly::factory()->create( [
            'ip_address'  => $ip,
            'description' => 'Test attack',
        ] );

        $this->action->execute( $anomaly );

        $blockInfo = BlockIpAction::getBlockInfo( $ip );

        $this->assertNotNull( $blockInfo );
        $this->assertEquals( $anomaly->id, $blockInfo['anomaly_id'] );
        $this->assertArrayHasKey( 'blocked_at', $blockInfo );
        $this->assertArrayHasKey( 'expires_at', $blockInfo );
    }

    public function test_it_can_unblock_ip(): void
    {
        $ip      = '10.0.0.100';
        $anomaly = Anomaly::factory()->create( [
            'ip_address' => $ip,
        ] );

        $this->action->execute( $anomaly );
        $this->assertTrue( BlockIpAction::isBlocked( $ip ) );

        $unblocked = BlockIpAction::unblock( $ip );
        $this->assertTrue( $unblocked );
        $this->assertFalse( BlockIpAction::isBlocked( $ip ) );
    }

    public function test_it_validates_ip_format(): void
    {
        $errors = $this->action->validate( ['ip' => 'invalid-ip'] );

        $this->assertNotEmpty( $errors );
        $this->assertContains( 'Invalid IP address format', $errors );
    }

    public function test_it_validates_duration(): void
    {
        $errors = $this->action->validate( ['duration_hours' => 0] );

        $this->assertNotEmpty( $errors );
        $this->assertContains( 'Duration must be at least 1 hour', $errors );
    }

    public function test_it_passes_validation_with_valid_config(): void
    {
        $errors = $this->action->validate( [
            'ip'             => '192.168.1.1',
            'duration_hours' => 24,
        ] );

        $this->assertEmpty( $errors );
    }

    public function test_it_logs_to_incident(): void
    {
        $ip      = '192.168.1.250';
        $anomaly = Anomaly::factory()->create( [
            'ip_address' => $ip,
        ] );

        $incident = SecurityIncident::factory()->create( [
            'affected_ips' => [],
        ]);

        $this->action->execute( $anomaly, $incident);

        $incident->refresh();
        $this->assertContains( $ip, $incident->affected_ips ?? []);
    }
}
