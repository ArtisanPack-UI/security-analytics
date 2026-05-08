<?php

declare( strict_types=1 );

namespace Tests\Unit\Analytics\Channels;

use ArtisanPackUI\SecurityAnalytics\Analytics\Alerting\Channels\SlackChannel;
use ArtisanPackUI\SecurityAnalytics\Models\AlertRule;
use ArtisanPackUI\SecurityAnalytics\Models\Anomaly;
use Exception;
use Illuminate\Support\Facades\Http;
use Tests\Unit\Analytics\AnalyticsTestCase;

class SlackChannelTest extends AnalyticsTestCase
{
    protected SlackChannel $channel;

    protected function setUp(): void
    {
        parent::setUp();
        $this->channel = new SlackChannel( [
            'enabled'     => true,
            'webhook_url' => 'https://hooks.slack.com/services/test',
            'channel'     => '#security-alerts',
            'username'    => 'Security Bot',
            'icon_emoji'  => ':shield:',
        ] );
    }

    public function test_it_has_correct_name(): void
    {
        $this->assertEquals( 'slack', $this->channel->getName() );
    }

    public function test_it_can_be_enabled_and_disabled(): void
    {
        $this->assertTrue( $this->channel->isEnabled() );

        $disabledChannel = new SlackChannel( ['enabled' => false] );
        $this->assertFalse( $disabledChannel->isEnabled() );
    }

    public function test_it_requires_webhook_url(): void
    {
        $channelWithoutUrl = new SlackChannel( [
            'enabled'     => true,
            'webhook_url' => null,
        ] );

        $this->assertFalse( $channelWithoutUrl->isEnabled() );
    }

    public function test_it_returns_error_when_disabled(): void
    {
        $disabledChannel = new SlackChannel( ['enabled' => false] );

        $anomaly = Anomaly::factory()->create( [
            'detected_at' => now(),
        ] );
        $rule = AlertRule::factory()->create();

        $result = $disabledChannel->send( $anomaly, $rule, [] );

        $this->assertFalse( $result['success'] );
        $this->assertStringContainsString( 'not configured', $result['error'] );
    }

    public function test_it_sends_alert_successfully(): void
    {
        Http::fake( [
            'hooks.slack.com/*' => Http::response( 'ok', 200 ),
        ] );

        $anomaly = Anomaly::factory()->create( [
            'severity'    => Anomaly::SEVERITY_HIGH,
            'category'    => Anomaly::CATEGORY_AUTHENTICATION,
            'description' => 'Brute force attack detected',
            'score'       => 85.0,
            'detected_at' => now(),
        ] );
        $rule = AlertRule::factory()->create( ['name' => 'High Severity Alert'] );

        $result = $this->channel->send( $anomaly, $rule, ['U123456'] );

        $this->assertTrue( $result['success'] );
        $this->assertEquals( '#security-alerts', $result['channel'] );
    }

    public function test_it_handles_api_errors(): void
    {
        Http::fake( [
            'hooks.slack.com/*' => Http::response( 'invalid_token', 401 ),
        ] );

        $anomaly = Anomaly::factory()->create( [
            'detected_at' => now(),
        ] );
        $rule = AlertRule::factory()->create();

        $result = $this->channel->send( $anomaly, $rule, [] );

        $this->assertFalse( $result['success'] );
    }

    public function test_it_handles_connection_exceptions(): void
    {
        Http::fake( function (): void {
            throw new Exception( 'Connection refused' );
        } );

        $anomaly = Anomaly::factory()->create( [
            'detected_at' => now(),
        ] );
        $rule = AlertRule::factory()->create();

        $result = $this->channel->send( $anomaly, $rule, [] );

        $this->assertFalse( $result['success'] );
        $this->assertStringContainsString( 'Connection refused', $result['error'] );
    }

    public function test_it_includes_mentions(): void
    {
        Http::fake( [
            'hooks.slack.com/*' => Http::response( 'ok', 200 ),
        ] );

        $anomaly = Anomaly::factory()->create( [
            'detected_at' => now(),
        ] );
        $rule = AlertRule::factory()->create();

        $result = $this->channel->send( $anomaly, $rule, ['U123', 'U456'] );

        $this->assertTrue( $result['success'] );
        $this->assertEquals( ['U123', 'U456'], $result['mentions'] );
    }

    public function test_it_returns_config(): void
    {
        $config = $this->channel->getConfig();

        $this->assertArrayHasKey( 'enabled', $config );
        $this->assertArrayHasKey( 'webhook_url', $config );
        $this->assertArrayHasKey( 'channel', $config);
        $this->assertArrayHasKey( 'username', $config);
        $this->assertArrayHasKey( 'icon_emoji', $config);
    }
}
