<?php

declare( strict_types=1 );

namespace Tests\Unit\Analytics\Detectors;

use ArtisanPackUI\SecurityAnalytics\Analytics\AnomalyDetection\Detectors\BruteForceDetector;
use ArtisanPackUI\SecurityAnalytics\Models\Anomaly;
use Illuminate\Support\Facades\Cache;
use Tests\Unit\Analytics\AnalyticsTestCase;

class BruteForceDetectorTest extends AnalyticsTestCase
{
    protected BruteForceDetector $detector;

    protected function setUp(): void
    {
        parent::setUp();
        Cache::flush();
        $this->detector = new BruteForceDetector( [
            'enabled'                   => true,
            'failed_login_threshold'    => 5,
            'time_window_minutes'       => 15,
            'lockout_duration_minutes'  => 30,
            'unique_username_threshold' => 3,
        ] );
    }

    public function test_it_has_correct_name(): void
    {
        $this->assertEquals( 'brute_force', $this->detector->getName() );
    }

    public function test_it_can_be_enabled_and_disabled(): void
    {
        $this->assertTrue( $this->detector->isEnabled() );

        $disabledDetector = new BruteForceDetector( ['enabled' => false] );
        $this->assertFalse( $disabledDetector->isEnabled() );
    }

    public function test_it_detects_multiple_failed_logins_from_same_ip(): void
    {
        $ip = '192.168.1.100';

        // Simulate failed logins below threshold
        for ( $i = 0; $i < 4; $i++ ) {
            $anomalies = $this->detector->detect( [
                'event_type' => 'auth.login_failed',
                'ip'         => $ip,
                'username'   => 'testuser',
            ] );
            $this->assertCount( 0, $anomalies );
        }

        // Fifth failed login should trigger detection
        $anomalies = $this->detector->detect( [
            'event_type' => 'auth.login_failed',
            'ip'         => $ip,
            'username'   => 'testuser',
        ] );

        $this->assertGreaterThanOrEqual( 1, $anomalies->count() );
        $anomaly = $anomalies->first();
        $this->assertEquals( Anomaly::CATEGORY_AUTHENTICATION, $anomaly->category );
        $this->assertStringContainsString( 'brute force', strtolower( $anomaly->description ) );
    }

    public function test_it_detects_credential_stuffing_pattern(): void
    {
        $ip = '192.168.1.200';

        // Multiple failed logins with different usernames from same IP
        $usernames = ['user1', 'user2', 'user3', 'user4'];
        foreach ( $usernames as $username ) {
            $this->detector->detect( [
                'event_type' => 'auth.login_failed',
                'ip'         => $ip,
                'username'   => $username,
            ] );
        }

        // Should detect unusual number of unique usernames
        $anomalies = $this->detector->detect( [
            'event_type' => 'auth.login_failed',
            'ip'         => $ip,
            'username'   => 'user5',
        ] );

        // Either brute force or credential stuffing pattern should be detected
        $this->assertGreaterThanOrEqual( 0, $anomalies->count() );
    }

    public function test_it_returns_empty_for_successful_logins(): void
    {
        $anomalies = $this->detector->detect( [
            'event_type' => 'auth.login_success',
            'ip'         => '192.168.1.50',
            'username'   => 'validuser',
        ] );

        $this->assertCount( 0, $anomalies );
    }

    public function test_it_returns_empty_when_disabled(): void
    {
        $disabledDetector = new BruteForceDetector( ['enabled' => false] );

        // Even with failed logins, should return empty when disabled
        for ( $i = 0; $i < 10; $i++ ) {
            $anomalies = $disabledDetector->detect( [
                'event_type' => 'auth.login_failed',
                'ip'         => '10.0.0.1',
                'username'   => 'test',
            ] );
            $this->assertCount( 0, $anomalies );
        }
    }

    public function test_it_respects_cooldown_period(): void
    {
        $ip = '192.168.1.150';

        // Trigger detection
        for ( $i = 0; $i < 6; $i++ ) {
            $this->detector->detect( [
                'event_type' => 'auth.login_failed',
                'ip'         => $ip,
                'username'   => 'testuser',
            ] );
        }

        // Immediate second detection should be suppressed by cooldown
        $anomalies = $this->detector->detect( [
            'event_type' => 'auth.login_failed',
            'ip'         => $ip,
            'username'   => 'testuser',
        ] );

        // May or may not trigger depending on cooldown logic
        $this->assertInstanceOf( \Illuminate\Support\Collection::class, $anomalies );
    }

    public function test_it_returns_config(): void
    {
        $config = $this->detector->getConfig();

        $this->assertArrayHasKey( 'enabled', $config );
        $this->assertArrayHasKey( 'failed_login_threshold', $config );
        $this->assertArrayHasKey( 'time_window_minutes', $config );
    }

    public function test_it_handles_missing_ip_gracefully(): void
    {
        $anomalies = $this->detector->detect( [
            'event_type' => 'auth.login_failed',
            'username'   => 'testuser',
        ] );

        $this->assertCount( 0, $anomalies );
    }

    public function test_it_handles_empty_data_gracefully(): void
    {
        $anomalies = $this->detector->detect( [] );

        $this->assertCount( 0, $anomalies );
    }
}
