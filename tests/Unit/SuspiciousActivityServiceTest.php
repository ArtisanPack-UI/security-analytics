<?php

namespace Tests\Unit;

use ArtisanPackUI\SecurityAnalytics\Authentication\Detection\SuspiciousActivityService;
use ArtisanPackUI\SecurityAnalytics\Models\SuspiciousActivity;
use Illuminate\Http\Request;
use Tests\TestCase;

class SuspiciousActivityServiceTest extends TestCase
{
    protected SuspiciousActivityService $service;

    protected function setUp(): void
    {
        parent::setUp();
        $this->service = new SuspiciousActivityService();
    }

    /** @test */
    public function it_calculates_risk_score_for_detection(): void
    {
        $detections = [
            [
                'type'     => SuspiciousActivity::TYPE_BRUTE_FORCE,
                'severity' => SuspiciousActivity::SEVERITY_HIGH,
                'details'  => ['attempt_count' => 10],
            ],
        ];

        $riskScore = $this->service->calculateRiskScore( $detections );

        $this->assertIsInt( $riskScore );
        $this->assertGreaterThan( 0, $riskScore );
        $this->assertLessThanOrEqual( 100, $riskScore );
    }

    /** @test */
    public function it_determines_severity_from_risk_score(): void
    {
        $this->assertEquals( 'low', $this->service->determineSeverity( 15 ) );
        $this->assertEquals( 'medium', $this->service->determineSeverity( 45 ) );
        $this->assertEquals( 'high', $this->service->determineSeverity( 70 ) );
        $this->assertEquals( 'critical', $this->service->determineSeverity( 90 ) );
    }

    /** @test */
    public function it_provides_recommended_actions_based_on_severity(): void
    {
        $this->assertEquals( 'notify', $this->service->getRecommendedAction( 'low' ) );
        $this->assertEquals( 'captcha', $this->service->getRecommendedAction( 'medium' ) );
        $this->assertEquals( 'step_up', $this->service->getRecommendedAction( 'high' ) );
        $this->assertEquals( 'block', $this->service->getRecommendedAction( 'critical' ) );
    }

    /** @test */
    public function it_analyzes_request_for_suspicious_patterns(): void
    {
        $request = Request::create( '/', 'GET', [], [], [], [
            'HTTP_USER_AGENT' => 'Mozilla/5.0',
            'REMOTE_ADDR'     => '192.168.1.1',
        ] );

        $analysis = $this->service->analyze( $request, null, [] );

        $this->assertIsArray( $analysis );
        $this->assertArrayHasKey( 'suspicious', $analysis );
        $this->assertArrayHasKey( 'risk_score', $analysis );
        $this->assertArrayHasKey( 'detections', $analysis );
    }
}
