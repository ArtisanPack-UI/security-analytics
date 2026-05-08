<?php

declare( strict_types=1 );

namespace Tests\Unit\Analytics;

use ArtisanPackUI\SecurityAnalytics\Analytics\AnomalyDetection\AnomalyDetectionService;
use ArtisanPackUI\SecurityAnalytics\Analytics\AnomalyDetection\Contracts\DetectorInterface;
use ArtisanPackUI\SecurityAnalytics\Models\Anomaly;
use Illuminate\Support\Collection;

class AnomalyDetectionServiceTest extends AnalyticsTestCase
{
    protected AnomalyDetectionService $service;

    protected function setUp(): void
    {
        parent::setUp();
        $this->service = new AnomalyDetectionService( [
            'dispatch_events' => false,
        ] );
    }

    public function test_it_registers_default_detectors(): void
    {
        $detectors = $this->service->getDetectors();

        $this->assertArrayHasKey( 'statistical', $detectors );
        $this->assertArrayHasKey( 'behavioral', $detectors );
        $this->assertArrayHasKey( 'rule_based', $detectors );
    }

    public function test_it_can_register_custom_detector(): void
    {
        $customDetector = new class implements DetectorInterface {
            public function getName(): string
            {
                return 'custom';
            }

            public function isEnabled(): bool
            {
                return true;
            }

            public function detect( array $data ): Collection
            {
                return collect();
            }

            public function getConfig(): array
            {
                return [];
            }
        };

        $this->service->registerDetector( $customDetector );

        $this->assertNotNull( $this->service->getDetector( 'custom' ) );
    }

    public function test_it_can_be_enabled_and_disabled(): void
    {
        $this->assertTrue( $this->service->isEnabled() );

        $this->service->disable();
        $this->assertFalse( $this->service->isEnabled() );

        $this->service->enable();
        $this->assertTrue( $this->service->isEnabled() );
    }

    public function test_it_returns_empty_when_disabled(): void
    {
        $this->service->disable();

        $anomalies = $this->service->detect( [] );

        $this->assertCount( 0, $anomalies );
    }

    public function test_it_gets_recent_anomalies(): void
    {
        Anomaly::create( [
            'detector'    => 'test',
            'category'    => Anomaly::CATEGORY_AUTHENTICATION,
            'description' => 'Recent anomaly',
            'severity'    => 'high',
            'score'       => 80,
            'detected_at' => now()->subHour(),
        ] );

        Anomaly::create( [
            'detector'    => 'test',
            'category'    => Anomaly::CATEGORY_AUTHENTICATION,
            'description' => 'Old anomaly',
            'severity'    => 'high',
            'score'       => 80,
            'detected_at' => now()->subDays( 2 ),
        ] );

        $recent = $this->service->getRecentAnomalies( 24 );

        $this->assertCount( 1, $recent );
        $this->assertEquals( 'Recent anomaly', $recent->first()->description );
    }

    public function test_it_gets_unresolved_anomalies(): void
    {
        $unresolved = Anomaly::create( [
            'detector'    => 'test',
            'category'    => Anomaly::CATEGORY_THREAT,
            'description' => 'Unresolved',
            'severity'    => 'high',
            'score'       => 80,
            'detected_at' => now(),
        ] );

        $resolved = Anomaly::create( [
            'detector'    => 'test',
            'category'    => Anomaly::CATEGORY_THREAT,
            'description' => 'Resolved',
            'severity'    => 'high',
            'score'       => 80,
            'detected_at' => now(),
            'resolved_at' => now(),
        ] );

        $anomalies = $this->service->getUnresolvedAnomalies();

        $this->assertCount( 1, $anomalies );
        $this->assertEquals( 'Unresolved', $anomalies->first()->description );
    }

    public function test_it_resolves_anomaly(): void
    {
        $anomaly = Anomaly::create( [
            'detector'    => 'test',
            'category'    => Anomaly::CATEGORY_THREAT,
            'description' => 'Test anomaly',
            'severity'    => 'high',
            'score'       => 80,
            'detected_at' => now(),
        ] );

        $result = $this->service->resolveAnomaly( $anomaly->id, 1, 'Test resolution' );

        $this->assertTrue( $result );

        $anomaly->refresh();
        $this->assertTrue( $anomaly->isResolved() );
        $this->assertEquals( 1, $anomaly->resolved_by );
        $this->assertEquals( 'Test resolution', $anomaly->resolution_notes );
    }

    public function test_it_bulk_resolves_anomalies(): void
    {
        $anomalies = Anomaly::factory()->count( 3 )->create( [
            'detector' => 'test',
            'category' => Anomaly::CATEGORY_THREAT,
            'severity' => 'medium',
            'score'    => 50,
        ] );

        $ids   = $anomalies->pluck( 'id' )->toArray();
        $count = $this->service->bulkResolve( $ids, 1, 'Bulk resolved' );

        $this->assertEquals( 3, $count );
        $this->assertEquals( 0, Anomaly::unresolved()->count() );
    }

    public function test_it_gets_statistics(): void
    {
        Anomaly::create( [
            'detector'    => 'statistical',
            'category'    => Anomaly::CATEGORY_AUTHENTICATION,
            'description' => 'Auth anomaly',
            'severity'    => 'critical',
            'score'       => 90,
            'detected_at' => now(),
        ] );

        Anomaly::create( [
            'detector'    => 'behavioral',
            'category'    => Anomaly::CATEGORY_BEHAVIORAL,
            'description' => 'Behavior anomaly',
            'severity'    => 'high',
            'score'       => 75,
            'detected_at' => now(),
        ] );

        $stats = $this->service->getStatistics( 7 );

        $this->assertEquals( 2, $stats['total_count'] );
        $this->assertArrayHasKey( 'by_severity', $stats );
        $this->assertArrayHasKey( 'by_category', $stats );
        $this->assertArrayHasKey( 'by_detector', $stats );
    }

    public function test_it_auto_resolves_old_anomalies(): void
    {
        Anomaly::create( [
            'detector'    => 'test',
            'category'    => Anomaly::CATEGORY_THREAT,
            'description' => 'Old anomaly',
            'severity'    => 'low',
            'score'       => 30,
            'detected_at' => now()->subDays( 5 ),
        ] );

        Anomaly::create( [
            'detector'    => 'test',
            'category'    => Anomaly::CATEGORY_THREAT,
            'description' => 'Recent anomaly',
            'severity'    => 'low',
            'score'       => 30,
            'detected_at' => now(),
        ] );

        $resolved = $this->service->autoResolveOld( 72); // 3 days

        $this->assertEquals( 1, $resolved);
        $this->assertEquals( 1, Anomaly::unresolved()->count());
    }
}
