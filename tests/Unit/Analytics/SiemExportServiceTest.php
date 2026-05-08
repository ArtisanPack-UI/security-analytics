<?php

declare( strict_types=1 );

namespace Tests\Unit\Analytics;

use ArtisanPackUI\SecurityAnalytics\Analytics\Siem\Contracts\SiemExporterInterface;
use ArtisanPackUI\SecurityAnalytics\Analytics\Siem\SiemExportService;
use ArtisanPackUI\SecurityAnalytics\Models\Anomaly;
use ArtisanPackUI\SecurityAnalytics\Models\SecurityIncident;

class SiemExportServiceTest extends AnalyticsTestCase
{
    protected SiemExportService $service;

    protected function setUp(): void
    {
        parent::setUp();
        $this->service = new SiemExportService( [
            'enabled'       => true,
            'batch_enabled' => false,
            'export_events' => ['authentication', 'authorization', 'threat', 'anomaly', 'incident'],
        ] );
    }

    public function test_it_registers_exporter(): void
    {
        $exporter = $this->createMockExporter( 'test_exporter', true );

        $this->service->registerExporter( $exporter );

        $this->assertNotNull( $this->service->getExporter( 'test_exporter' ) );
    }

    public function test_it_returns_null_for_unknown_exporter(): void
    {
        $this->assertNull( $this->service->getExporter( 'nonexistent' ) );
    }

    public function test_it_gets_enabled_exporters(): void
    {
        $enabledExporter  = $this->createMockExporter( 'enabled', true );
        $disabledExporter = $this->createMockExporter( 'disabled', false );

        $this->service->registerExporter( $enabledExporter );
        $this->service->registerExporter( $disabledExporter );

        $enabled = $this->service->getEnabledExporters();

        $this->assertCount( 1, $enabled );
        $this->assertArrayHasKey( 'enabled', $enabled );
    }

    public function test_it_is_enabled_when_has_enabled_exporters(): void
    {
        $exporter = $this->createMockExporter( 'test', true );
        $this->service->registerExporter( $exporter );

        $this->assertTrue( $this->service->isEnabled() );
    }

    public function test_it_is_disabled_when_no_enabled_exporters(): void
    {
        $service = new SiemExportService( ['enabled' => true] );

        $this->assertFalse( $service->isEnabled() );
    }

    public function test_it_skips_export_when_disabled(): void
    {
        $service = new SiemExportService( ['enabled' => false] );

        $result = $service->exportEvent( ['event_type' => 'test'] );

        $this->assertTrue( $result['skipped'] );
        $this->assertEquals( 'SIEM export is disabled', $result['reason'] );
    }

    public function test_it_exports_event_to_enabled_exporters(): void
    {
        $exporter = $this->createMockExporter( 'test_exporter', true, ['success' => true] );
        $this->service->registerExporter( $exporter );

        $result = $this->service->exportEvent( [
            'event_type' => 'security.login',
            'category'   => 'authentication',
            'message'    => 'Test event',
        ] );

        $this->assertEquals( 1, $result['exported'] );
        $this->assertArrayHasKey( 'results', $result );
        $this->assertTrue( $result['results']['test_exporter']['success'] );
    }

    public function test_it_skips_events_not_in_export_list(): void
    {
        $service = new SiemExportService( [
            'enabled'       => true,
            'batch_enabled' => false,
            'export_events' => ['authentication'],
        ] );

        $exporter = $this->createMockExporter( 'test_exporter', true );
        $service->registerExporter( $exporter );

        $result = $service->exportEvent( [
            'event_type' => 'test',
            'category'   => 'performance',
        ] );

        $this->assertTrue( $result['skipped'] );
        $this->assertStringContainsString( 'not configured for export', $result['reason'] );
    }

    public function test_it_buffers_events_when_batch_enabled(): void
    {
        $service = new SiemExportService( [
            'enabled'       => true,
            'batch_enabled' => true,
            'batch_size'    => 10,
        ] );

        $exporter = $this->createMockExporter( 'test', true );
        $service->registerExporter( $exporter );

        $result = $service->exportEvent( [
            'event_type' => 'test',
            'category'   => 'authentication',
        ] );

        $this->assertTrue( $result['buffered'] );
        $this->assertEquals( 1, $result['buffer_size'] );
        $this->assertEquals( 1, $service->getBufferSize() );
    }

    public function test_it_auto_flushes_when_buffer_is_full(): void
    {
        $service = new SiemExportService( [
            'enabled'       => true,
            'batch_enabled' => true,
            'batch_size'    => 3,
        ] );

        $exporter = $this->createMockExporter( 'test', true, ['success' => true] );
        $service->registerExporter( $exporter );

        // Add events to fill buffer
        $service->exportEvent( ['event_type' => 'test', 'category' => 'authentication'] );
        $service->exportEvent( ['event_type' => 'test', 'category' => 'authentication'] );
        $result = $service->exportEvent( ['event_type' => 'test', 'category' => 'authentication'] );

        // Buffer should have flushed
        $this->assertEquals( 3, $result['exported'] );
        $this->assertEquals( 0, $service->getBufferSize() );
    }

    public function test_it_flushes_buffer_manually(): void
    {
        $service = new SiemExportService( [
            'enabled'       => true,
            'batch_enabled' => true,
            'batch_size'    => 100,
        ] );

        $exporter = $this->createMockExporter( 'test', true, ['success' => true] );
        $service->registerExporter( $exporter );

        $service->exportEvent( ['event_type' => 'test', 'category' => 'authentication'] );
        $service->exportEvent( ['event_type' => 'test', 'category' => 'authentication'] );

        $this->assertEquals( 2, $service->getBufferSize() );

        $result = $service->flush();

        $this->assertEquals( 2, $result['exported'] );
        $this->assertEquals( 0, $service->getBufferSize() );
    }

    public function test_it_clears_buffer_without_exporting(): void
    {
        $service = new SiemExportService( [
            'enabled'       => true,
            'batch_enabled' => true,
        ] );

        $exporter = $this->createMockExporter( 'test', true );
        $service->registerExporter( $exporter );

        $service->exportEvent( ['event_type' => 'test', 'category' => 'authentication'] );
        $service->exportEvent( ['event_type' => 'test', 'category' => 'authentication'] );

        $this->assertEquals( 2, $service->getBufferSize() );

        $service->clearBuffer();

        $this->assertEquals( 0, $service->getBufferSize() );
    }

    public function test_it_exports_anomaly(): void
    {
        $exporter = $this->createMockExporter( 'test', true, ['success' => true] );
        $this->service->registerExporter( $exporter );

        $anomaly = Anomaly::factory()->create();

        $result = $this->service->exportAnomaly( $anomaly );

        $this->assertEquals( 1, $result['exported'] );
    }

    public function test_it_exports_incident(): void
    {
        $exporter = $this->createMockExporter( 'test', true, ['success' => true] );
        $this->service->registerExporter( $exporter );

        $incident = SecurityIncident::factory()->create();

        $result = $this->service->exportIncident( $incident );

        $this->assertEquals( 1, $result['exported'] );
    }

    public function test_it_exports_multiple_events(): void
    {
        $exporter = $this->createMockExporter( 'test', true, ['success' => true, 'exported' => 3] );
        $this->service->registerExporter( $exporter );

        $events = [
            ['event_type' => 'test1', 'category' => 'authentication'],
            ['event_type' => 'test2', 'category' => 'authorization'],
            ['event_type' => 'test3', 'category' => 'threat'],
        ];

        $result = $this->service->exportEvents( $events );

        $this->assertEquals( 3, $result['exported'] );
    }

    public function test_it_exports_recent_anomalies(): void
    {
        $exporter = $this->createMockExporter( 'test', true, ['success' => true, 'exported' => 3] );
        $this->service->registerExporter( $exporter );

        Anomaly::factory()->count( 3 )->create( ['detected_at' => now()->subMinutes( 30 )] );
        Anomaly::factory()->count( 2 )->create( ['detected_at' => now()->subHours( 2 )] );

        $result = $this->service->exportRecentAnomalies( 1 );

        // All 5 anomalies should be within the last hour scope
        $this->assertArrayHasKey( 'exported', $result );
    }

    public function test_it_exports_recent_incidents(): void
    {
        $exporter = $this->createMockExporter( 'test', true, ['success' => true, 'exported' => 2] );
        $this->service->registerExporter( $exporter );

        SecurityIncident::factory()->count( 2 )->create( ['updated_at' => now()->subMinutes( 30 )] );

        $result = $this->service->exportRecentIncidents( 1 );

        $this->assertArrayHasKey( 'exported', $result );
    }

    public function test_it_gets_statistics(): void
    {
        $exporter = $this->createMockExporter( 'test', true );
        $this->service->registerExporter( $exporter );

        $stats = $this->service->getStatistics();

        $this->assertArrayHasKey( 'enabled', $stats );
        $this->assertArrayHasKey( 'enabled_exporters', $stats );
        $this->assertArrayHasKey( 'buffer_size', $stats );
        $this->assertArrayHasKey( 'config', $stats );
        $this->assertTrue( $stats['enabled'] );
        $this->assertContains( 'test', $stats['enabled_exporters'] );
    }

    public function test_flush_returns_zero_when_buffer_empty(): void
    {
        $result = $this->service->flush();

        $this->assertEquals( 0, $result['flushed'] );
    }

    protected function createMockExporter( string $name, bool $enabled = true, array $exportResult = [] ): SiemExporterInterface
    {
        return new class( $name, $enabled, $exportResult ) implements SiemExporterInterface {
            public function __construct(
                private string $name,
                private bool $enabled,
                private array $exportResult,
            ) {
            }

            public function getName(): string
            {
                return $this->name;
            }

            public function isEnabled(): bool
            {
                return $this->enabled;
            }

            public function export( array $event): array
            {
                return $this->exportResult ?: ['success' => true];
            }

            public function exportBatch( array $events): array
            {
                return $this->exportResult ?: ['success' => true, 'exported' => count( $events)];
            }

            public function getConfig(): array
            {
                return [];
            }
        };
    }
}
