<?php

declare( strict_types=1 );

namespace ArtisanPackUI\SecurityAnalytics\Console\Commands;

use ArtisanPackUI\SecurityAnalytics\Analytics\AnomalyDetection\AnomalyDetectionService;
use ArtisanPackUI\SecurityAnalytics\Analytics\MetricsCollector;
use ArtisanPackUI\SecurityAnalytics\Analytics\Siem\SiemExportService;
use Illuminate\Console\Command;

class AnalyticsProcessCommand extends Command
{
    /**
     * The name and signature of the console command.
     *
     * @var string
     */
    protected $signature = 'security:analytics:process
                            {--anomalies : Run anomaly detection}
                            {--export-siem : Export events to SIEM}
                            {--flush-metrics : Flush buffered metrics}
                            {--all : Run all processing tasks}';

    /**
     * The console command description.
     *
     * @var string
     */
    protected $description = 'Process security analytics data';

    public function __construct(
        protected MetricsCollector $metricsCollector,
        protected AnomalyDetectionService $anomalyDetection,
        protected SiemExportService $siemExport,
    ) {
        parent::__construct();
    }

    /**
     * Execute the console command.
     */
    public function handle(): int
    {
        $runAll = $this->option( 'all' );

        if ( $runAll || $this->option( 'flush-metrics' ) ) {
            $this->flushMetrics();
        }

        if ( $runAll || $this->option( 'anomalies' ) ) {
            $this->runAnomalyDetection();
        }

        if ( $runAll || $this->option( 'export-siem' ) ) {
            $this->exportToSiem();
        }

        if ( ! $runAll && ! $this->option( 'anomalies' ) && ! $this->option( 'export-siem' ) && ! $this->option( 'flush-metrics' ) ) {
            $this->info( 'No processing task specified. Use --all to run all tasks or specify individual tasks.' );
            $this->line( 'Available options:' );
            $this->line( '  --anomalies      Run anomaly detection' );
            $this->line( '  --export-siem    Export events to SIEM' );
            $this->line( '  --flush-metrics  Flush buffered metrics' );
            $this->line( '  --all            Run all processing tasks' );

            return Command::SUCCESS;
        }

        $this->info( 'Analytics processing completed.' );

        return Command::SUCCESS;
    }

    /**
     * Flush buffered metrics.
     */
    protected function flushMetrics(): void
    {
        $this->info( 'Flushing buffered metrics...' );

        $this->metricsCollector->flush();

        $this->info( 'Metrics flushed successfully.' );
    }

    /**
     * Run anomaly detection.
     */
    protected function runAnomalyDetection(): void
    {
        $this->info( 'Running anomaly detection...' );

        $anomalies = $this->anomalyDetection->detect();

        $count = $anomalies->count();

        if ( $count > 0 ) {
            $this->info( "Detected {$count} anomalies." );

            $this->table(
                ['ID', 'Detector', 'Category', 'Severity', 'Score'],
                $anomalies->map( fn ( $a ) => [
                    $a->id,
                    $a->detector,
                    $a->category,
                    $a->severity,
                    $a->score,
                ] )->toArray(),
            );
        } else {
            $this->info( 'No anomalies detected.' );
        }
    }

    /**
     * Export events to SIEM.
     */
    protected function exportToSiem(): void
    {
        if ( ! $this->siemExport->isEnabled() ) {
            $this->warn( 'SIEM export is not enabled. Check your configuration.' );

            return;
        }

        $this->info( 'Exporting events to SIEM...' );

        // Flush any buffered events
        $result = $this->siemExport->flush();

        $exported = $result['exported'] ?? $result['flushed'] ?? 0;

        $this->info( "Exported {$exported} events to SIEM." );

        // Export recent anomalies
        $anomalyResult   = $this->siemExport->exportRecentAnomalies( 1 );
        $anomalyExported = $anomalyResult['exported'] ?? 0;

        $this->info( "Exported {$anomalyExported} recent anomalies." );

        // Export recent incidents
        $incidentResult   = $this->siemExport->exportRecentIncidents( 1 );
        $incidentExported = $incidentResult['exported'] ?? 0;

        $this->info( "Exported {$incidentExported} recent incidents." );
    }
}
