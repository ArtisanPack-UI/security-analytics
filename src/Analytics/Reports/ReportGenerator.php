<?php

declare( strict_types=1 );

namespace ArtisanPackUI\SecurityAnalytics\Analytics\Reports;

use ArtisanPackUI\SecurityAnalytics\Analytics\Reports\Contracts\ReportInterface;
use ArtisanPackUI\SecurityAnalytics\Models\ScheduledReport;
use Exception;
use Illuminate\Support\Facades\Storage;
use InvalidArgumentException;

class ReportGenerator
{
    /**
     * @var array<string, class-string<ReportInterface>>
     */
    protected array $reportTypes = [];

    /**
     * @var array<string, mixed>
     */
    protected array $config;

    /**
     * @param  array<string, mixed>  $config
     */
    public function __construct( array $config = [] )
    {
        $this->config = array_merge( [
            'storage_path'   => storage_path( 'app/security-reports' ),
            'default_format' => 'html',
        ], $config );

        $this->registerDefaultReports();
    }

    /**
     * Register a report type.
     *
     * @param  class-string<ReportInterface>  $reportClass
     */
    public function registerReportType( string $type, string $reportClass ): self
    {
        $this->reportTypes[ $type ] = $reportClass;

        return $this;
    }

    /**
     * Generate a report.
     *
     * @param  array<string, mixed>  $options
     *
     * @return array<string, mixed>
     */
    public function generate( string $type, array $options = [] ): array
    {
        if ( ! isset( $this->reportTypes[ $type ] ) ) {
            throw new InvalidArgumentException( "Unknown report type: {$type}" );
        }

        $reportClass = $this->reportTypes[ $type ];
        $report      = new $reportClass( $options );

        $data   = $report->generate();
        $format = $options['format'] ?? $this->config['default_format'];

        $content  = $this->formatReport( $report, $data, $format );
        $filename = $this->generateFilename( $type, $format );
        $path     = $this->saveReport( $filename, $content );

        return [
            'type'         => $type,
            'format'       => $format,
            'path'         => $path,
            'filename'     => $filename,
            'generated_at' => now()->toIso8601String(),
            'data'         => $data,
        ];
    }

    /**
     * Generate a scheduled report.
     *
     * @return array<string, mixed>
     */
    public function generateScheduledReport( ScheduledReport $scheduledReport ): array
    {
        $options           = $scheduledReport->options ?? [];
        $options['format'] = $scheduledReport->format;

        $result = $this->generate( $scheduledReport->report_type, $options );

        // Mark the report as run
        $scheduledReport->markAsRun();

        return array_merge( $result, [
            'scheduled_report_id'   => $scheduledReport->id,
            'scheduled_report_name' => $scheduledReport->name,
        ] );
    }

    /**
     * Get available report types.
     *
     * @return array<string, string>
     */
    public function getAvailableReportTypes(): array
    {
        return array_keys( $this->reportTypes );
    }

    /**
     * Run all due scheduled reports.
     *
     * @return array<int, array<string, mixed>>
     */
    public function runDueReports(): array
    {
        $results = [];

        $dueReports = ScheduledReport::due()->get();

        foreach ( $dueReports as $scheduledReport ) {
            try {
                $result           = $this->generateScheduledReport( $scheduledReport );
                $result['status'] = 'success';

                // Send to recipients if configured
                $this->sendToRecipients( $scheduledReport, $result );
            } catch ( Exception $e ) {
                $result = [
                    'scheduled_report_id' => $scheduledReport->id,
                    'status'              => 'error',
                    'error'               => $e->getMessage(),
                ];
            }

            $results[] = $result;
        }

        return $results;
    }

    /**
     * Cleanup old reports.
     */
    public function cleanup( int $daysOld = 30 ): int
    {
        $cutoff = now()->subDays( $daysOld );
        $count  = 0;

        $path = $this->config['storage_path'];

        if ( ! is_dir( $path ) ) {
            return 0;
        }

        $files = glob( $path . '/security_*' );

        foreach ( $files as $file ) {
            if ( filemtime( $file ) < $cutoff->timestamp ) {
                if ( unlink( $file ) ) {
                    $count++;
                }
            }
        }

        return $count;
    }

    /**
     * Register default report types.
     */
    protected function registerDefaultReports(): void
    {
        $this->registerReportType( ScheduledReport::TYPE_EXECUTIVE, ExecutiveSummaryReport::class );
        $this->registerReportType( ScheduledReport::TYPE_THREAT, ThreatReport::class );
        $this->registerReportType( ScheduledReport::TYPE_INCIDENT, IncidentReport::class );
        $this->registerReportType( ScheduledReport::TYPE_COMPLIANCE, ComplianceReport::class );
        $this->registerReportType( ScheduledReport::TYPE_USER_ACTIVITY, UserActivityReport::class );
        $this->registerReportType( ScheduledReport::TYPE_TREND, TrendReport::class );
    }

    /**
     * Format report content based on format type.
     *
     * @param  array<string, mixed>  $data
     */
    protected function formatReport( ReportInterface $report, array $data, string $format ): string
    {
        return match ( $format ) {
            'html'  => $report->toHtml( $data ),
            'json'  => json_encode( $data, JSON_PRETTY_PRINT ),
            'csv'   => $report->toCsv( $data ),
            'pdf'   => $report->toPdf( $data ),
            default => json_encode( $data, JSON_PRETTY_PRINT ),
        };
    }

    /**
     * Generate a filename for the report.
     */
    protected function generateFilename( string $type, string $format ): string
    {
        $timestamp = now()->format( 'Y-m-d_H-i-s' );

        return "security_{$type}_{$timestamp}.{$format}";
    }

    /**
     * Save report to storage.
     */
    protected function saveReport( string $filename, string $content ): string
    {
        $path = $this->config['storage_path'] . '/' . $filename;

        // Ensure directory exists
        $dir = dirname( $path );
        if ( ! is_dir( $dir ) ) {
            mkdir( $dir, 0755, true );
        }

        file_put_contents( $path, $content );

        return $path;
    }

    /**
     * Send report to configured recipients.
     *
     * @param  array<string, mixed>  $result
     */
    protected function sendToRecipients( ScheduledReport $scheduledReport, array $result ): void
    {
        $recipients = $scheduledReport->getEmailRecipients();

        if ( empty( $recipients ) ) {
            return;
        }

        // Simple email sending - in production, use a proper notification system
        foreach ( $recipients as $recipient ) {
            try {
                \Illuminate\Support\Facades\Mail::raw(
                    $this->buildReportEmailBody( $scheduledReport, $result ),
                    function ( $message ) use ( $recipient, $scheduledReport, $result ): void {
                        $message->to( $recipient )
                            ->subject( "Security Report: {$scheduledReport->name}" )
                            ->attach( $result['path'] );
                    },
                );
            } catch ( Exception $e ) {
                // Log error but don't fail the entire process
                report( $e );
            }
        }
    }

    /**
     * Build report email body.
     *
     * @param  array<string, mixed>  $result
     */
    protected function buildReportEmailBody( ScheduledReport $scheduledReport, array $result ): string
    {
        return implode( "\n", [
            "Security Report: {$scheduledReport->name}",
            '',
            "Report Type: {$scheduledReport->report_type}",
            "Format: {$result['format']}",
            "Generated At: {$result['generated_at']}",
            '',
            'The report is attached to this email.',
        ]);
    }
}
