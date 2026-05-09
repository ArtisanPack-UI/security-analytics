<?php

declare( strict_types=1 );

namespace ArtisanPackUI\SecurityAnalytics\Jobs;

use ArtisanPackUI\SecurityAnalytics\Analytics\Reports\ReportGenerator;
use ArtisanPackUI\SecurityAnalytics\Models\ScheduledReport;
use Carbon\Carbon;
use Exception;
use Illuminate\Bus\Queueable;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Foundation\Bus\Dispatchable;
use Illuminate\Queue\InteractsWithQueue;
use Illuminate\Queue\SerializesModels;
use Illuminate\Support\Facades\Mail;
use Illuminate\Support\Facades\Storage;
use Log;
use Throwable;

class GenerateScheduledReport implements ShouldQueue
{
    use Dispatchable;
use InteractsWithQueue;
use Queueable;
use SerializesModels;

    /**
     * The number of times the job may be attempted.
     *
     * @var int
     */
    public int $tries = 3;

    /**
     * The number of seconds the job can run before timing out.
     *
     * @var int
     */
    public int $timeout = 300;

    /**
     * Create a new job instance.
     */
    public function __construct(
        protected int $scheduledReportId,
    ) {
    }

    /**
     * Execute the job.
     */
    public function handle( ReportGenerator $reportGenerator ): void
    {
        $scheduledReport = ScheduledReport::find( $this->scheduledReportId );

        if ( ! $scheduledReport || ! $scheduledReport->is_active ) {
            Log::info( 'Scheduled report not found or inactive', [
                'scheduled_report_id' => $this->scheduledReportId,
            ] );

            return;
        }

        $options = $scheduledReport->options ?? [];
        $period  = $this->calculateReportPeriod( $scheduledReport );

        $options['from']   = $period['from'];
        $options['to']     = $period['to'];
        $options['format'] = $scheduledReport->format;

        try {
            // Generate the report
            $report = $reportGenerator->generate( $scheduledReport->report_type, $options );

            if ( ! $report ) {
                throw new Exception( 'Failed to generate report' );
            }

            $content = $report->render( $scheduledReport->format );

            // Save to storage
            $filename    = $this->generateFilename( $scheduledReport, $period );
            $storagePath = config( 'security-analytics.reporting.storage_path', 'security-reports' );
            $fullPath    = "{$storagePath}/{$filename}";

            Storage::put( $fullPath, $content );

            // Send to recipients
            $this->sendToRecipients( $scheduledReport, $content, $filename, $period );

            // Update last run time and calculate next run
            $scheduledReport->update( [
                'last_run_at' => now(),
                'next_run_at' => $this->calculateNextRun( $scheduledReport ),
            ] );

            Log::info( 'Scheduled report generated successfully', [
                'scheduled_report_id' => $scheduledReport->id,
                'report_type'         => $scheduledReport->report_type,
                'path'                => $fullPath,
            ] );
        } catch ( Exception $e ) {
            Log::error( 'Failed to generate scheduled report', [
                'scheduled_report_id' => $scheduledReport->id,
                'exception'           => $e->getMessage(),
            ] );

            throw $e;
        }
    }

    /**
     * Handle a job failure.
     */
    public function failed( Throwable $exception ): void
    {
        Log::error( 'Scheduled report generation failed permanently', [
            'scheduled_report_id' => $this->scheduledReportId,
            'exception'           => $exception->getMessage(),
        ] );
    }

    /**
     * Get the tags that should be assigned to the job.
     *
     * @return array<int, string>
     */
    public function tags(): array
    {
        return [
            'security',
            'report',
            "scheduled_report:{$this->scheduledReportId}",
        ];
    }

    /**
     * Calculate the report period based on cron expression.
     *
     * @return array{from: Carbon, to: Carbon}
     */
    protected function calculateReportPeriod( ScheduledReport $scheduledReport ): array
    {
        $now = now();

        // Parse cron expression to determine period
        $cronExpression = $scheduledReport->cron_expression;

        // Daily report (0 0 * * *)
        if ( preg_match( '/^0 0 \* \* \*$/', $cronExpression ) ) {
            return [
                'from' => $now->copy()->subDay()->startOfDay(),
                'to'   => $now->copy()->subDay()->endOfDay(),
            ];
        }

        // Weekly report (0 0 * * 0 or 0 0 * * 1)
        if ( preg_match( '/^0 0 \* \* [01]$/', $cronExpression ) ) {
            return [
                'from' => $now->copy()->subWeek()->startOfWeek(),
                'to'   => $now->copy()->subWeek()->endOfWeek(),
            ];
        }

        // Monthly report (0 0 1 * *)
        if ( preg_match( '/^0 0 1 \* \*$/', $cronExpression ) ) {
            return [
                'from' => $now->copy()->subMonth()->startOfMonth(),
                'to'   => $now->copy()->subMonth()->endOfMonth(),
            ];
        }

        // Default: last 7 days
        return [
            'from' => $now->copy()->subDays( 7 )->startOfDay(),
            'to'   => $now->copy()->subDay()->endOfDay(),
        ];
    }

    /**
     * Generate filename for the report.
     *
     * @param  array{from: Carbon, to: Carbon}  $period
     */
    protected function generateFilename( ScheduledReport $scheduledReport, array $period ): string
    {
        $extension = match ( $scheduledReport->format ) {
            'pdf'   => 'pdf',
            'html'  => 'html',
            'csv'   => 'csv',
            'json'  => 'json',
            default => 'txt',
        };

        return sprintf(
            '%s_%s_to_%s.%s',
            str_replace( '_', '-', $scheduledReport->report_type ),
            $period['from']->format( 'Y-m-d' ),
            $period['to']->format( 'Y-m-d' ),
            $extension,
        );
    }

    /**
     * Send report to recipients.
     *
     * @param  array{from: Carbon, to: Carbon}  $period
     */
    protected function sendToRecipients(
        ScheduledReport $scheduledReport,
        string $content,
        string $filename,
        array $period,
    ): void {
        $recipients = $scheduledReport->recipients ?? [];

        if ( empty( $recipients ) ) {
            return;
        }

        $subject = sprintf(
            '[Security] %s - %s to %s',
            ucwords( str_replace( '_', ' ', $scheduledReport->report_type ) ),
            $period['from']->format( 'M d' ),
            $period['to']->format( 'M d, Y' ),
        );

        $mimeType = match ( $scheduledReport->format ) {
            'pdf'   => 'application/pdf',
            'html'  => 'text/html',
            'csv'   => 'text/csv',
            'json'  => 'application/json',
            default => 'text/plain',
        };

        foreach ( $recipients as $recipient ) {
            try {
                Mail::raw(
                    "Please find attached the scheduled security report.\n\nReport: {$scheduledReport->name}\nPeriod: {$period['from']->format( 'Y-m-d' )} to {$period['to']->format( 'Y-m-d' )}",
                    function ( $message ) use ( $recipient, $subject, $content, $filename, $mimeType ): void {
                        $message->to( $recipient )
                            ->subject( $subject )
                            ->attachData( $content, $filename, [
                                'mime' => $mimeType,
                            ] );
                    },
                );

                Log::debug( 'Report sent to recipient', ['recipient' => $recipient] );
            } catch ( Exception $e ) {
                Log::error( 'Failed to send report to recipient', [
                    'recipient' => $recipient,
                    'exception' => $e->getMessage(),
                ] );
            }
        }
    }

    /**
     * Calculate next run time based on cron expression.
     */
    protected function calculateNextRun( ScheduledReport $scheduledReport ): Carbon
    {
        $cron = new \Cron\CronExpression( $scheduledReport->cron_expression );

        return Carbon::instance( $cron->getNextRunDate());
    }
}
