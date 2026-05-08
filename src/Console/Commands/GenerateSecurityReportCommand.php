<?php

declare( strict_types=1 );

namespace ArtisanPackUI\SecurityAnalytics\Console\Commands;

use ArtisanPackUI\SecurityAnalytics\Analytics\Reports\ReportGenerator;
use Exception;
use Illuminate\Console\Command;
use Illuminate\Support\Facades\Mail;
use Illuminate\Support\Facades\Storage;

class GenerateSecurityReportCommand extends Command
{
    /**
     * The name and signature of the console command.
     *
     * @var string
     */
    protected $signature = 'security:report:generate
                            {type : Report type (executive_summary, threat_report, compliance_report, incident_report, user_activity, trend_report)}
                            {--format=pdf : Output format (pdf, html, csv, json)}
                            {--from= : Start date (Y-m-d format)}
                            {--to= : End date (Y-m-d format)}
                            {--email=* : Email addresses to send report to}
                            {--output= : Output file path}
                            {--user= : User ID for user_activity report}';

    /**
     * The console command description.
     *
     * @var string
     */
    protected $description = 'Generate security reports';

    public function __construct(
        protected ReportGenerator $reportGenerator,
    ) {
        parent::__construct();
    }

    /**
     * Execute the console command.
     */
    public function handle(): int
    {
        $type   = $this->argument( 'type' );
        $format = $this->option( 'format' );
        $from   = $this->option( 'from' ) ? \Carbon\Carbon::parse( $this->option( 'from' ) ) : now()->subDays( 7 );
        $to     = $this->option( 'to' ) ? \Carbon\Carbon::parse( $this->option( 'to' ) ) : now();

        $this->info( "Generating {$type} report..." );

        $options = [
            'from'   => $from,
            'to'     => $to,
            'format' => $format,
        ];

        if ( $this->option( 'user' ) ) {
            $options['user_id'] = (int) $this->option( 'user' );
        }

        try {
            $report = $this->reportGenerator->generate( $type, $options );

            if ( ! $report ) {
                $this->error( 'Failed to generate report. Check the report type and options.' );

                return Command::FAILURE;
            }

            $content = $report->render( $format );

            // Handle output
            $outputPath = $this->option( 'output' );
            $emails     = $this->option( 'email' );

            if ( $outputPath ) {
                $this->saveReport( $content, $outputPath, $format );
            }

            if ( ! empty( $emails ) ) {
                $this->emailReport( $content, $emails, $type, $format, $from, $to );
            }

            if ( ! $outputPath && empty( $emails ) ) {
                // Default: save to storage
                $filename    = $this->generateFilename( $type, $format, $from, $to );
                $storagePath = config( 'security-analytics.reporting.storage_path', 'security-reports' );
                $fullPath    = "{$storagePath}/{$filename}";

                Storage::put( $fullPath, $content );
                $this->info( "Report saved to: {$fullPath}" );
            }

            $this->info( 'Report generated successfully.' );

            // Display summary
            $this->displayReportSummary( $report );

            return Command::SUCCESS;
        } catch ( Exception $e ) {
            $this->error( "Error generating report: {$e->getMessage()}" );

            return Command::FAILURE;
        }
    }

    /**
     * Save report to file.
     */
    protected function saveReport( string $content, string $path, string $format ): void
    {
        // Ensure path has correct extension
        $extension = $this->getExtension( $format );
        if ( ! str_ends_with( $path, ".{$extension}" ) ) {
            $path .= ".{$extension}";
        }

        file_put_contents( $path, $content );
        $this->info( "Report saved to: {$path}" );
    }

    /**
     * Email report to recipients.
     *
     * @param  array<int, string>  $emails
     */
    protected function emailReport(
        string $content,
        array $emails,
        string $type,
        string $format,
        \Carbon\Carbon $from,
        \Carbon\Carbon $to,
    ): void {
        $filename = $this->generateFilename( $type, $format, $from, $to );
        $subject  = $this->getEmailSubject( $type, $from, $to );

        foreach ( $emails as $email ) {
            Mail::raw(
                "Please find attached the {$type} security report for the period {$from->format( 'Y-m-d' )} to {$to->format( 'Y-m-d' )}.",
                function ( $message ) use ( $email, $subject, $content, $filename, $format ): void {
                    $message->to( $email )
                        ->subject( $subject )
                        ->attachData( $content, $filename, [
                            'mime' => $this->getMimeType( $format ),
                        ] );
                },
            );

            $this->info( "Report emailed to: {$email}" );
        }
    }

    /**
     * Generate filename for report.
     */
    protected function generateFilename( string $type, string $format, \Carbon\Carbon $from, \Carbon\Carbon $to ): string
    {
        $extension = $this->getExtension( $format );

        return sprintf(
            '%s_%s_to_%s.%s',
            str_replace( '_', '-', $type ),
            $from->format( 'Y-m-d' ),
            $to->format( 'Y-m-d' ),
            $extension,
        );
    }

    /**
     * Get file extension for format.
     */
    protected function getExtension( string $format ): string
    {
        return match ( $format ) {
            'pdf'   => 'pdf',
            'html'  => 'html',
            'csv'   => 'csv',
            'json'  => 'json',
            default => 'txt',
        };
    }

    /**
     * Get MIME type for format.
     */
    protected function getMimeType( string $format ): string
    {
        return match ( $format ) {
            'pdf'   => 'application/pdf',
            'html'  => 'text/html',
            'csv'   => 'text/csv',
            'json'  => 'application/json',
            default => 'text/plain',
        };
    }

    /**
     * Get email subject for report type.
     */
    protected function getEmailSubject( string $type, \Carbon\Carbon $from, \Carbon\Carbon $to ): string
    {
        $typeLabels = [
            'executive_summary' => 'Executive Security Summary',
            'threat_report'     => 'Security Threat Report',
            'compliance_report' => 'Compliance Status Report',
            'incident_report'   => 'Security Incident Report',
            'user_activity'     => 'User Activity Report',
            'trend_report'      => 'Security Trend Analysis',
        ];

        $label = $typeLabels[ $type ] ?? ucwords( str_replace( '_', ' ', $type ) );

        return "[Security] {$label} - {$from->format( 'M d' )} to {$to->format( 'M d, Y' )}";
    }

    /**
     * Display report summary.
     *
     * @param  mixed  $report
     */
    protected function displayReportSummary( $report ): void
    {
        $data = $report->getData();

        if ( isset( $data['summary'] ) ) {
            $this->newLine();
            $this->info( 'Report Summary:' );

            $rows = [];
            foreach ( $data['summary'] as $key => $value ) {
                if ( is_scalar( $value ) ) {
                    $rows[] = [ucwords( str_replace( '_', ' ', $key)), $value];
                }
            }

            if ( ! empty( $rows)) {
                $this->table( ['Metric', 'Value'], $rows);
            }
        }
    }
}
