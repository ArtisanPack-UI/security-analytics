<?php

declare( strict_types=1 );

namespace ArtisanPackUI\SecurityAnalytics\Console\Commands;

use ArtisanPackUI\SecurityAnalytics\Analytics\Siem\SiemExportService;
use Exception;
use Illuminate\Console\Command;

class TestSiemConnectionCommand extends Command
{
    /**
     * The name and signature of the console command.
     *
     * @var string
     */
    protected $signature = 'security:siem:test
                            {--provider= : Test specific provider (splunk, elasticsearch, syslog)}
                            {--send-test : Send a test event to SIEM}';

    /**
     * The console command description.
     *
     * @var string
     */
    protected $description = 'Test SIEM connections and configuration';

    public function __construct(
        protected SiemExportService $siemExport,
    ) {
        parent::__construct();
    }

    /**
     * Execute the console command.
     */
    public function handle(): int
    {
        $this->info( 'Testing SIEM configuration...' );
        $this->newLine();

        // Check if SIEM is enabled
        if ( ! $this->siemExport->isEnabled() ) {
            $this->warn( 'SIEM export is not enabled.' );
            $this->line( 'To enable SIEM export, set SECURITY_SIEM_ENABLED=true in your .env file' );
            $this->line( 'and configure at least one provider.' );

            return Command::SUCCESS;
        }

        $specificProvider = $this->option( 'provider' );

        if ( $specificProvider ) {
            $this->testProvider( $specificProvider );
        } else {
            $this->testAllProviders();
        }

        if ( $this->option( 'send-test' ) ) {
            $this->sendTestEvent();
        }

        $this->showStatistics();

        return Command::SUCCESS;
    }

    /**
     * Test a specific provider.
     */
    protected function testProvider( string $providerName ): void
    {
        $exporter = $this->siemExport->getExporter( $providerName );

        if ( ! $exporter ) {
            $this->error( "Provider '{$providerName}' is not registered." );

            return;
        }

        $this->info( "Testing {$providerName} provider..." );

        if ( ! $exporter->isEnabled() ) {
            $this->warn( '  Provider is registered but not enabled.' );

            return;
        }

        $result = $this->testExporterConnection( $exporter );
        $this->displayTestResult( $providerName, $result );
    }

    /**
     * Test all providers.
     */
    protected function testAllProviders(): void
    {
        $exporters = $this->siemExport->getEnabledExporters();

        if ( empty( $exporters ) ) {
            $this->warn( 'No enabled SIEM exporters found.' );

            return;
        }

        $this->info( 'Testing all enabled exporters:' );
        $this->newLine();

        $results = [];

        foreach ( $exporters as $name => $exporter ) {
            $result           = $this->testExporterConnection( $exporter );
            $results[ $name ] = $result;
            $this->displayTestResult( $name, $result );
        }

        // Summary
        $this->newLine();
        $successful = count( array_filter( $results, fn ( $r ) => $r['success'] ) );
        $total      = count( $results );

        $this->info( "Connection tests completed: {$successful}/{$total} successful" );
    }

    /**
     * Test exporter connection.
     *
     * @return array<string, mixed>
     */
    protected function testExporterConnection( $exporter ): array
    {
        try {
            // Try to send a minimal test payload
            $testEvent = [
                'event_type' => 'connection_test',
                'category'   => 'system',
                'severity'   => 'info',
                'timestamp'  => now()->toIso8601String(),
                'message'    => 'SIEM connection test from ArtisanPack Security',
                'source'     => config( 'app.name', 'Laravel' ),
                'test'       => true,
            ];

            $result = $exporter->export( $testEvent );

            return [
                'success'    => $result['success'] ?? false,
                'message'    => $result['message'] ?? 'Connection successful',
                'latency_ms' => $result['latency_ms'] ?? null,
            ];
        } catch ( Exception $e ) {
            return [
                'success' => false,
                'message' => $e->getMessage(),
            ];
        }
    }

    /**
     * Display test result.
     *
     * @param  array<string, mixed>  $result
     */
    protected function displayTestResult( string $name, array $result ): void
    {
        $status = $result['success'] ? '<fg=green>PASS</>' : '<fg=red>FAIL</>';

        $this->line( "  [{$status}] {$name}" );

        if ( ! $result['success'] ) {
            $this->line( "        Error: {$result['message']}" );
        } elseif ( isset( $result['latency_ms'] ) ) {
            $this->line( "        Latency: {$result['latency_ms']}ms" );
        }
    }

    /**
     * Send a test event.
     */
    protected function sendTestEvent(): void
    {
        $this->newLine();
        $this->info( 'Sending test event to SIEM...' );

        $testEvent = [
            'event_type' => 'security_test',
            'category'   => 'system',
            'severity'   => 'info',
            'timestamp'  => now()->toIso8601String(),
            'message'    => 'Test security event from ArtisanPack Security CLI',
            'source'     => [
                'application' => config( 'app.name', 'Laravel' ),
                'environment' => config( 'app.env' ),
                'host'        => gethostname() ?: 'unknown',
            ],
            'details' => [
                'test_id'      => uniqid( 'test_', true ),
                'initiated_by' => 'cli',
                'command'      => 'security:siem:test',
            ],
        ];

        $result = $this->siemExport->exportEvent( $testEvent );

        if ( $result['skipped'] ?? false ) {
            $this->warn( "Test event was skipped: {$result['reason']}" );
        } elseif ( $result['buffered'] ?? false ) {
            $this->info( 'Test event was added to buffer.' );
            $this->line( 'Use --flush flag or wait for automatic flush to send.' );
        } else {
            $this->info( 'Test event sent successfully.' );

            if ( isset( $result['results'] ) ) {
                foreach ( $result['results'] as $provider => $providerResult ) {
                    $status = ( $providerResult['success'] ?? true ) ? 'sent' : 'failed';
                    $this->line( "  {$provider}: {$status}" );
                }
            }
        }
    }

    /**
     * Show SIEM statistics.
     */
    protected function showStatistics(): void
    {
        $this->newLine();
        $this->info( 'SIEM Export Statistics:' );

        $stats = $this->siemExport->getStatistics();

        $this->table(
            ['Setting', 'Value'],
            [
                ['Enabled', $stats['enabled'] ? 'Yes' : 'No'],
                ['Enabled Exporters', implode( ', ', $stats['enabled_exporters'] )],
                ['Buffer Size', $stats['buffer_size']],
                ['Batch Enabled', $stats['config']['batch_enabled'] ? 'Yes' : 'No'],
                ['Batch Size', $stats['config']['batch_size']],
            ],
        );

        if ( ! empty( $stats['exporters'] ) ) {
            $this->newLine();
            $this->info( 'Exporter Statistics:' );

            $rows = [];
            foreach ( $stats['exporters'] as $name => $exporterStats ) {
                $rows[] = [
                    $name,
                    $exporterStats['total_exported'],
                    $exporterStats['errors'],
                    $exporterStats['last_export'] ?? 'Never',
                ];
            }

            $this->table( ['Exporter', 'Total Exported', 'Errors', 'Last Export'], $rows);
        }
    }
}
