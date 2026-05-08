<?php

declare( strict_types=1 );

namespace ArtisanPackUI\SecurityAnalytics\Console\Commands;

use ArtisanPackUI\SecurityAnalytics\Analytics\ThreatIntelligence\ThreatIntelligenceService;
use ArtisanPackUI\SecurityAnalytics\Models\ThreatIndicator;
use Exception;
use Illuminate\Console\Command;
use Illuminate\Support\Facades\Http;

class SyncThreatFeedsCommand extends Command
{
    /**
     * The name and signature of the console command.
     *
     * @var string
     */
    protected $signature = 'security:threat-feeds:sync
                            {--feed=* : Specific feed URLs to sync}
                            {--cleanup : Cleanup expired indicators after sync}
                            {--stats : Show statistics after sync}';

    /**
     * The console command description.
     *
     * @var string
     */
    protected $description = 'Synchronize threat intelligence feeds';

    public function __construct(
        protected ThreatIntelligenceService $threatIntel,
    ) {
        parent::__construct();
    }

    /**
     * Execute the console command.
     */
    public function handle(): int
    {
        $this->info( 'Starting threat feed synchronization...' );

        $feeds = $this->option( 'feed' );

        if ( empty( $feeds ) ) {
            $feeds = config( 'artisanpack.security-analytics.threat_intelligence.custom_feeds', [] );
        }

        $totalImported = 0;

        foreach ( $feeds as $feedUrl ) {
            $imported = $this->syncFeed( $feedUrl );
            $totalImported += $imported;
        }

        $this->info( "Total indicators imported: {$totalImported}" );

        if ( $this->option( 'cleanup' ) ) {
            $this->cleanupExpired();
        }

        if ( $this->option( 'stats' ) ) {
            $this->showStatistics();
        }

        return Command::SUCCESS;
    }

    /**
     * Sync a single feed.
     */
    protected function syncFeed( string $feedUrl ): int
    {
        $this->info( "Syncing feed: {$feedUrl}" );

        try {
            $response = Http::timeout( 30 )->get( $feedUrl );

            if ( ! $response->successful() ) {
                $this->error( "Failed to fetch feed: HTTP {$response->status()}" );

                return 0;
            }

            $indicators = $this->parseFeed( $response->body(), $feedUrl );

            if ( empty( $indicators ) ) {
                $this->warn( 'No indicators found in feed.' );

                return 0;
            }

            $imported = $this->threatIntel->importIndicators( $indicators, $this->getFeedSource( $feedUrl ) );

            $this->info( "Imported {$imported} indicators from feed." );

            return $imported;
        } catch ( Exception $e ) {
            $this->error( "Error syncing feed: {$e->getMessage()}" );

            return 0;
        }
    }

    /**
     * Parse feed content into indicators.
     *
     * @return array<int, array<string, mixed>>
     */
    protected function parseFeed( string $content, string $feedUrl ): array
    {
        $indicators = [];

        // Try JSON format first
        $data = json_decode( $content, true );

        if ( JSON_ERROR_NONE === json_last_error() ) {
            return $this->parseJsonFeed( $data );
        }

        // Try CSV format
        if ( str_contains( $content, ',' ) || str_contains( $content, "\t" ) ) {
            return $this->parseCsvFeed( $content );
        }

        // Plain text (one indicator per line)
        return $this->parsePlainTextFeed( $content );
    }

    /**
     * Parse JSON feed.
     *
     * @param  array<string, mixed>  $data
     *
     * @return array<int, array<string, mixed>>
     */
    protected function parseJsonFeed( array $data ): array
    {
        $indicators = [];

        // Handle STIX format
        if ( isset( $data['objects'] ) ) {
            foreach ( $data['objects'] as $object ) {
                if ( 'indicator' === $object['type'] ) {
                    $indicators[] = $this->parseStixIndicator( $object );
                }
            }

            return array_filter( $indicators );
        }

        // Handle simple JSON array
        if ( isset( $data['indicators'] ) ) {
            return $data['indicators'];
        }

        // Handle flat array of indicators
        if ( is_array( $data ) && isset( $data[0] ) ) {
            return $data;
        }

        return $indicators;
    }

    /**
     * Parse STIX indicator.
     *
     * @param  array<string, mixed>  $object
     *
     * @return array<string, mixed>|null
     */
    protected function parseStixIndicator( array $object ): ?array
    {
        $pattern = $object['pattern'] ?? '';

        // Extract indicator from STIX pattern
        if ( preg_match( "/\[ipv4-addr:value\s*=\s*'([^']+)'\]/", $pattern, $matches ) ) {
            return [
                'type'        => ThreatIndicator::TYPE_IP,
                'value'       => $matches[1],
                'threat_type' => $object['indicator_types'][0] ?? 'unknown',
                'confidence'  => $object['confidence'] ?? 50,
            ];
        }

        if ( preg_match( "/\[domain-name:value\s*=\s*'([^']+)'\]/", $pattern, $matches ) ) {
            return [
                'type'        => ThreatIndicator::TYPE_DOMAIN,
                'value'       => $matches[1],
                'threat_type' => $object['indicator_types'][0] ?? 'unknown',
                'confidence'  => $object['confidence'] ?? 50,
            ];
        }

        if ( preg_match( "/\[file:hashes\.'SHA-256'\s*=\s*'([^']+)'\]/", $pattern, $matches ) ) {
            return [
                'type'        => ThreatIndicator::TYPE_HASH,
                'value'       => $matches[1],
                'threat_type' => $object['indicator_types'][0] ?? 'unknown',
                'confidence'  => $object['confidence'] ?? 50,
            ];
        }

        return null;
    }

    /**
     * Parse CSV feed.
     *
     * @return array<int, array<string, mixed>>
     */
    protected function parseCsvFeed( string $content ): array
    {
        $indicators = [];
        $lines      = explode( "\n", trim( $content ) );

        // Skip header if present
        $firstLine = trim( $lines[0] );
        $hasHeader = str_contains( strtolower( $firstLine ), 'indicator' )
            || str_contains( strtolower( $firstLine ), 'type' )
            || str_contains( strtolower( $firstLine ), 'ip' );

        if ( $hasHeader ) {
            array_shift( $lines );
        }

        foreach ( $lines as $line ) {
            $line = trim( $line );
            if ( empty( $line ) || str_starts_with( $line, '#' ) ) {
                continue;
            }

            $parts = str_getcsv( $line );

            if ( count( $parts ) >= 1 ) {
                $value = trim( $parts[0] );
                $type  = $this->detectIndicatorType( $value );

                $indicators[] = [
                    'type'        => $type,
                    'value'       => $value,
                    'threat_type' => $parts[1] ?? 'unknown',
                    'confidence'  => isset( $parts[2] ) ? (int) $parts[2] : 50,
                ];
            }
        }

        return $indicators;
    }

    /**
     * Parse plain text feed.
     *
     * @return array<int, array<string, mixed>>
     */
    protected function parsePlainTextFeed( string $content ): array
    {
        $indicators = [];
        $lines      = explode( "\n", trim( $content ) );

        foreach ( $lines as $line ) {
            $line = trim( $line );
            if ( empty( $line ) || str_starts_with( $line, '#' ) ) {
                continue;
            }

            $type = $this->detectIndicatorType( $line );

            $indicators[] = [
                'type'        => $type,
                'value'       => $line,
                'threat_type' => 'unknown',
                'confidence'  => 50,
            ];
        }

        return $indicators;
    }

    /**
     * Detect indicator type from value.
     */
    protected function detectIndicatorType( string $value ): string
    {
        // IP address
        if ( filter_var( $value, FILTER_VALIDATE_IP ) ) {
            return ThreatIndicator::TYPE_IP;
        }

        // Hash (MD5, SHA1, SHA256)
        if ( preg_match( '/^[a-f0-9]{32}$/i', $value ) || preg_match( '/^[a-f0-9]{40}$/i', $value ) || preg_match( '/^[a-f0-9]{64}$/i', $value ) ) {
            return ThreatIndicator::TYPE_HASH;
        }

        // URL
        if ( filter_var( $value, FILTER_VALIDATE_URL ) ) {
            return ThreatIndicator::TYPE_URL;
        }

        // Email
        if ( filter_var( $value, FILTER_VALIDATE_EMAIL ) ) {
            return ThreatIndicator::TYPE_EMAIL;
        }

        // Default to domain
        return ThreatIndicator::TYPE_DOMAIN;
    }

    /**
     * Get source name from feed URL.
     */
    protected function getFeedSource( string $feedUrl ): string
    {
        $host = parse_url( $feedUrl, PHP_URL_HOST );

        return $host ?: 'custom_feed';
    }

    /**
     * Cleanup expired indicators.
     */
    protected function cleanupExpired(): void
    {
        $this->info( 'Cleaning up expired indicators...' );

        $deleted = $this->threatIntel->cleanupExpired();

        $this->info( "Deleted {$deleted} expired indicators." );
    }

    /**
     * Show statistics.
     */
    protected function showStatistics(): void
    {
        $this->info( 'Threat Intelligence Statistics:' );

        $stats = $this->threatIntel->getStatistics();

        $this->table(
            ['Metric', 'Value'],
            [
                ['Total Indicators', $stats['total_indicators']],
                ['Active Indicators', $stats['active_indicators']],
                ['Expiring Soon', $stats['expiring_soon']],
            ],
        );

        if ( ! empty( $stats['by_type'] ) ) {
            $this->info( 'By Type:' );
            $this->table(
                ['Type', 'Count'],
                collect( $stats['by_type'] )->map( fn ( $count, $type ) => [$type, $count] )->toArray(),
            );
        }

        if ( ! empty( $stats['by_threat_type'] ) ) {
            $this->info( 'By Threat Type:' );
            $this->table(
                ['Threat Type', 'Count'],
                collect( $stats['by_threat_type'] )->map( fn ( $count, $type ) => [$type, $count] )->toArray(),
            );
        }
    }
}
