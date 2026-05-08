<?php

declare( strict_types=1 );

namespace ArtisanPackUI\SecurityAnalytics\Console\Commands;

use ArtisanPackUI\SecurityAnalytics\Contracts\SecurityEventLoggerInterface;
use ArtisanPackUI\SecurityAnalytics\Models\SecurityEvent;
use Illuminate\Console\Command;

class SecurityEventStats extends Command
{
    /**
     * The name and signature of the console command.
     *
     * @var string
     */
    protected $signature = 'security:events:stats
                            {--days=7 : Number of days to analyze}';

    /**
     * The console command description.
     *
     * @var string
     */
    protected $description = 'Display security event statistics';

    /**
     * Execute the console command.
     */
    public function handle( SecurityEventLoggerInterface $logger ): int
    {
        $days = (int) $this->option( 'days' );
        
        if ( $days < 1 ) {
            $this->error( 'Days must be a positive integer.' );
            return self::FAILURE;
        }
        
        if ( $days > 365 ) {
            $this->warn( 'Querying more than 365 days may impact performance.' );
        }
        
        $stats = $logger->getEventStats( $days );

        $this->info( "Security Event Statistics (Last {$days} days)" );
        $this->newLine();

        // Summary
        $this->line( "<fg=cyan>Total Events:</> {$stats['total']}" );
        $this->line( "<fg=red>Failed Logins:</> {$stats['failedLogins']}" );
        $this->line( "<fg=yellow>Authorization Failures:</> {$stats['authorizationFailures']}" );
        $this->newLine();

        // Events by type
        if ( ! empty( $stats['byType'] ) ) {
            $this->info( 'Events by Type:' );
            $this->table(
                ['Type', 'Count'],
                collect( $stats['byType'] )->map( fn ( $count, $type ) => [$type, $count] )->toArray(),
            );
        }

        // Events by severity
        if ( ! empty( $stats['bySeverity'] ) ) {
            $this->info( 'Events by Severity:' );
            $rows = collect( $stats['bySeverity'] )->map( function ( $count, $severity ) {
                return [$this->formatSeverity( $severity ), $count];
            } )->toArray();
            $this->table( ['Severity', 'Count'], $rows );
        }

        // Top IPs
        if ( ! empty( $stats['topIps'] ) ) {
            $this->info( 'Top IP Addresses:' );
            $this->table(
                ['IP Address', 'Events'],
                collect( $stats['topIps'] )->map( fn ( $count, $ip ) => [$ip, $count] )->toArray(),
            );
        }

        // Top Users
        if ( ! empty( $stats['topUsers'] ) ) {
            $this->info( 'Top Users:' );
            $this->table(
                ['User ID', 'Events'],
                collect( $stats['topUsers'] )->map( fn ( $count, $userId ) => [$userId, $count] )->toArray(),
            );
        }

        return self::SUCCESS;
    }

    /**
     * Format severity with color.
     */
    protected function formatSeverity( string $severity ): string
    {
        return match ( $severity ) {
            SecurityEvent::SEVERITY_DEBUG    => "<fg=gray>{$severity}</>",
            SecurityEvent::SEVERITY_INFO     => "<fg=blue>{$severity}</>",
            SecurityEvent::SEVERITY_WARNING  => "<fg=yellow>{$severity}</>",
            SecurityEvent::SEVERITY_ERROR    => "<fg=red>{$severity}</>",
            SecurityEvent::SEVERITY_CRITICAL => "<fg=white;bg=red>{$severity}</>",
            default                          => $severity,
        };
    }
}
