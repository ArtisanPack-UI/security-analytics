<?php

/**
 * `ListSecurityEvents` Artisan command.
 *
 * @package    ArtisanPack_UI
 * @subpackage SecurityAnalytics
 *
 * @author     Jacob Martella <support@artisanpackui.dev>
 *
 * @since      1.0.0
 */

declare( strict_types=1 );

namespace ArtisanPackUI\SecurityAnalytics\Console\Commands;

use ArtisanPackUI\SecurityAnalytics\Models\SecurityEvent;
use Illuminate\Console\Command;

class ListSecurityEvents extends Command
{
    /**
     * The name and signature of the console command.
     *
     * @var string
     */
    protected $signature = 'security:events:list
                            {--type= : Filter by event type (authentication, authorization, api_access, security_violation, role_change, permission_change)}
                            {--severity= : Filter by severity (debug, info, warning, error, critical)}
                            {--user= : Filter by user ID}
                            {--ip= : Filter by IP address}
                            {--hours=24 : Show events from the last N hours}
                            {--limit=50 : Maximum number of events to display}';

    /**
     * The console command description.
     *
     * @var string
     */
    protected $description = 'List security events';

    /**
     * Execute the console command.
     */
    public function handle(): int
    {
        $query = SecurityEvent::query();

        // Apply filters
        if ( $type = $this->option( 'type' ) ) {
            $query->byType( $type );
        }

        if ( $severity = $this->option( 'severity' ) ) {
            $query->bySeverity( $severity );
        }

        if ( $userId = $this->option( 'user' ) ) {
            if ( (int) $userId < 1 ) {
                $this->error( 'User ID must be a positive integer.' );
                return self::FAILURE;
            }
            $query->byUser( (int) $userId );
        }

        if ( $ip = $this->option( 'ip' ) ) {
            $query->byIp( $ip );
        }

        $hours = (int) $this->option( 'hours' );
        if ( $hours < 1 ) {
            $this->error( 'Hours must be a positive integer.' );
            return self::FAILURE;
        }
        
        $query->recent( $hours );

        $events = $query->latest( 'created_at' )
            ->limit( max( 1, min( (int) $this->option( 'limit' ), 1000 ) ) )
            ->get();

        if ( $events->isEmpty() ) {
            $this->info( 'No security events found.' );

            return self::SUCCESS;
        }

        $rows = $events->map( function ( $event ) {
            return [
                $event->id,
                $event->event_type,
                $event->event_name,
                $this->formatSeverity( $event->severity ),
                $event->user_id ?? 'Guest',
                $event->ip_address,
                $event->created_at->diffForHumans(),
            ];
        } );

        $this->table(
            ['ID', 'Type', 'Event', 'Severity', 'User', 'IP', 'Time'],
            $rows,
        );

        $this->newLine();
        $this->info( "Total: {$events->count()} event(s) in the last {$hours} hour(s)" );

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
