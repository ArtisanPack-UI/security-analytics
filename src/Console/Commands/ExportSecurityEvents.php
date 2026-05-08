<?php

declare( strict_types=1 );

namespace ArtisanPackUI\SecurityAnalytics\Console\Commands;

use ArtisanPackUI\SecurityAnalytics\Models\SecurityEvent;
use Illuminate\Console\Command;
use Illuminate\Support\Facades\File;

class ExportSecurityEvents extends Command
{
    /**
     * The name and signature of the console command.
     *
     * @var string
     */
    protected $signature = 'security:events:export
                            {path : The file path to export to}
                            {--format=csv : Export format (csv, json)}
                            {--type= : Filter by event type}
                            {--severity= : Filter by severity}
                            {--days=30 : Export events from the last N days}';

    /**
     * The console command description.
     *
     * @var string
     */
    protected $description = 'Export security events to a file';

    /**
     * Execute the console command.
     */
    public function handle(): int
    {
        $path   = $this->argument( 'path' );
        $format = $this->option( 'format' );
        $days   = (int) $this->option( 'days' );

        $query = SecurityEvent::query()
            ->where( 'created_at', '>=', now()->subDays( $days ) )
            ->orderBy( 'created_at', 'desc' );

        if ( $type = $this->option( 'type' ) ) {
            $query->byType( $type );
        }

        if ( $severity = $this->option( 'severity' ) ) {
            $query->bySeverity( $severity );
        }

        $events = $query->get();

        if ( $events->isEmpty() ) {
            $this->warn( 'No events found matching the criteria.' );

            return self::SUCCESS;
        }

        $this->info( "Exporting {$events->count()} event(s)..." );

        $content = match ( $format ) {
            'json'  => $this->exportJson( $events ),
            default => $this->exportCsv( $events ),
        };

        File::put( $path, $content );

        $this->info( "Events exported to: {$path}" );

        return self::SUCCESS;
    }

    /**
     * Export events as JSON.
     */
    protected function exportJson( $events ): string
    {
        return json_encode( $events->toArray(), JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE );
    }

    /**
     * Export events as CSV.
     */
    protected function exportCsv( $events ): string
    {
        $headers = ['ID', 'Type', 'Name', 'Severity', 'User ID', 'IP Address', 'User Agent', 'URL', 'Method', 'Details', 'Created At'];

        $rows = $events->map( function ( $event ) {
            return [
                $event->id,
                $event->event_type,
                $event->event_name,
                $event->severity,
                $event->user_id ?? '',
                $event->ip_address,
                $event->user_agent ?? '',
                $event->url ?? '',
                $event->method ?? '',
                json_encode( $event->details ?? [] ),
                $event->created_at->toIso8601String(),
            ];
        } );

        $output = implode( ',', $headers ) . "\n";

        foreach ( $rows as $row ) {
            $output .= implode( ',', array_map( [$this, 'escapeCsv'], $row ) ) . "\n";
        }

        return $output;
    }

    /**
     * Escape a value for CSV.
     */
    protected function escapeCsv( $value ): string
    {
        $value = (string) $value;

        if ( str_contains( $value, ',' ) || str_contains( $value, '"' ) || str_contains( $value, "\n" ) ) {
            return '"' . str_replace( '"', '""', $value) . '"';
        }

        return $value;
    }
}
