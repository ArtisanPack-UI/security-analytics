<?php

/**
 * SiemExportService SIEM service.
 *
 * @package    ArtisanPack_UI
 * @subpackage SecurityAnalytics
 *
 * @author     Jacob Martella <support@artisanpackui.dev>
 *
 * @since      1.0.0
 */

declare( strict_types=1 );

namespace ArtisanPackUI\SecurityAnalytics\Analytics\Siem;

use ArtisanPackUI\SecurityAnalytics\Analytics\Siem\Contracts\SiemExporterInterface;
use ArtisanPackUI\SecurityAnalytics\Analytics\Siem\Exporters\ElasticsearchExporter;
use ArtisanPackUI\SecurityAnalytics\Analytics\Siem\Exporters\SplunkExporter;
use ArtisanPackUI\SecurityAnalytics\Analytics\Siem\Exporters\SyslogExporter;
use ArtisanPackUI\SecurityAnalytics\Analytics\Siem\Formatters\EventFormatter;
use ArtisanPackUI\SecurityAnalytics\Models\Anomaly;
use ArtisanPackUI\SecurityAnalytics\Models\SecurityIncident;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Log;
use Throwable;

class SiemExportService
{
    /**
     * @var array<string, SiemExporterInterface>
     */
    protected array $exporters = [];

    /**
     * @var array<string, mixed>
     */
    protected array $config;

    /**
     * @var array<int, array<string, mixed>>
     */
    protected array $buffer = [];

    /**
     * @param  array<string, mixed>  $config
     */
    public function __construct( array $config = [] )
    {
        $this->config = array_merge( $this->getDefaultConfig(), $config );
        $this->registerDefaultExporters();
    }

    /**
     * Register an exporter.
     */
    public function registerExporter( SiemExporterInterface $exporter ): self
    {
        $this->exporters[ $exporter->getName() ] = $exporter;

        return $this;
    }

    /**
     * Get an exporter by name.
     */
    public function getExporter( string $name ): ?SiemExporterInterface
    {
        return $this->exporters[ $name ] ?? null;
    }

    /**
     * Get all enabled exporters.
     *
     * @return array<string, SiemExporterInterface>
     */
    public function getEnabledExporters(): array
    {
        return array_filter( $this->exporters, fn ( $e ) => $e->isEnabled() );
    }

    /**
     * Check if SIEM export is enabled.
     */
    public function isEnabled(): bool
    {
        return $this->config['enabled'] && ! empty( $this->getEnabledExporters() );
    }

    /**
     * Export an anomaly to SIEM.
     *
     * @return array<string, mixed>
     */
    public function exportAnomaly( Anomaly $anomaly ): array
    {
        $event = EventFormatter::fromAnomaly( $anomaly );

        return $this->exportEvent( $event );
    }

    /**
     * Export an incident to SIEM.
     *
     * @return array<string, mixed>
     */
    public function exportIncident( SecurityIncident $incident ): array
    {
        $event = EventFormatter::fromIncident( $incident );

        return $this->exportEvent( $event );
    }

    /**
     * Export a generic event to SIEM.
     *
     * @param  array<string, mixed>  $event
     *
     * @return array<string, mixed>
     */
    public function exportEvent( array $event ): array
    {
        if ( ! $this->isEnabled() ) {
            return ['skipped' => true, 'reason' => 'SIEM export is disabled'];
        }

        // Check if this event type should be exported
        $eventType = $event['event_type'] ?? 'unknown';
        $category  = $event['category'] ?? 'general';

        if ( ! $this->shouldExportEvent( $category, $eventType ) ) {
            return ['skipped' => true, 'reason' => "Event category '{$category}' is not configured for export"];
        }

        if ( $this->config['batch_enabled'] ) {
            return $this->addToBuffer( $event );
        }

        return $this->sendToExporters( $event );
    }

    /**
     * Export multiple events.
     *
     * @param  array<int, array<string, mixed>>  $events
     *
     * @return array<string, mixed>
     */
    public function exportEvents( array $events ): array
    {
        if ( ! $this->isEnabled() ) {
            return ['skipped' => true, 'reason' => 'SIEM export is disabled'];
        }

        // Filter events based on configured export types
        $filteredEvents = array_filter( $events, function ( $event ) {
            $category  = $event['category'] ?? 'general';
            $eventType = $event['event_type'] ?? null;

            return $this->shouldExportEvent( $category, $eventType );
        } );

        if ( $this->config['batch_enabled'] ) {
            $flushResults = [];
            foreach ( $filteredEvents as $event ) {
                $result = $this->addToBuffer( $event );
                if ( is_array( $result ) && isset( $result['results'] ) ) {
                    // The buffer overflowed and addToBuffer triggered a flush
                    // — surface its result so callers can see export failures
                    // instead of silently treating buffered+flushed as success.
                    $flushResults[] = $result;
                }
            }

            return [
                'buffered'      => count( $this->buffer ),
                'flush_results' => $flushResults,
            ];
        }

        return $this->sendBatchToExporters( $filteredEvents );
    }

    /**
     * Flush the event buffer.
     *
     * @return array<string, mixed>
     */
    public function flush(): array
    {
        if ( empty( $this->buffer ) ) {
            return ['flushed' => 0];
        }

        // Keep the buffer intact until we know the export succeeded. Clearing
        // up-front would permanently lose queued events on a transient
        // exporter failure.
        $events = $this->buffer;
        $result = $this->sendBatchToExporters( $events );

        if ( $result['success'] ?? false ) {
            $this->buffer = [];
        }

        return $result;
    }

    /**
     * Export recent anomalies to SIEM.
     *
     * @return array<string, mixed>
     */
    public function exportRecentAnomalies( int $hours = 1 ): array
    {
        $anomalies = Anomaly::where( 'detected_at', '>=', now()->subHours( $hours ) )->get();

        $events = $anomalies->map( fn ( $a ) => EventFormatter::fromAnomaly( $a ) )->toArray();

        return $this->exportEvents( $events );
    }

    /**
     * Export recent incidents to SIEM.
     *
     * @return array<string, mixed>
     */
    public function exportRecentIncidents( int $hours = 1 ): array
    {
        $incidents = SecurityIncident::where( 'updated_at', '>=', now()->subHours( $hours ) )->get();

        $events = $incidents->map( fn ( $i ) => EventFormatter::fromIncident( $i ) )->toArray();

        return $this->exportEvents( $events );
    }

    /**
     * Get export statistics.
     *
     * @return array<string, mixed>
     */
    public function getStatistics(): array
    {
        $stats = [
            'enabled'           => $this->isEnabled(),
            'enabled_exporters' => array_keys( $this->getEnabledExporters() ),
            'buffer_size'       => count( $this->buffer ),
            'config'            => [
                'batch_enabled' => $this->config['batch_enabled'],
                'batch_size'    => $this->config['batch_size'],
                'export_events' => $this->config['export_events'],
            ],
        ];

        // Get per-exporter stats from cache
        foreach ( $this->getEnabledExporters() as $name => $exporter ) {
            $stats['exporters'][ $name ] = [
                'total_exported' => (int) Cache::get( "siem_stats:{$name}:total", 0 ),
                'last_export'    => Cache::get( "siem_stats:{$name}:last_export" ),
                'errors'         => (int) Cache::get( "siem_stats:{$name}:errors", 0 ),
            ];
        }

        return $stats;
    }

    /**
     * Get buffer size.
     */
    public function getBufferSize(): int
    {
        return count( $this->buffer );
    }

    /**
     * Clear the buffer without exporting.
     */
    public function clearBuffer(): void
    {
        $this->buffer = [];
    }

    /**
     * Get default configuration.
     *
     * @return array<string, mixed>
     */
    protected function getDefaultConfig(): array
    {
        return [
            'enabled'                => false,
            'format'                 => 'cef',
            'batch_enabled'          => true,
            'batch_size'             => 100,
            'batch_interval_seconds' => 30,
            'export_events'          => [
                'authentication',
                'authorization',
                'threat',
                'anomaly',
                'incident',
            ],
            'providers' => [],
        ];
    }

    /**
     * Register default exporters.
     */
    protected function registerDefaultExporters(): void
    {
        $providerConfigs = $this->config['providers'] ?? [];

        if ( ! empty( $providerConfigs['splunk'] ) ) {
            $this->registerExporter( new SplunkExporter( $providerConfigs['splunk'] ) );
        }

        if ( ! empty( $providerConfigs['elasticsearch'] ) ) {
            $this->registerExporter( new ElasticsearchExporter( $providerConfigs['elasticsearch'] ) );
        }

        if ( ! empty( $providerConfigs['syslog'] ) ) {
            $this->registerExporter( new SyslogExporter( $providerConfigs['syslog'] ) );
        }
    }

    /**
     * Check if an event category should be exported.
     */
    protected function shouldExportEvent( string $category, ?string $eventType = null ): bool
    {
        $exportEvents = $this->config['export_events'] ?? [];

        if ( empty( $exportEvents ) ) {
            return true; // Export all if not specified
        }

        // Check if category is in allowed list
        if ( in_array( $category, $exportEvents, true ) ) {
            return true;
        }

        // Check if event type indicates a special category (incident, anomaly)
        if ( null !== $eventType ) {
            // Map event types to export category names
            $eventTypeMapping = [
                'security_incident' => 'incident',
                'security_anomaly'  => 'anomaly',
            ];

            $mappedType = $eventTypeMapping[ $eventType ] ?? null;
            if ( null !== $mappedType && in_array( $mappedType, $exportEvents, true ) ) {
                return true;
            }
        }

        return false;
    }

    /**
     * Add event to buffer for batch export.
     *
     * @param  array<string, mixed>  $event
     *
     * @return array<string, mixed>
     */
    protected function addToBuffer( array $event ): array
    {
        $this->buffer[] = $event;

        // Check if buffer should be flushed
        if ( count( $this->buffer ) >= $this->config['batch_size'] ) {
            return $this->flush();
        }

        return ['buffered' => true, 'buffer_size' => count( $this->buffer )];
    }

    /**
     * Send a single event to all enabled exporters.
     *
     * @param  array<string, mixed>  $event
     *
     * @return array<string, mixed>
     */
    protected function sendToExporters( array $event ): array
    {
        $results         = [];
        $successfulSinks = 0;

        foreach ( $this->getEnabledExporters() as $name => $exporter ) {
            // Wrap each sink in try/catch so one bad exporter (HTTP timeout,
            // serialization error, schema mismatch, etc.) doesn't abort the
            // remaining sinks for this event. Per-exporter failures show up
            // in $results so the caller still has full visibility.
            try {
                $result           = $exporter->export( $event );
                $results[ $name ] = $result;
                if ( $result['success'] ?? false ) {
                    $successfulSinks++;
                }
            } catch ( Throwable $e ) {
                Log::error( 'SiemExportService: exporter threw on export', [
                    'exporter' => $name,
                    'message'  => $e->getMessage(),
                ] );
                $results[ $name ] = [
                    'success' => false,
                    'error'   => $e->getMessage(),
                    'code'    => $e->getCode(),
                ];
            }
        }

        // Report the actual number of exporters that confirmed delivery
        // for this event rather than always saying 1 — callers and
        // downstream metrics need an accurate success signal.
        return [
            'success'  => $successfulSinks > 0,
            'exported' => $successfulSinks,
            'results'  => $results,
        ];
    }

    /**
     * Send batch of events to all enabled exporters.
     *
     * @param  array<int, array<string, mixed>>  $events
     *
     * @return array<string, mixed>
     */
    protected function sendBatchToExporters( array $events ): array
    {
        if ( empty( $events ) ) {
            return ['success' => true, 'exported' => 0];
        }

        $results = [];

        foreach ( $this->getEnabledExporters() as $name => $exporter ) {
            try {
                $results[ $name ] = $exporter->exportBatch( $events );
            } catch ( Throwable $e ) {
                Log::error( 'SiemExportService: exporter threw on batch export', [
                    'exporter' => $name,
                    'message'  => $e->getMessage(),
                ] );
                $results[ $name ] = [
                    'success'  => false,
                    'exported' => 0,
                    'error'    => $e->getMessage(),
                    'code'     => $e->getCode(),
                ];
            }
        }

        // Sum the per-exporter acknowledged counts so the reported
        // `exported` reflects what actually shipped. Falling back to a
        // full-batch count when an exporter reports success without an
        // explicit count, and to 0 when it failed.
        //
        // The overall `success` flag is still all-or-nothing — flush()
        // uses it to decide whether to clear the buffer, so partial
        // failures keep the buffer intact for retry. (Side effect:
        // healthy exporters can see duplicates on a retried batch;
        // per-exporter delivery cursors are the correct long-term fix
        // and tracked separately.)
        $allSuccessful  = true;
        $exportedTotal  = 0;
        $batchSize      = count( $events );
        foreach ( $results as $result ) {
            $resultSuccess = $result['success'] ?? false;
            if ( ! $resultSuccess ) {
                $allSuccessful = false;
            }
            $exportedTotal += (int) ( $result['exported'] ?? ( $resultSuccess ? $batchSize : 0 ) );
        }

        return [
            'success'  => $allSuccessful,
            'exported' => $exportedTotal,
            'results'  => $results,
        ];
    }
}
