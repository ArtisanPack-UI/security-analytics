<?php

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
            foreach ( $filteredEvents as $event ) {
                $this->addToBuffer( $event );
            }

            return ['buffered' => count( $filteredEvents )];
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

        $events       = $this->buffer;
        $this->buffer = [];

        return $this->sendBatchToExporters( $events );
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
        $results = [];

        foreach ( $this->getEnabledExporters() as $name => $exporter ) {
            $results[ $name ] = $exporter->export( $event );
        }

        return [
            'exported' => 1,
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
            return ['exported' => 0];
        }

        $results = [];

        foreach ( $this->getEnabledExporters() as $name => $exporter) {
            $results[ $name ] = $exporter->exportBatch( $events);
        }

        return [
            'exported' => count( $events),
            'results'  => $results,
        ];
    }
}
