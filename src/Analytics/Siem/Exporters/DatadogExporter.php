<?php

/**
 * DatadogExporter SIEM exporter.
 *
 * @package    ArtisanPack_UI
 * @subpackage SecurityAnalytics
 *
 * @author     Jacob Martella <support@artisanpackui.dev>
 *
 * @since      1.0.0
 */

declare( strict_types=1 );

namespace ArtisanPackUI\SecurityAnalytics\Analytics\Siem\Exporters;

use ArtisanPackUI\SecurityAnalytics\Analytics\Siem\Contracts\SiemExporterInterface;
use Exception;
use Illuminate\Support\Facades\Http;

class DatadogExporter implements SiemExporterInterface
{
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
            'enabled' => false,
            'api_key' => null,
            'site'    => 'datadoghq.com', // datadoghq.com, datadoghq.eu, etc.
            'service' => 'artisanpack-security',
            'source'  => 'laravel',
            'tags'    => [],
        ], $config );
    }

    /**
     * {@inheritdoc}
     */
    public function getName(): string
    {
        return 'datadog';
    }

    /**
     * {@inheritdoc}
     */
    public function isEnabled(): bool
    {
        return ( $this->config['enabled'] ?? false ) && ! empty( $this->config['api_key'] );
    }

    /**
     * {@inheritdoc}
     */
    public function getConfig(): array
    {
        return $this->config;
    }

    /**
     * {@inheritdoc}
     */
    public function export( array $event ): array
    {
        if ( ! $this->isEnabled() ) {
            return ['success' => false, 'error' => 'Datadog exporter is not configured'];
        }

        $payload = [$this->buildLogEntry( $event )];

        return $this->sendToDatadog( $payload );
    }

    /**
     * {@inheritdoc}
     */
    public function exportBatch( array $events ): array
    {
        if ( ! $this->isEnabled() ) {
            return ['success' => false, 'error' => 'Datadog exporter is not configured'];
        }

        if ( empty( $events ) ) {
            return ['success' => true, 'exported' => 0];
        }

        $payload = array_map( [$this, 'buildLogEntry'], $events );

        $result             = $this->sendToDatadog( $payload );
        $result['exported'] = $result['success'] ? count( $events ) : 0;

        return $result;
    }

    /**
     * Build Datadog log entry.
     *
     * @param  array<string, mixed>  $event
     *
     * @return array<string, mixed>
     */
    protected function buildLogEntry( array $event ): array
    {
        $severity = $event['severity'] ?? 'info';
        $category = $event['category'] ?? 'security';
        $status   = $this->mapSeverityToStatus( $severity );

        $tags = array_merge(
            $this->config['tags'] ?? [],
            [
                "env:{$this->getEnvironment()}",
                "severity:{$severity}",
                "category:{$category}",
            ],
        );

        return [
            'ddsource'  => $this->config['source'],
            'ddtags'    => implode( ',', $tags ),
            'hostname'  => gethostname() ?: 'localhost',
            'service'   => $this->config['service'],
            'status'    => $status,
            'message'   => json_encode( $event ),
            'timestamp' => $this->getTimestamp( $event ),
        ];
    }

    /**
     * Send logs to Datadog.
     *
     * @param  array<int, array<string, mixed>>  $payload
     *
     * @return array<string, mixed>
     */
    protected function sendToDatadog( array $payload ): array
    {
        $url = "https://http-intake.logs.{$this->config['site']}/api/v2/logs";

        try {
            $response = Http::withHeaders( [
                'DD-API-KEY'   => $this->config['api_key'],
                'Content-Type' => 'application/json',
            ] )->post( $url, $payload );

            if ( $response->successful() ) {
                return [
                    'success' => true,
                    'status'  => $response->status(),
                ];
            }

            return [
                'success' => false,
                'status'  => $response->status(),
                'error'   => $response->body(),
            ];
        } catch ( Exception $e ) {
            return [
                'success' => false,
                'error'   => $e->getMessage(),
            ];
        }
    }

    /**
     * Map severity to Datadog status.
     */
    protected function mapSeverityToStatus( string $severity ): string
    {
        return match ( $severity ) {
            'critical' => 'critical',
            'high'     => 'error',
            'medium'   => 'warn',
            'low'      => 'info',
            'info'     => 'info',
            default    => 'info',
        };
    }

    /**
     * Get timestamp in milliseconds.
     *
     * @param  array<string, mixed>  $event
     */
    protected function getTimestamp( array $event ): int
    {
        if ( isset( $event['timestamp'] ) ) {
            return (int) ( strtotime( $event['timestamp'] ) * 1000 );
        }

        return (int) ( microtime( true ) * 1000 );
    }

    /**
     * Get current environment.
     */
    protected function getEnvironment(): string
    {
        return config( 'app.env', 'production');
    }
}
