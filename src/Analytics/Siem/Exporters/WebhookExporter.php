<?php

declare( strict_types=1 );

namespace ArtisanPackUI\SecurityAnalytics\Analytics\Siem\Exporters;

use ArtisanPackUI\SecurityAnalytics\Analytics\Siem\Contracts\SiemExporterInterface;
use Exception;
use Illuminate\Support\Facades\Http;

class WebhookExporter implements SiemExporterInterface
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
            'enabled'        => false,
            'url'            => null,
            'secret'         => null,
            'method'         => 'POST',
            'headers'        => [],
            'timeout'        => 30,
            'retry'          => 3,
            'format'         => 'json', // json, cef, leef
            'batch_endpoint' => null, // Optional separate endpoint for batch
        ], $config );
    }

    /**
     * {@inheritdoc}
     */
    public function getName(): string
    {
        return 'webhook';
    }

    /**
     * {@inheritdoc}
     */
    public function isEnabled(): bool
    {
        return ( $this->config['enabled'] ?? false ) && ! empty( $this->config['url'] );
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
            return ['success' => false, 'error' => 'Webhook exporter is not configured'];
        }

        $payload = $this->formatEvent( $event );

        return $this->sendWebhook( $this->config['url'], $payload );
    }

    /**
     * {@inheritdoc}
     */
    public function exportBatch( array $events ): array
    {
        if ( ! $this->isEnabled() ) {
            return ['success' => false, 'error' => 'Webhook exporter is not configured'];
        }

        if ( empty( $events ) ) {
            return ['success' => true, 'exported' => 0];
        }

        $url     = $this->config['batch_endpoint'] ?? $this->config['url'];
        $payload = [
            'batch'     => true,
            'count'     => count( $events ),
            'events'    => array_map( [$this, 'formatEvent'], $events ),
            'timestamp' => now()->toIso8601String(),
        ];

        $result             = $this->sendWebhook( $url, $payload );
        $result['exported'] = $result['success'] ? count( $events ) : 0;

        return $result;
    }

    /**
     * Format event based on configured format.
     *
     * @param  array<string, mixed>  $event
     *
     * @return array<string, mixed>|string
     */
    protected function formatEvent( array $event )
    {
        return match ( $this->config['format'] ) {
            'cef'   => $this->formatAsCef( $event ),
            'leef'  => $this->formatAsLeef( $event ),
            default => $this->formatAsJson( $event ),
        };
    }

    /**
     * Format event as JSON.
     *
     * @param  array<string, mixed>  $event
     *
     * @return array<string, mixed>
     */
    protected function formatAsJson( array $event ): array
    {
        return array_merge( $event, [
            'exported_at' => now()->toIso8601String(),
            'source'      => [
                'application' => config( 'app.name', 'Laravel' ),
                'environment' => config( 'app.env' ),
                'host'        => gethostname(),
            ],
        ] );
    }

    /**
     * Format event as CEF (Common Event Format).
     *
     * @param  array<string, mixed>  $event
     */
    protected function formatAsCef( array $event ): string
    {
        $severity  = $this->mapSeverityToCef( $event['severity'] ?? 'info' );
        $eventType = $event['event_type'] ?? 'SecurityEvent';
        $category  = $event['category'] ?? 'security';

        $extension   = [];
        $extension[] = 'src=' . $this->escapeValue( $event['source_ip'] ?? '' );
        $extension[] = 'dst=' . $this->escapeValue( $event['destination_ip'] ?? '' );
        $extension[] = 'suser=' . $this->escapeValue( $event['user_id'] ?? '' );
        $extension[] = 'msg=' . $this->escapeValue( $event['message'] ?? '' );
        $extension[] = 'cat=' . $this->escapeValue( $category );
        $extension[] = 'rt=' . strtotime( $event['timestamp'] ?? 'now' ) * 1000;

        return sprintf(
            'CEF:0|ArtisanPack|Security|1.0|%s|%s|%d|%s',
            $eventType,
            $event['message'] ?? 'Security Event',
            $severity,
            implode( ' ', array_filter( $extension ) ),
        );
    }

    /**
     * Format event as LEEF (Log Event Extended Format).
     *
     * @param  array<string, mixed>  $event
     */
    protected function formatAsLeef( array $event ): string
    {
        $eventId  = $event['event_type'] ?? 'SecurityEvent';
        $category = $event['category'] ?? 'security';

        $attributes   = [];
        $attributes[] = 'cat=' . $category;
        $attributes[] = 'sev=' . $this->mapSeverityToLeef( $event['severity'] ?? 'info' );
        $attributes[] = 'src=' . $this->escapeValue( $event['source_ip'] ?? '' );
        $attributes[] = 'usrName=' . $this->escapeValue( $event['user_id'] ?? '' );
        $attributes[] = 'msg=' . $this->escapeValue( $event['message'] ?? '' );
        $attributes[] = 'devTime=' . date( 'M d Y H:i:s', strtotime( $event['timestamp'] ?? 'now' ) );

        return sprintf(
            'LEEF:1.0|ArtisanPack|Security|1.0|%s|%s',
            $eventId,
            implode( "\t", array_filter( $attributes ) ),
        );
    }

    /**
     * Send webhook request.
     *
     * @param  mixed  $payload
     *
     * @return array<string, mixed>
     */
    protected function sendWebhook( string $url, $payload ): array
    {
        try {
            $headers = array_merge( [
                'Content-Type' => 'application/json',
                'Accept'       => 'application/json',
                'User-Agent'   => 'ArtisanPack-Security-SIEM/1.0',
            ], $this->config['headers'] ?? [] );

            // Add signature if secret is configured
            if ( ! empty( $this->config['secret'] ) ) {
                $payloadString              = is_string( $payload ) ? $payload : json_encode( $payload );
                $signature                  = hash_hmac( 'sha256', $payloadString, $this->config['secret'] );
                $headers['X-Signature']     = $signature;
                $headers['X-Signature-256'] = 'sha256=' . $signature;
            }

            $http = Http::withHeaders( $headers )
                ->timeout( $this->config['timeout'] )
                ->retry( $this->config['retry'], 1000 );

            // Handle string payloads (CEF/LEEF)
            if ( is_string( $payload ) ) {
                $headers['Content-Type'] = 'text/plain';
                $response                = $http->withBody( $payload, 'text/plain' )->post( $url );
            } else {
                $response = match ( strtoupper( $this->config['method'] ) ) {
                    'PUT'   => $http->put( $url, $payload ),
                    default => $http->post( $url, $payload ),
                };
            }

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
     * Map severity to CEF numeric value.
     */
    protected function mapSeverityToCef( string $severity ): int
    {
        return match ( $severity ) {
            'critical' => 10,
            'high'     => 8,
            'medium'   => 5,
            'low'      => 3,
            'info'     => 1,
            default    => 0,
        };
    }

    /**
     * Map severity to LEEF value.
     */
    protected function mapSeverityToLeef( string $severity ): int
    {
        return match ( $severity ) {
            'critical' => 9,
            'high'     => 7,
            'medium'   => 5,
            'low'      => 3,
            'info'     => 1,
            default    => 0,
        };
    }

    /**
     * Escape value for CEF/LEEF format.
     */
    protected function escapeValue( mixed $value): string
    {
        if ( ! is_string( $value)) {
            $value = (string) $value;
        }

        return str_replace( ['\\', '=', '|'], ['\\\\', '\\=', '\\|'], $value);
    }
}
