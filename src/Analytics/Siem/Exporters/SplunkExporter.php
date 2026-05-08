<?php

declare( strict_types=1 );

namespace ArtisanPackUI\SecurityAnalytics\Analytics\Siem\Exporters;

use ArtisanPackUI\SecurityAnalytics\Analytics\Siem\Contracts\SiemExporterInterface;
use Exception;
use Illuminate\Support\Facades\Http;
use JsonException;

class SplunkExporter implements SiemExporterInterface
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
            'enabled'    => false,
            'hec_url'    => null,
            'hec_token'  => null,
            'index'      => 'security',
            'source'     => 'artisanpack-security',
            'sourcetype' => '_json',
            'verify_ssl' => true,
        ], $config );
    }

    /**
     * {@inheritdoc}
     */
    public function getName(): string
    {
        return 'splunk';
    }

    /**
     * {@inheritdoc}
     */
    public function isEnabled(): bool
    {
        return ( $this->config['enabled'] ?? false )
            && ! empty( $this->config['hec_url'] )
            && ! empty( $this->config['hec_token'] );
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
            return ['success' => false, 'error' => 'Splunk exporter is not configured'];
        }

        $payload = $this->buildPayload( $event );

        try {
            $json = json_encode( $payload, JSON_THROW_ON_ERROR );
        } catch ( JsonException $e ) {
            return [
                'success' => false,
                'error'   => 'JSON encoding failed',
                'details' => $e->getMessage(),
            ];
        }

        return $this->sendToHec( $json );
    }

    /**
     * {@inheritdoc}
     */
    public function exportBatch( array $events ): array
    {
        if ( ! $this->isEnabled() ) {
            return ['success' => false, 'error' => 'Splunk exporter is not configured'];
        }

        if ( empty( $events ) ) {
            return ['success' => true, 'exported' => 0];
        }

        // Build batch payload (newline-delimited JSON)
        $lines = [];
        foreach ( $events as $event ) {
            $json = json_encode( $this->buildPayload( $event ) );
            if ( false === $json ) {
                continue; // Skip events that can't be encoded
            }
            $lines[] = $json;
        }

        if ( empty( $lines ) ) {
            return [
                'success'  => false,
                'error'    => 'All events failed JSON encoding',
                'exported' => 0,
            ];
        }

        $result             = $this->sendToHec( implode( "\n", $lines ) );
        $result['exported'] = $result['success'] ? count( $lines ) : 0;

        return $result;
    }

    /**
     * Build Splunk HEC payload.
     *
     * @param  array<string, mixed>  $event
     *
     * @return array<string, mixed>
     */
    protected function buildPayload( array $event ): array
    {
        $timestamp = isset( $event['timestamp'] )
            ? strtotime( $event['timestamp'] )
            : time();

        return [
            'time'       => $timestamp,
            'host'       => gethostname() ?: 'localhost',
            'source'     => $this->config['source'],
            'sourcetype' => $this->config['sourcetype'],
            'index'      => $this->config['index'],
            'event'      => $event,
        ];
    }

    /**
     * Send data to Splunk HEC.
     *
     * @return array<string, mixed>
     */
    protected function sendToHec( string $payload ): array
    {
        try {
            $response = Http::withHeaders( [
                'Authorization' => 'Splunk ' . $this->config['hec_token'],
                'Content-Type'  => 'application/json',
            ] )
                ->withOptions( ['verify' => $this->config['verify_ssl']] )
                ->post( $this->config['hec_url'], $payload );

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
}
