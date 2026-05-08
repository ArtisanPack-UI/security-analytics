<?php

declare( strict_types=1 );

namespace ArtisanPackUI\SecurityAnalytics\Analytics\Siem\Exporters;

use ArtisanPackUI\SecurityAnalytics\Analytics\Siem\Contracts\SiemExporterInterface;
use Exception;
use Illuminate\Support\Facades\Http;

class ElasticsearchExporter implements SiemExporterInterface
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
            'enabled'      => false,
            'hosts'        => ['localhost:9200'],
            'index_prefix' => 'security-',
            'username'     => null,
            'password'     => null,
            'verify_ssl'   => true,
        ], $config );
    }

    /**
     * {@inheritdoc}
     */
    public function getName(): string
    {
        return 'elasticsearch';
    }

    /**
     * {@inheritdoc}
     */
    public function isEnabled(): bool
    {
        return ( $this->config['enabled'] ?? false ) && ! empty( $this->config['hosts'] );
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
            return ['success' => false, 'error' => 'Elasticsearch exporter is not configured'];
        }

        $index = $this->getIndexName( $event );
        $host  = $this->getHost();
        $url   = "{$host}/{$index}/_doc";

        return $this->sendRequest( 'POST', $url, $event );
    }

    /**
     * {@inheritdoc}
     */
    public function exportBatch( array $events ): array
    {
        if ( ! $this->isEnabled() ) {
            return ['success' => false, 'error' => 'Elasticsearch exporter is not configured'];
        }

        if ( empty( $events ) ) {
            return ['success' => true, 'exported' => 0];
        }

        $host = $this->getHost();
        $url  = "{$host}/_bulk";

        // Build bulk request body
        $lines = [];
        foreach ( $events as $event ) {
            $index = $this->getIndexName( $event );

            // Action line
            $lines[] = json_encode( [
                'index' => [
                    '_index' => $index,
                ],
            ] );

            // Document line
            $lines[] = json_encode( $event );
        }

        $body = implode( "\n", $lines ) . "\n";

        $result             = $this->sendRequest( 'POST', $url, $body, true );
        $result['exported'] = $result['success'] ? count( $events ) : 0;

        return $result;
    }

    /**
     * Get the index name for an event.
     *
     * @param  array<string, mixed>  $event
     */
    protected function getIndexName( array $event ): string
    {
        $prefix = $this->config['index_prefix'];
        $date   = date( 'Y.m.d' );

        return "{$prefix}{$date}";
    }

    /**
     * Get the Elasticsearch host.
     */
    protected function getHost(): string
    {
        $hosts = $this->config['hosts'];
        $host  = is_array( $hosts ) ? $hosts[ array_rand( $hosts ) ] : $hosts;

        if ( ! str_starts_with( $host, 'http' ) ) {
            $host = 'http://' . $host;
        }

        return rtrim( $host, '/' );
    }

    /**
     * Send request to Elasticsearch.
     *
     * @param  array<string, mixed>|string  $body
     *
     * @return array<string, mixed>
     */
    protected function sendRequest( string $method, string $url, $body, bool $isRawBody = false ): array
    {
        try {
            $http = Http::withHeaders( [
                'Content-Type' => 'application/json',
            ] )->withOptions( ['verify' => $this->config['verify_ssl']] );

            // Add basic auth if configured
            if ( ! empty( $this->config['username'] ) ) {
                $http = $http->withBasicAuth(
                    $this->config['username'],
                    $this->config['password'] ?? '',
                );
            }

            if ( $isRawBody ) {
                $response = $http->withBody( $body, 'application/x-ndjson' )->post( $url );
            } else {
                $response = $http->post( $url, $body );
            }

            if ( $response->successful() ) {
                $data = $response->json();

                // Check for errors in bulk response
                if ( isset( $data['errors'] ) && true === $data['errors'] ) {
                    return [
                        'success' => false,
                        'error'   => 'Some documents failed to index',
                        'details' => $data,
                    ];
                }

                return [
                    'success' => true,
                    'status'  => $response->status(),
                    'id'      => $data['_id'] ?? null,
                ];
            }

            return [
                'success' => false,
                'status'  => $response->status(),
                'error'   => $response->body(),
            ];
        } catch ( Exception $e) {
            return [
                'success' => false,
                'error'   => $e->getMessage(),
            ];
        }
    }
}
