<?php

declare( strict_types=1 );

namespace ArtisanPackUI\SecurityAnalytics\Analytics\ThreatIntelligence\Providers;

use ArtisanPackUI\SecurityAnalytics\Analytics\ThreatIntelligence\Contracts\ThreatIntelProviderInterface;
use Exception;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Http;

abstract class AbstractProvider implements ThreatIntelProviderInterface
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
        $this->config = array_merge( $this->getDefaultConfig(), $config );
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
    public function checkDomain( string $domain ): ?array
    {
        return null; // Override in providers that support this
    }

    /**
     * {@inheritdoc}
     */
    public function checkUrl( string $url ): ?array
    {
        return null; // Override in providers that support this
    }

    /**
     * {@inheritdoc}
     */
    public function checkHash( string $hash ): ?array
    {
        return null; // Override in providers that support this
    }

    /**
     * Get the default configuration.
     *
     * @return array<string, mixed>
     */
    abstract protected function getDefaultConfig(): array;

    /**
     * Make an HTTP request with caching.
     *
     * @param  array<string, mixed>  $options
     *
     * @return array<string, mixed>|null
     */
    protected function makeRequest( string $url, string $method = 'GET', array $options = [] ): ?array
    {
        $cacheKey = $this->getCacheKey( $url, $options );
        $cacheTtl = $this->config['cache_ttl'] ?? 60;

        // Normalize TTL: if > 60, assume seconds; otherwise assume minutes
        $cacheExpiry = $cacheTtl > 60
            ? now()->addSeconds( $cacheTtl )
            : now()->addMinutes( $cacheTtl );

        return Cache::remember( $cacheKey, $cacheExpiry, function () use ( $url, $method, $options ) {
            try {
                $response = match ( $method ) {
                    'POST'  => $this->makePostRequest( $url, $options ),
                    default => Http::withHeaders( $this->getHeaders() )->get( $url, $options['query'] ?? [] ),
                };

                if ( $response->successful() ) {
                    return $response->json();
                }

                return null;
            } catch ( Exception $e ) {
                report( $e );

                return null;
            }
        } );
    }

    /**
     * Make a POST request with proper JSON handling.
     *
     * @param  array<string, mixed>  $options
     *
     * @return \Illuminate\Http\Client\Response
     */
    protected function makePostRequest( string $url, array $options ): \Illuminate\Http\Client\Response
    {
        $http = Http::withHeaders( $this->getHeaders() );

        // Prefer 'json' option for JSON payloads, fallback to 'body'
        if ( isset( $options['json'] ) ) {
            return $http->post( $url, $options['json'] );
        }

        return $http->post( $url, $options['body'] ?? [] );
    }

    /**
     * Get HTTP headers for requests.
     *
     * @return array<string, string>
     */
    protected function getHeaders(): array
    {
        return [
            'Accept' => 'application/json',
        ];
    }

    /**
     * Generate a cache key for a request.
     *
     * @param  array<string, mixed>  $options
     */
    protected function getCacheKey( string $url, array $options = [] ): string
    {
        return 'threat_intel:' . $this->getName() . ':' . md5( $url . serialize( $options ) );
    }

    /**
     * Normalize a threat score to 0-100 range.
     */
    protected function normalizeScore( float $score, float $maxScore = 100 ): int
    {
        return (int) min( 100, max( 0, ( $score / $maxScore ) * 100 ) );
    }

    /**
     * Determine threat level from score.
     */
    protected function determineThreatLevel( int $score ): string
    {
        return match ( true ) {
            $score >= 80 => 'critical',
            $score >= 60 => 'high',
            $score >= 40 => 'medium',
            $score >= 20 => 'low',
            default      => 'none',
        };
    }
}
