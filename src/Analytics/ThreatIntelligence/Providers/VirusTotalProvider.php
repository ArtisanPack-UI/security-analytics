<?php

declare( strict_types=1 );

namespace ArtisanPackUI\SecurityAnalytics\Analytics\ThreatIntelligence\Providers;

class VirusTotalProvider extends AbstractProvider
{
    protected const BASE_URL = 'https://www.virustotal.com/api/v3';

    /**
     * {@inheritdoc}
     */
    public function getName(): string
    {
        return 'virustotal';
    }

    /**
     * {@inheritdoc}
     */
    public function getSupportedTypes(): array
    {
        return ['ip', 'domain', 'url', 'hash'];
    }

    /**
     * {@inheritdoc}
     */
    public function checkIp( string $ip ): ?array
    {
        if ( ! $this->isEnabled() ) {
            return null;
        }

        $response = $this->makeRequest( self::BASE_URL . "/ip_addresses/{$ip}" );

        return $this->parseResponse( $response, 'ip', $ip );
    }

    /**
     * {@inheritdoc}
     */
    public function checkDomain( string $domain ): ?array
    {
        if ( ! $this->isEnabled() ) {
            return null;
        }

        $response = $this->makeRequest( self::BASE_URL . "/domains/{$domain}" );

        return $this->parseResponse( $response, 'domain', $domain );
    }

    /**
     * {@inheritdoc}
     */
    public function checkUrl( string $url ): ?array
    {
        if ( ! $this->isEnabled() ) {
            return null;
        }

        // URL needs to be base64 encoded for VirusTotal
        $urlId = rtrim( strtr( base64_encode( $url ), '+/', '-_' ), '=' );

        $response = $this->makeRequest( self::BASE_URL . "/urls/{$urlId}" );

        return $this->parseResponse( $response, 'url', $url );
    }

    /**
     * {@inheritdoc}
     */
    public function checkHash( string $hash ): ?array
    {
        if ( ! $this->isEnabled() ) {
            return null;
        }

        $response = $this->makeRequest( self::BASE_URL . "/files/{$hash}" );

        return $this->parseResponse( $response, 'hash', $hash );
    }

    /**
     * {@inheritdoc}
     */
    protected function getDefaultConfig(): array
    {
        return [
            'enabled'        => false,
            'api_key'        => null,
            'cache_ttl'      => 60,
            'min_detections' => 3,
        ];
    }

    /**
     * {@inheritdoc}
     */
    protected function getHeaders(): array
    {
        return [
            'Accept'   => 'application/json',
            'x-apikey' => $this->config['api_key'],
        ];
    }

    /**
     * Parse VirusTotal response.
     *
     * @param  array<string, mixed>|null  $response
     *
     * @return array<string, mixed>|null
     */
    protected function parseResponse( ?array $response, string $type, string $indicator ): ?array
    {
        if ( ! $response || ! isset( $response['data']['attributes'] ) ) {
            return null;
        }

        $attributes = $response['data']['attributes'];
        $stats      = $attributes['last_analysis_stats'] ?? [];

        $malicious    = $stats['malicious'] ?? 0;
        $suspicious   = $stats['suspicious'] ?? 0;
        $totalEngines = array_sum( $stats );

        $score = $totalEngines > 0
            ? $this->normalizeScore( ( $malicious + $suspicious ) / $totalEngines * 100 )
            : 0;

        return [
            'provider'       => $this->getName(),
            'indicator'      => $indicator,
            'indicator_type' => $type,
            'is_malicious'   => $malicious >= $this->config['min_detections'],
            'confidence'     => $score,
            'threat_level'   => $this->determineThreatLevel( $score ),
            'detections'     => [
                'malicious'     => $malicious,
                'suspicious'    => $suspicious,
                'harmless'      => $stats['harmless'] ?? 0,
                'undetected'    => $stats['undetected'] ?? 0,
                'total_engines' => $totalEngines,
            ],
            'reputation'         => $attributes['reputation'] ?? 0,
            'categories'         => $this->extractCategories( $attributes ),
            'last_analysis_date' => isset( $attributes['last_analysis_date'] )
                ? date( 'c', $attributes['last_analysis_date'] )
                : null,
            'raw_data' => $attributes,
        ];
    }

    /**
     * Extract categories from attributes.
     *
     * @param  array<string, mixed>  $attributes
     *
     * @return array<int, string>
     */
    protected function extractCategories( array $attributes ): array
    {
        $categories = [];

        // From analysis results
        if ( isset( $attributes['last_analysis_results'] ) ) {
            foreach ( $attributes['last_analysis_results'] as $engine => $result ) {
                if ( 'malicious' === $result['category'] && ! empty( $result['result'] ) ) {
                    $categories[] = $result['result'];
                }
            }
        }

        // From categories field (domains/IPs)
        if ( isset( $attributes['categories'] ) ) {
            foreach ( $attributes['categories'] as $engine => $category ) {
                if ( ! in_array( $category, $categories, true)) {
                    $categories[] = $category;
                }
            }
        }

        return array_unique( $categories);
    }
}
