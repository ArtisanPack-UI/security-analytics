<?php

declare( strict_types=1 );

namespace ArtisanPackUI\SecurityAnalytics\Analytics\ThreatIntelligence\Providers;

class GoogleSafeBrowsingProvider extends AbstractProvider
{
    protected const BASE_URL = 'https://safebrowsing.googleapis.com/v4';

    /**
     * {@inheritdoc}
     */
    public function getName(): string
    {
        return 'google_safebrowsing';
    }

    /**
     * {@inheritdoc}
     */
    public function getSupportedTypes(): array
    {
        return ['url', 'domain'];
    }

    /**
     * {@inheritdoc}
     */
    public function checkUrl( string $url ): ?array
    {
        if ( ! $this->isEnabled() ) {
            return null;
        }

        $response = $this->lookupUrl( $url );

        if ( null === $response ) {
            return null;
        }

        // Empty matches means safe
        $matches     = $response['matches'] ?? [];
        $isMalicious = ! empty( $matches );

        return [
            'provider'       => $this->getName(),
            'indicator'      => $url,
            'indicator_type' => 'url',
            'is_malicious'   => $isMalicious,
            'confidence'     => $isMalicious ? 95 : 0, // Google Safe Browsing is highly reliable
            'threat_level'   => $isMalicious ? $this->determineThreatLevelFromMatches( $matches ) : 'none',
            'threat_type'    => $isMalicious ? $this->extractThreatType( $matches ) : null,
            'categories'     => $this->extractCategories( $matches ),
            'threats_found'  => count( $matches ),
            'cache_duration' => $response['negativeCacheDuration'] ?? null,
            'raw_data'       => $response,
        ];
    }

    /**
     * Check a domain.
     *
     * @return array<string, mixed>|null
     */
    public function checkDomain( string $domain ): ?array
    {
        // Convert domain to URL format for Safe Browsing
        $url = "https://{$domain}/";

        return $this->checkUrl( $url );
    }

    /**
     * Batch check multiple URLs.
     *
     * @param  array<int, string>  $urls
     *
     * @return array<string, array<string, mixed>>
     */
    public function batchCheckUrls( array $urls ): array
    {
        if ( ! $this->isEnabled() || empty( $urls ) ) {
            return [];
        }

        $endpoint = self::BASE_URL . '/threatMatches:find';

        $threatEntries = array_map( fn ( $url ) => ['url' => $url], $urls );

        $payload = [
            'client' => [
                'clientId'      => $this->config['client_id'],
                'clientVersion' => $this->config['client_version'],
            ],
            'threatInfo' => [
                'threatTypes'      => $this->config['threat_types'],
                'platformTypes'    => $this->config['platform_types'],
                'threatEntryTypes' => ['URL'],
                'threatEntries'    => $threatEntries,
            ],
        ];

        $response = $this->makeRequest( $endpoint, 'POST', [
            'query' => ['key' => $this->config['api_key']],
            'json'  => $payload,
        ] );

        if ( ! $response ) {
            return [];
        }

        // Map matches back to URLs
        $results = [];
        $matches = $response['matches'] ?? [];

        foreach ( $urls as $url ) {
            $urlMatches = array_filter( $matches, fn ( $m ) => ( $m['threat']['url'] ?? '' ) === $url );

            $results[ $url ] = [
                'provider'       => $this->getName(),
                'indicator'      => $url,
                'indicator_type' => 'url',
                'is_malicious'   => ! empty( $urlMatches ),
                'confidence'     => ! empty( $urlMatches ) ? 95 : 0,
                'threat_level'   => ! empty( $urlMatches ) ? $this->determineThreatLevelFromMatches( $urlMatches ) : 'none',
                'threats'        => $urlMatches,
            ];
        }

        return $results;
    }

    /**
     * {@inheritdoc}
     */
    protected function getDefaultConfig(): array
    {
        return [
            'enabled'        => false,
            'api_key'        => null,
            'client_id'      => 'artisanpack-security',
            'client_version' => '1.0.0',
            'threat_types'   => [
                'MALWARE',
                'SOCIAL_ENGINEERING',
                'UNWANTED_SOFTWARE',
                'POTENTIALLY_HARMFUL_APPLICATION',
            ],
            'platform_types' => ['ANY_PLATFORM'],
            'cache_ttl'      => 300, // 5 minutes - Safe Browsing has strict caching requirements
        ];
    }

    /**
     * Perform Safe Browsing lookup.
     *
     * @return array<string, mixed>|null
     */
    protected function lookupUrl( string $url ): ?array
    {
        $endpoint = self::BASE_URL . '/threatMatches:find';

        $payload = [
            'client' => [
                'clientId'      => $this->config['client_id'],
                'clientVersion' => $this->config['client_version'],
            ],
            'threatInfo' => [
                'threatTypes'      => $this->config['threat_types'],
                'platformTypes'    => $this->config['platform_types'],
                'threatEntryTypes' => ['URL'],
                'threatEntries'    => [
                    ['url' => $url],
                ],
            ],
        ];

        return $this->makeRequest( $endpoint, 'POST', [
            'query' => ['key' => $this->config['api_key']],
            'body'  => $payload,
        ] );
    }

    /**
     * {@inheritdoc}
     */
    protected function getHeaders(): array
    {
        return [
            'Content-Type' => 'application/json',
            'Accept'       => 'application/json',
        ];
    }

    /**
     * Determine threat level from matches.
     *
     * @param  array<int, array<string, mixed>>  $matches
     */
    protected function determineThreatLevelFromMatches( array $matches ): string
    {
        foreach ( $matches as $match ) {
            $threatType = $match['threatType'] ?? '';

            if ( 'MALWARE' === $threatType ) {
                return 'critical';
            }
            if ( 'SOCIAL_ENGINEERING' === $threatType ) {
                return 'high';
            }
        }

        return 'medium';
    }

    /**
     * Extract primary threat type from matches.
     *
     * @param  array<int, array<string, mixed>>  $matches
     */
    protected function extractThreatType( array $matches ): string
    {
        $threatTypeMap = [
            'MALWARE'                         => 'malware',
            'SOCIAL_ENGINEERING'              => 'phishing',
            'UNWANTED_SOFTWARE'               => 'unwanted_software',
            'POTENTIALLY_HARMFUL_APPLICATION' => 'potentially_harmful',
        ];

        foreach ( $matches as $match ) {
            $threatType = $match['threatType'] ?? '';
            if ( isset( $threatTypeMap[ $threatType ] ) ) {
                return $threatTypeMap[ $threatType ];
            }
        }

        return 'unknown';
    }

    /**
     * Extract categories from matches.
     *
     * @param  array<int, array<string, mixed>>  $matches
     *
     * @return array<int, string>
     */
    protected function extractCategories( array $matches ): array
    {
        $categories = [];

        $categoryMap = [
            'MALWARE'                         => 'Malware',
            'SOCIAL_ENGINEERING'              => 'Phishing/Social Engineering',
            'UNWANTED_SOFTWARE'               => 'Unwanted Software',
            'POTENTIALLY_HARMFUL_APPLICATION' => 'Potentially Harmful App',
        ];

        foreach ( $matches as $match ) {
            $threatType = $match['threatType'] ?? '';
            if ( isset( $categoryMap[ $threatType ] ) && ! in_array( $categoryMap[ $threatType ], $categories, true ) ) {
                $categories[] = $categoryMap[ $threatType ];
            }
        }

        return $categories;
    }
}
