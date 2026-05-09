<?php

declare( strict_types=1 );

namespace ArtisanPackUI\SecurityAnalytics\Analytics\ThreatIntelligence;

use ArtisanPackUI\SecurityAnalytics\Analytics\ThreatIntelligence\Contracts\ThreatIntelProviderInterface;
use ArtisanPackUI\SecurityAnalytics\Analytics\ThreatIntelligence\Providers\AbuseIPDBProvider;
use ArtisanPackUI\SecurityAnalytics\Analytics\ThreatIntelligence\Providers\VirusTotalProvider;
use ArtisanPackUI\SecurityAnalytics\Models\ThreatIndicator;

class ThreatIntelligenceService
{
    /**
     * @var array<string, ThreatIntelProviderInterface>
     */
    protected array $providers = [];

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
        $this->registerDefaultProviders();
    }

    /**
     * Register a threat intelligence provider.
     */
    public function registerProvider( ThreatIntelProviderInterface $provider ): self
    {
        $this->providers[ $provider->getName() ] = $provider;

        return $this;
    }

    /**
     * Get a registered provider.
     */
    public function getProvider( string $name ): ?ThreatIntelProviderInterface
    {
        return $this->providers[ $name ] ?? null;
    }

    /**
     * Get all enabled providers.
     *
     * @return array<string, ThreatIntelProviderInterface>
     */
    public function getEnabledProviders(): array
    {
        return array_filter( $this->providers, fn ( $p ) => $p->isEnabled() );
    }

    /**
     * Check an IP address against all providers.
     *
     * @return array<string, mixed>
     */
    public function checkIp( string $ip ): array
    {
        // First check local database
        $localResult = $this->checkLocalIndicator( $ip, ThreatIndicator::TYPE_IP );

        if ( $localResult ) {
            return $localResult;
        }

        // Check with external providers
        $results = $this->queryProviders( 'checkIp', $ip );

        // Aggregate results
        $aggregated = $this->aggregateResults( $results, $ip, 'ip' );

        // Store result in local database
        $this->storeIndicator( $aggregated );

        return $aggregated;
    }

    /**
     * Check a domain against all providers.
     *
     * @return array<string, mixed>
     */
    public function checkDomain( string $domain ): array
    {
        $localResult = $this->checkLocalIndicator( $domain, ThreatIndicator::TYPE_DOMAIN );

        if ( $localResult ) {
            return $localResult;
        }

        $results    = $this->queryProviders( 'checkDomain', $domain );
        $aggregated = $this->aggregateResults( $results, $domain, 'domain' );
        $this->storeIndicator( $aggregated );

        return $aggregated;
    }

    /**
     * Check a URL against all providers.
     *
     * @return array<string, mixed>
     */
    public function checkUrl( string $url ): array
    {
        $localResult = $this->checkLocalIndicator( $url, ThreatIndicator::TYPE_URL );

        if ( $localResult ) {
            return $localResult;
        }

        $results    = $this->queryProviders( 'checkUrl', $url );
        $aggregated = $this->aggregateResults( $results, $url, 'url' );
        $this->storeIndicator( $aggregated );

        return $aggregated;
    }

    /**
     * Check a file hash against all providers.
     *
     * @return array<string, mixed>
     */
    public function checkHash( string $hash ): array
    {
        $localResult = $this->checkLocalIndicator( $hash, ThreatIndicator::TYPE_HASH );

        if ( $localResult ) {
            return $localResult;
        }

        $results    = $this->queryProviders( 'checkHash', $hash );
        $aggregated = $this->aggregateResults( $results, $hash, 'hash' );
        $this->storeIndicator( $aggregated );

        return $aggregated;
    }

    /**
     * Check if an IP should be blocked based on threat score.
     */
    public function shouldBlockIp( string $ip ): bool
    {
        $threshold = $this->config['auto_block_threshold'];

        if ( null === $threshold ) {
            return false;
        }

        $result = $this->checkIp( $ip );

        return ( $result['confidence'] ?? 0 ) >= $threshold;
    }

    /**
     * Get IP reputation score (0-100, lower is better).
     */
    public function getIpReputation( string $ip ): int
    {
        $result = $this->checkIp( $ip );

        return $result['confidence'] ?? 0;
    }

    /**
     * Import threat indicators from a feed.
     *
     * @param  array<int, array<string, mixed>>  $indicators
     */
    public function importIndicators( array $indicators, string $source ): int
    {
        $imported = 0;

        foreach ( $indicators as $indicatorData ) {
            $confidence = $indicatorData['confidence'] ?? 50;

            // Use firstOrNew to preserve first_seen_at on existing records
            $indicator = ThreatIndicator::firstOrNew( [
                'type'  => $indicatorData['type'],
                'value' => $indicatorData['value'],
            ] );

            // Only set first_seen_at for new records
            if ( ! $indicator->exists ) {
                $indicator->first_seen_at = now();
            }

            $indicator->fill( [
                'source'       => $source,
                'threat_type'  => $indicatorData['threat_type'] ?? 'unknown',
                'severity'     => $indicatorData['severity'] ?? $this->mapConfidenceToSeverity( $confidence ),
                'confidence'   => $confidence,
                'metadata'     => $indicatorData['metadata'] ?? [],
                'last_seen_at' => now(),
                'expires_at'   => now()->addDays( $indicatorData['ttl_days'] ?? 30 ),
            ] );

            $indicator->save();
            $imported++;
        }

        return $imported;
    }

    /**
     * Get statistics about stored threat indicators.
     *
     * @return array<string, mixed>
     */
    public function getStatistics(): array
    {
        return [
            'total_indicators'  => ThreatIndicator::count(),
            'active_indicators' => ThreatIndicator::active()->count(),
            'by_type'           => ThreatIndicator::selectRaw( 'type, COUNT(*) as count' )
                ->groupBy( 'type' )
                ->pluck( 'count', 'type' )
                ->toArray(),
            'by_threat_type' => ThreatIndicator::selectRaw( 'threat_type, COUNT(*) as count' )
                ->groupBy( 'threat_type' )
                ->pluck( 'count', 'threat_type' )
                ->toArray(),
            'by_source' => ThreatIndicator::selectRaw( 'source, COUNT(*) as count' )
                ->groupBy( 'source' )
                ->pluck( 'count', 'source' )
                ->toArray(),
            'expiring_soon' => ThreatIndicator::where( 'expires_at', '<=', now()->addDays( 3 ) )
                ->where( 'expires_at', '>', now() )
                ->count(),
        ];
    }

    /**
     * Cleanup expired indicators.
     */
    public function cleanupExpired(): int
    {
        return ThreatIndicator::expired()->delete();
    }

    /**
     * Get default configuration.
     *
     * @return array<string, mixed>
     */
    protected function getDefaultConfig(): array
    {
        return [
            'enabled'              => true,
            'cache_ttl'            => 60,
            'auto_block_threshold' => null,
            'providers'            => [],
        ];
    }

    /**
     * Register default providers.
     */
    protected function registerDefaultProviders(): void
    {
        $providerConfigs = $this->config['providers'] ?? [];

        if ( ! empty( $providerConfigs['abuseipdb'] ) ) {
            $this->registerProvider( new AbuseIPDBProvider( $providerConfigs['abuseipdb'] ) );
        }

        if ( ! empty( $providerConfigs['virustotal'] ) ) {
            $this->registerProvider( new VirusTotalProvider( $providerConfigs['virustotal'] ) );
        }
    }

    /**
     * Check local threat indicator database.
     *
     * @return array<string, mixed>|null
     */
    protected function checkLocalIndicator( string $value, string $type ): ?array
    {
        $indicator = ThreatIndicator::findActive( $type, $value );

        if ( ! $indicator ) {
            return null;
        }

        return [
            'indicator'      => $value,
            'indicator_type' => $type,
            'is_malicious'   => $indicator->confidence >= 70,
            'confidence'     => $indicator->confidence,
            'threat_level'   => $this->determineThreatLevel( $indicator->confidence ),
            'threat_type'    => $indicator->threat_type,
            'source'         => 'local_database',
            'providers'      => [$indicator->source],
            'first_seen'     => $indicator->first_seen_at?->toIso8601String(),
            'last_seen'      => $indicator->last_seen_at?->toIso8601String(),
        ];
    }

    /**
     * Query all enabled providers.
     *
     * @return array<int, array<string, mixed>>
     */
    protected function queryProviders( string $method, string $indicator ): array
    {
        $results = [];

        foreach ( $this->getEnabledProviders() as $provider ) {
            if ( in_array( $this->getTypeFromMethod( $method ), $provider->getSupportedTypes(), true ) ) {
                $result = $provider->$method( $indicator );
                if ( null !== $result ) {
                    $results[] = $result;
                }
            }
        }

        return $results;
    }

    /**
     * Aggregate results from multiple providers.
     *
     * @param  array<int, array<string, mixed>>  $results
     *
     * @return array<string, mixed>
     */
    protected function aggregateResults( array $results, string $indicator, string $type ): array
    {
        if ( empty( $results ) ) {
            return [
                'indicator'      => $indicator,
                'indicator_type' => $type,
                'is_malicious'   => false,
                'confidence'     => 0,
                'threat_level'   => 'none',
                'providers'      => [],
                'message'        => 'No threat intelligence data available',
            ];
        }

        $isMalicious     = false;
        $totalConfidence = 0;
        $maxConfidence   = 0;
        $providers       = [];
        $categories      = [];
        $threatTypes     = [];

        foreach ( $results as $result ) {
            if ( $result['is_malicious'] ?? false ) {
                $isMalicious = true;
            }

            $confidence = $result['confidence'] ?? 0;
            $totalConfidence += $confidence;
            $maxConfidence = max( $maxConfidence, $confidence );

            $providers[] = $result['provider'];

            if ( ! empty( $result['categories'] ) ) {
                $categories = array_merge( $categories, $result['categories'] );
            }

            if ( ! empty( $result['threat_type'] ) ) {
                $threatTypes[] = $result['threat_type'];
            }
        }

        // Use weighted average with bias toward max
        $avgConfidence   = count( $results ) > 0 ? $totalConfidence / count( $results ) : 0;
        $finalConfidence = (int) ( ( $avgConfidence + $maxConfidence ) / 2 );

        return [
            'indicator'        => $indicator,
            'indicator_type'   => $type,
            'is_malicious'     => $isMalicious,
            'confidence'       => $finalConfidence,
            'threat_level'     => $this->determineThreatLevel( $finalConfidence ),
            'providers'        => $providers,
            'categories'       => array_unique( $categories ),
            'threat_types'     => array_unique( $threatTypes ),
            'provider_results' => $results,
        ];
    }

    /**
     * Store a threat indicator in the local database.
     *
     * @param  array<string, mixed>  $data
     */
    protected function storeIndicator( array $data ): void
    {
        if ( ( $data['confidence'] ?? 0 ) < 20 ) {
            return; // Don't store low-confidence indicators
        }

        // Use firstOrNew to preserve first_seen_at on existing records
        $indicator = ThreatIndicator::firstOrNew( [
            'type'  => $data['indicator_type'],
            'value' => $data['indicator'],
        ] );

        // Only set first_seen_at for new records
        if ( ! $indicator->exists ) {
            $indicator->first_seen_at = now();
        }

        $indicator->fill( [
            'source'      => implode( ',', $data['providers'] ?? [] ),
            'threat_type' => $data['threat_types'][0] ?? 'unknown',
            'severity'    => $this->mapConfidenceToSeverity( $data['confidence'] ?? 0 ),
            'confidence'  => $data['confidence'],
            'metadata'    => [
                'categories'   => $data['categories'] ?? [],
                'threat_level' => $data['threat_level'],
            ],
            'last_seen_at' => now(),
            'expires_at'   => now()->addDays( 7 ),
        ] );

        $indicator->save();
    }

    /**
     * Determine threat level from confidence score.
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

    /**
     * Get indicator type from method name.
     */
    protected function getTypeFromMethod( string $method ): string
    {
        return match ( $method ) {
            'checkIp'     => 'ip',
            'checkDomain' => 'domain',
            'checkUrl'    => 'url',
            'checkHash'   => 'hash',
            default       => 'unknown',
        };
    }

    /**
     * Map confidence score to severity level.
     */
    protected function mapConfidenceToSeverity( int $confidence ): string
    {
        return match ( true ) {
            $confidence >= 80 => ThreatIndicator::SEVERITY_CRITICAL,
            $confidence >= 60 => ThreatIndicator::SEVERITY_HIGH,
            $confidence >= 40 => ThreatIndicator::SEVERITY_MEDIUM,
            $confidence >= 20 => ThreatIndicator::SEVERITY_LOW,
            default           => ThreatIndicator::SEVERITY_INFO,
        };
    }
}
