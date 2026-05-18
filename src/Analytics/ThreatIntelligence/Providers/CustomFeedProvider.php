<?php

/**
 * CustomFeedProvider threat intelligence provider.
 *
 * @package    ArtisanPack_UI
 * @subpackage SecurityAnalytics
 *
 * @author     Jacob Martella <support@artisanpackui.dev>
 *
 * @since      1.0.0
 */

declare( strict_types=1 );

namespace ArtisanPackUI\SecurityAnalytics\Analytics\ThreatIntelligence\Providers;

use ArtisanPackUI\SecurityAnalytics\Models\ThreatIndicator;
use Exception;
use Illuminate\Support\Facades\Http;

class CustomFeedProvider extends AbstractProvider
{
    /**
     * {@inheritdoc}
     */
    public function getName(): string
    {
        return 'custom_feed';
    }

    /**
     * {@inheritdoc}
     */
    public function getSupportedTypes(): array
    {
        return ['ip', 'domain', 'url', 'hash', 'email'];
    }

    /**
     * {@inheritdoc}
     */
    public function checkIp( string $ip ): ?array
    {
        return $this->checkLocalIndicator( $ip, ThreatIndicator::TYPE_IP );
    }

    /**
     * {@inheritdoc}
     */
    public function checkDomain( string $domain ): ?array
    {
        return $this->checkLocalIndicator( $domain, ThreatIndicator::TYPE_DOMAIN );
    }

    /**
     * {@inheritdoc}
     */
    public function checkUrl( string $url ): ?array
    {
        return $this->checkLocalIndicator( $url, ThreatIndicator::TYPE_URL );
    }

    /**
     * {@inheritdoc}
     */
    public function checkHash( string $hash ): ?array
    {
        return $this->checkLocalIndicator( $hash, ThreatIndicator::TYPE_HASH );
    }

    /**
     * Sync all configured feeds.
     *
     * @return array<string, mixed>
     */
    public function syncAllFeeds(): array
    {
        $results = [];

        foreach ( $this->config['feeds'] as $feedName => $feedConfig ) {
            $results[ $feedName ] = $this->syncFeed( $feedName, $feedConfig );
        }

        return $results;
    }

    /**
     * Sync a single feed.
     *
     * @param  array<string, mixed>  $feedConfig
     *
     * @return array<string, mixed>
     */
    public function syncFeed( string $feedName, array $feedConfig ): array
    {
        $url = $feedConfig['url'] ?? null;

        if ( ! $url ) {
            return ['success' => false, 'error' => 'No URL configured'];
        }

        try {
            $response = Http::timeout( $this->config['timeout'] )
                ->withHeaders( $feedConfig['headers'] ?? [] )
                ->get( $url );

            if ( ! $response->successful() ) {
                return [
                    'success' => false,
                    'error'   => "HTTP {$response->status()}",
                ];
            }

            $indicators = $this->parseFeedContent(
                $response->body(),
                $feedConfig['format'] ?? 'auto',
                $feedConfig,
            );

            $imported = $this->importIndicators( $indicators, $feedName, $feedConfig );

            return [
                'success'      => true,
                'imported'     => $imported,
                'total_parsed' => count( $indicators ),
            ];
        } catch ( Exception $e ) {
            return [
                'success' => false,
                'error'   => $e->getMessage(),
            ];
        }
    }

    /**
     * {@inheritdoc}
     */
    protected function getDefaultConfig(): array
    {
        return [
            'enabled'            => false,
            'feeds'              => [],
            'default_confidence' => 70,
            'default_ttl_days'   => 7,
            'cache_ttl'          => 3600, // 1 hour
            'timeout'            => 30,
        ];
    }

    /**
     * Check indicator against local database.
     *
     * @return array<string, mixed>|null
     */
    protected function checkLocalIndicator( string $value, string $type ): ?array
    {
        $indicator = ThreatIndicator::findActive( $value, $type );

        if ( ! $indicator ) {
            return null;
        }

        return [
            'provider'       => $this->getName(),
            'indicator'      => $value,
            'indicator_type' => $type,
            'is_malicious'   => $indicator->confidence >= 70,
            'confidence'     => $indicator->confidence,
            'threat_level'   => $this->determineThreatLevel( $indicator->confidence ),
            'threat_type'    => $indicator->threat_type,
            'source'         => $indicator->source,
            'first_seen'     => $indicator->first_seen_at?->toIso8601String(),
            'last_seen'      => $indicator->last_seen_at?->toIso8601String(),
            'metadata'       => $indicator->metadata,
        ];
    }

    /**
     * Parse feed content based on format.
     *
     * @param  array<string, mixed>  $feedConfig
     *
     * @return array<int, array<string, mixed>>
     */
    protected function parseFeedContent( string $content, string $format, array $feedConfig ): array
    {
        return match ( $format ) {
            'json'  => $this->parseJsonFeed( $content, $feedConfig ),
            'csv'   => $this->parseCsvFeed( $content, $feedConfig ),
            'stix'  => $this->parseStixFeed( $content ),
            'plain' => $this->parsePlainFeed( $content, $feedConfig ),
            default => $this->autoDetectAndParse( $content, $feedConfig ),
        };
    }

    /**
     * Parse JSON feed.
     *
     * @param  array<string, mixed>  $feedConfig
     *
     * @return array<int, array<string, mixed>>
     */
    protected function parseJsonFeed( string $content, array $feedConfig ): array
    {
        $data = json_decode( $content, true );

        if ( JSON_ERROR_NONE !== json_last_error() ) {
            return [];
        }

        // Handle different JSON structures
        $indicatorsPath = $feedConfig['json_path'] ?? null;

        if ( $indicatorsPath ) {
            $data = data_get( $data, $indicatorsPath, [] );
        } elseif ( isset( $data['indicators'] ) ) {
            $data = $data['indicators'];
        } elseif ( isset( $data['data'] ) ) {
            $data = $data['data'];
        }

        if ( ! is_array( $data ) ) {
            return [];
        }

        return array_map( function ( $item ) use ( $feedConfig ) {
            return [
                'value'       => $item[ $feedConfig['value_field'] ?? 'indicator' ] ?? $item['value'] ?? $item,
                'type'        => $item[ $feedConfig['type_field'] ?? 'type' ] ?? $this->detectType( $item[ $feedConfig['value_field'] ?? 'indicator' ] ?? $item['value'] ?? $item ),
                'threat_type' => $item[ $feedConfig['threat_type_field'] ?? 'threat_type' ] ?? 'unknown',
                'confidence'  => $item[ $feedConfig['confidence_field'] ?? 'confidence' ] ?? $this->config['default_confidence'],
            ];
        }, $data );
    }

    /**
     * Parse CSV feed.
     *
     * @param  array<string, mixed>  $feedConfig
     *
     * @return array<int, array<string, mixed>>
     */
    protected function parseCsvFeed( string $content, array $feedConfig ): array
    {
        $indicators = [];
        $lines      = explode( "\n", trim( $content ) );

        // Handle header
        $hasHeader = $feedConfig['has_header'] ?? true;
        if ( $hasHeader ) {
            array_shift( $lines );
        }

        $valueColumn      = $feedConfig['value_column'] ?? 0;
        $typeColumn       = $feedConfig['type_column'] ?? null;
        $threatTypeColumn = $feedConfig['threat_type_column'] ?? null;
        $confidenceColumn = $feedConfig['confidence_column'] ?? null;

        foreach ( $lines as $line ) {
            $line = trim( $line );
            if ( empty( $line ) || str_starts_with( $line, '#' ) ) {
                continue;
            }

            $parts = str_getcsv( $line );
            $value = trim( $parts[ $valueColumn ] ?? '' );

            if ( empty( $value ) ) {
                continue;
            }

            $indicators[] = [
                'value'       => $value,
                'type'        => null !== $typeColumn ? ( $parts[ $typeColumn ] ?? $this->detectType( $value ) ) : $this->detectType( $value ),
                'threat_type' => null !== $threatTypeColumn ? ( $parts[ $threatTypeColumn ] ?? 'unknown' ) : 'unknown',
                'confidence'  => null !== $confidenceColumn ? (int) ( $parts[ $confidenceColumn ] ?? $this->config['default_confidence'] ) : $this->config['default_confidence'],
            ];
        }

        return $indicators;
    }

    /**
     * Parse STIX feed.
     *
     * @return array<int, array<string, mixed>>
     */
    protected function parseStixFeed( string $content ): array
    {
        $data = json_decode( $content, true );

        if ( JSON_ERROR_NONE !== json_last_error() || ! isset( $data['objects'] ) ) {
            return [];
        }

        $indicators = [];

        foreach ( $data['objects'] as $object ) {
            if ( 'indicator' !== $object['type'] ) {
                continue;
            }

            $indicator = $this->parseStixPattern( $object['pattern'] ?? '' );

            if ( $indicator ) {
                $indicators[] = array_merge( $indicator, [
                    'threat_type' => $object['indicator_types'][0] ?? 'unknown',
                    'confidence'  => $object['confidence'] ?? $this->config['default_confidence'],
                ] );
            }
        }

        return $indicators;
    }

    /**
     * Parse STIX pattern to extract indicator.
     *
     * @return array<string, string>|null
     */
    protected function parseStixPattern( string $pattern ): ?array
    {
        $patterns = [
            "/\[ipv4-addr:value\s*=\s*'([^']+)'\]/"        => ThreatIndicator::TYPE_IP,
            "/\[domain-name:value\s*=\s*'([^']+)'\]/"      => ThreatIndicator::TYPE_DOMAIN,
            "/\[url:value\s*=\s*'([^']+)'\]/"              => ThreatIndicator::TYPE_URL,
            "/\[file:hashes\.'SHA-256'\s*=\s*'([^']+)'\]/" => ThreatIndicator::TYPE_HASH,
            "/\[file:hashes\.'MD5'\s*=\s*'([^']+)'\]/"     => ThreatIndicator::TYPE_HASH,
        ];

        foreach ( $patterns as $regex => $type ) {
            if ( preg_match( $regex, $pattern, $matches ) ) {
                return [
                    'value' => $matches[1],
                    'type'  => $type,
                ];
            }
        }

        return null;
    }

    /**
     * Parse plain text feed.
     *
     * @param  array<string, mixed>  $feedConfig
     *
     * @return array<int, array<string, mixed>>
     */
    protected function parsePlainFeed( string $content, array $feedConfig ): array
    {
        $indicators  = [];
        $lines       = explode( "\n", trim( $content ) );
        $defaultType = $feedConfig['default_type'] ?? null;

        foreach ( $lines as $line ) {
            $line = trim( $line );
            if ( empty( $line ) || str_starts_with( $line, '#' ) ) {
                continue;
            }

            $indicators[] = [
                'value'       => $line,
                'type'        => $defaultType ?? $this->detectType( $line ),
                'threat_type' => 'unknown',
                'confidence'  => $this->config['default_confidence'],
            ];
        }

        return $indicators;
    }

    /**
     * Auto-detect format and parse.
     *
     * @param  array<string, mixed>  $feedConfig
     *
     * @return array<int, array<string, mixed>>
     */
    protected function autoDetectAndParse( string $content, array $feedConfig ): array
    {
        // Try JSON first
        $jsonIndicators = $this->parseJsonFeed( $content, $feedConfig );
        if ( ! empty( $jsonIndicators ) ) {
            return $jsonIndicators;
        }

        // Try CSV
        if ( str_contains( $content, ',' ) ) {
            return $this->parseCsvFeed( $content, $feedConfig );
        }

        // Default to plain text
        return $this->parsePlainFeed( $content, $feedConfig );
    }

    /**
     * Detect indicator type from value.
     */
    protected function detectType( string $value ): string
    {
        if ( filter_var( $value, FILTER_VALIDATE_IP ) ) {
            return ThreatIndicator::TYPE_IP;
        }

        if ( filter_var( $value, FILTER_VALIDATE_URL ) ) {
            return ThreatIndicator::TYPE_URL;
        }

        if ( filter_var( $value, FILTER_VALIDATE_EMAIL ) ) {
            return ThreatIndicator::TYPE_EMAIL;
        }

        if ( preg_match( '/^[a-f0-9]{32,64}$/i', $value ) ) {
            return ThreatIndicator::TYPE_HASH;
        }

        return ThreatIndicator::TYPE_DOMAIN;
    }

    /**
     * Import parsed indicators to database.
     *
     * @param  array<int, array<string, mixed>>  $indicators
     * @param  array<string, mixed>  $feedConfig
     */
    protected function importIndicators( array $indicators, string $feedName, array $feedConfig ): int
    {
        $imported = 0;
        $ttlDays  = $feedConfig['ttl_days'] ?? $this->config['default_ttl_days'];

        foreach ( $indicators as $indicator ) {
            ThreatIndicator::updateOrCreate(
                [
                    'type'  => $indicator['type'],
                    'value' => $indicator['value'],
                ],
                [
                    'source'       => "custom_feed:{$feedName}",
                    'threat_type'  => $indicator['threat_type'],
                    'confidence'   => $indicator['confidence'],
                    'metadata'     => $indicator['metadata'] ?? [],
                    'last_seen_at' => now(),
                    'expires_at'   => now()->addDays( $ttlDays ),
                ],
            );

            $imported++;
        }

        return $imported;
    }

    /**
     * {@inheritdoc}
     */
    protected function getHeaders(): array
    {
        return [
            'Accept' => 'application/json, text/plain, */*',
        ];
    }
}
