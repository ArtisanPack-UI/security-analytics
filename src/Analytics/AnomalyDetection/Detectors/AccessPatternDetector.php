<?php

declare( strict_types=1 );

namespace ArtisanPackUI\SecurityAnalytics\Analytics\AnomalyDetection\Detectors;

use ArtisanPackUI\SecurityAnalytics\Models\Anomaly;
use ArtisanPackUI\SecurityAnalytics\Models\UserBehaviorProfile;
use Illuminate\Support\Collection;
use Illuminate\Support\Facades\Cache;

class AccessPatternDetector extends AbstractDetector
{
    /**
     * {@inheritdoc}
     */
    public function getName(): string
    {
        return 'access_pattern';
    }

    /**
     * {@inheritdoc}
     */
    public function detect( array $data ): Collection
    {
        $anomalies = collect();

        if ( ! $this->isEnabled() ) {
            return $anomalies;
        }

        // Track request
        $this->trackRequest( $data );

        // Check for unusual access patterns
        if ( isset( $data['user_id'] ) ) {
            $userId = (int) $data['user_id'];

            // Check for sensitive endpoint access
            if ( isset( $data['endpoint'] ) ) {
                $anomaly = $this->checkSensitiveEndpointAccess( $userId, $data['endpoint'], $data );
                if ( $anomaly ) {
                    $anomalies->push( $anomaly );
                }
            }

            // Check for bulk data access
            $anomaly = $this->checkBulkDataAccess( $userId, $data );
            if ( $anomaly ) {
                $anomalies->push( $anomaly );
            }

            // Check for unusual access time
            $anomaly = $this->checkUnusualAccessTime( $userId, $data );
            if ( $anomaly ) {
                $anomalies->push( $anomaly );
            }

            // Check for rapid requests
            $anomaly = $this->checkRapidRequests( $userId, $data );
            if ( $anomaly ) {
                $anomalies->push( $anomaly );
            }
        }

        // Check for unusual resource access pattern
        if ( isset( $data['resource'] ) && isset( $data['user_id'] ) ) {
            $anomaly = $this->checkUnusualResourceAccess( (int) $data['user_id'], $data['resource'], $data );
            if ( $anomaly ) {
                $anomalies->push( $anomaly );
            }
        }

        return $anomalies;
    }

    /**
     * {@inheritdoc}
     */
    protected function getDefaultConfig(): array
    {
        return [
            'enabled'             => true,
            'min_samples'         => 50, // Minimum requests for baseline
            'deviation_threshold' => 3.0, // Standard deviations
            'sensitive_endpoints' => [
                '/admin/*',
                '/api/users/*',
                '/api/settings/*',
                '/api/export/*',
                '/api/audit/*',
            ],
            'bulk_download_threshold'      => 100, // Records in short time
            'bulk_download_window_minutes' => 5,
            'rapid_request_threshold'      => 60, // Requests per minute
        ];
    }

    /**
     * Track a request for pattern analysis.
     *
     * @param  array<string, mixed>  $data
     */
    protected function trackRequest( array $data ): void
    {
        $userId   = $data['user_id'] ?? 'anonymous';
        $cacheKey = "access_pattern:user:{$userId}";

        $requestData = Cache::get( $cacheKey, [
            'count'      => 0,
            'endpoints'  => [],
            'timestamps' => [],
            'resources'  => [],
        ] );

        $requestData['count']++;
        $requestData['timestamps'][] = now()->timestamp;

        if ( isset( $data['endpoint'] ) ) {
            $requestData['endpoints'][] = $data['endpoint'];
        }

        if ( isset( $data['resource'] ) ) {
            $requestData['resources'][] = $data['resource'];
        }

        // Keep only recent data
        $cutoff                    = now()->subHour()->timestamp;
        $requestData['timestamps'] = array_filter(
            $requestData['timestamps'],
            fn ( $ts ) => $ts >= $cutoff,
        );

        Cache::put( $cacheKey, $requestData, now()->addHour() );
    }

    /**
     * Check for sensitive endpoint access.
     *
     * @param  array<string, mixed>  $data
     */
    protected function checkSensitiveEndpointAccess( int $userId, string $endpoint, array $data ): ?Anomaly
    {
        if ( ! $this->isSensitiveEndpoint( $endpoint ) ) {
            return null;
        }

        // Check if user typically accesses this endpoint
        $profile = UserBehaviorProfile::where( 'user_id', $userId )
            ->where( 'profile_type', UserBehaviorProfile::TYPE_ACCESS_PATTERNS )
            ->first();

        if ( ! $profile || $profile->sample_count < $this->config['min_samples'] ) {
            // No baseline - flag first access to sensitive endpoints
            $cacheKey    = "sensitive_access:user:{$userId}";
            $firstAccess = ! Cache::has( $cacheKey );
            Cache::put( $cacheKey, true, now()->addDay() );

            if ( $firstAccess ) {
                $suppressKey = "sensitive_endpoint_user_{$userId}_" . md5( $endpoint );

                if ( ! $this->shouldSuppress( $suppressKey ) ) {
                    $this->startCooldown( $suppressKey, 60 );

                    return $this->createAnomaly(
                        Anomaly::CATEGORY_ACCESS,
                        "First-time access to sensitive endpoint: {$endpoint}",
                        Anomaly::SEVERITY_LOW,
                        60.0,
                        [
                            'endpoint'     => $endpoint,
                            'first_access' => true,
                            'ip'           => $data['ip'] ?? null,
                        ],
                        $userId,
                        $data['ip'] ?? null,
                    );
                }
            }

            return null;
        }

        // Check against baseline
        $baseline         = $profile->baseline_data ?? [];
        $typicalEndpoints = $baseline['frequent_endpoints'] ?? [];

        if ( ! in_array( $endpoint, $typicalEndpoints, true ) ) {
            $score       = 65.0;
            $suppressKey = "unusual_endpoint_user_{$userId}_" . md5( $endpoint );

            if ( ! $this->shouldSuppress( $suppressKey ) ) {
                $this->startCooldown( $suppressKey, 60 );

                return $this->createAnomaly(
                    Anomaly::CATEGORY_ACCESS,
                    "Access to unusual sensitive endpoint: {$endpoint}",
                    Anomaly::SEVERITY_MEDIUM,
                    $score,
                    [
                        'endpoint'          => $endpoint,
                        'typical_endpoints' => array_slice( $typicalEndpoints, 0, 5 ),
                        'ip'                => $data['ip'] ?? null,
                    ],
                    $userId,
                    $data['ip'] ?? null,
                );
            }
        }

        return null;
    }

    /**
     * Check for bulk data access patterns.
     *
     * @param  array<string, mixed>  $data
     */
    protected function checkBulkDataAccess( int $userId, array $data ): ?Anomaly
    {
        $recordsAccessed = $data['records_accessed'] ?? 0;

        if ( $recordsAccessed < $this->config['bulk_download_threshold'] ) {
            return null;
        }

        $cacheKey = "bulk_access:user:{$userId}";
        $bulkData = Cache::get( $cacheKey, [
            'accesses' => [], // Array of {timestamp, count} entries
        ] );

        // Add new access entry with timestamp and count
        $bulkData['accesses'][] = [
            'timestamp' => now()->timestamp,
            'count'     => $recordsAccessed,
        ];

        // Remove old entries outside the time window
        $cutoff               = now()->subMinutes( $this->config['bulk_download_window_minutes'] )->timestamp;
        $bulkData['accesses'] = array_filter(
            $bulkData['accesses'],
            fn ( $entry ) => $entry['timestamp'] >= $cutoff,
        );
        $bulkData['accesses'] = array_values( $bulkData['accesses'] ); // Re-index array

        // Recalculate total from remaining entries
        $totalRecords = array_sum( array_column( $bulkData['accesses'], 'count' ) );

        Cache::put( $cacheKey, $bulkData, now()->addMinutes( $this->config['bulk_download_window_minutes'] ) );

        if ( $totalRecords >= $this->config['bulk_download_threshold'] * 2 ) {
            $score       = min( 100, ( $totalRecords / ( $this->config['bulk_download_threshold'] * 2 ) ) * 70 + 30 );
            $suppressKey = "bulk_access_user_{$userId}";

            if ( ! $this->shouldSuppress( $suppressKey ) ) {
                $this->startCooldown( $suppressKey, 30 );

                return $this->createAnomaly(
                    Anomaly::CATEGORY_ACCESS,
                    'Bulk data access detected - potential data exfiltration',
                    Anomaly::SEVERITY_HIGH,
                    $score,
                    [
                        'attack_type'         => 'bulk_data_access',
                        'records_accessed'    => $totalRecords,
                        'time_window_minutes' => $this->config['bulk_download_window_minutes'],
                        'threshold'           => $this->config['bulk_download_threshold'],
                        'ip'                  => $data['ip'] ?? null,
                    ],
                    $userId,
                    $data['ip'] ?? null,
                );
            }
        }

        return null;
    }

    /**
     * Check for unusual access time.
     *
     * @param  array<string, mixed>  $data
     */
    protected function checkUnusualAccessTime( int $userId, array $data ): ?Anomaly
    {
        $profile = UserBehaviorProfile::where( 'user_id', $userId )
            ->where( 'profile_type', UserBehaviorProfile::TYPE_ACCESS_PATTERNS )
            ->first();

        if ( ! $profile || $profile->sample_count < $this->config['min_samples'] ) {
            return null;
        }

        $baseline     = $profile->baseline_data ?? [];
        $typicalHours = $baseline['typical_hours'] ?? [];

        if ( empty( $typicalHours ) ) {
            return null;
        }

        $currentHour = now()->hour;

        if ( ! in_array( $currentHour, $typicalHours, true ) ) {
            $score       = 55.0;
            $suppressKey = "unusual_time_user_{$userId}";

            if ( ! $this->shouldSuppress( $suppressKey ) ) {
                $this->startCooldown( $suppressKey, 60 );

                return $this->createAnomaly(
                    Anomaly::CATEGORY_ACCESS,
                    "Access at unusual time ({$currentHour}:00)",
                    Anomaly::SEVERITY_LOW,
                    $score,
                    [
                        'current_hour'  => $currentHour,
                        'typical_hours' => $typicalHours,
                        'ip'            => $data['ip'] ?? null,
                    ],
                    $userId,
                    $data['ip'] ?? null,
                );
            }
        }

        return null;
    }

    /**
     * Check for rapid requests.
     *
     * @param  array<string, mixed>  $data
     */
    protected function checkRapidRequests( int $userId, array $data ): ?Anomaly
    {
        $cacheKey = "rapid_requests:user:{$userId}";

        $requestData                 = Cache::get( $cacheKey, ['timestamps' => []] );
        $requestData['timestamps'][] = now()->timestamp;

        // Keep only last minute
        $cutoff                    = now()->subMinute()->timestamp;
        $requestData['timestamps'] = array_filter(
            $requestData['timestamps'],
            fn ( $ts ) => $ts >= $cutoff,
        );

        Cache::put( $cacheKey, $requestData, now()->addMinute() );

        $requestsPerMinute = count( $requestData['timestamps'] );

        if ( $requestsPerMinute >= $this->config['rapid_request_threshold'] ) {
            $score       = min( 100, ( $requestsPerMinute / $this->config['rapid_request_threshold'] ) * 70 );
            $suppressKey = "rapid_requests_user_{$userId}";

            if ( ! $this->shouldSuppress( $suppressKey ) ) {
                $this->startCooldown( $suppressKey, 5 );

                return $this->createAnomaly(
                    Anomaly::CATEGORY_ACCESS,
                    'Unusually high request rate detected',
                    Anomaly::SEVERITY_MEDIUM,
                    $score,
                    [
                        'requests_per_minute' => $requestsPerMinute,
                        'threshold'           => $this->config['rapid_request_threshold'],
                        'ip'                  => $data['ip'] ?? null,
                    ],
                    $userId,
                    $data['ip'] ?? null,
                );
            }
        }

        return null;
    }

    /**
     * Check for unusual resource access.
     *
     * @param  array<string, mixed>  $data
     */
    protected function checkUnusualResourceAccess( int $userId, string $resource, array $data ): ?Anomaly
    {
        $profile = UserBehaviorProfile::where( 'user_id', $userId )
            ->where( 'profile_type', UserBehaviorProfile::TYPE_ACCESS_PATTERNS )
            ->first();

        if ( ! $profile || $profile->sample_count < $this->config['min_samples'] ) {
            return null;
        }

        $baseline         = $profile->baseline_data ?? [];
        $typicalResources = $baseline['typical_resources'] ?? [];

        if ( empty( $typicalResources ) || in_array( $resource, $typicalResources, true ) ) {
            return null;
        }

        // Check if this resource type is completely new
        $resourceType = $this->extractResourceType( $resource );
        $knownTypes   = array_map( [$this, 'extractResourceType'], $typicalResources );

        if ( ! in_array( $resourceType, $knownTypes, true ) ) {
            $score       = 60.0;
            $suppressKey = "unusual_resource_user_{$userId}_" . md5( $resource );

            if ( ! $this->shouldSuppress( $suppressKey ) ) {
                $this->startCooldown( $suppressKey, 60 );

                return $this->createAnomaly(
                    Anomaly::CATEGORY_ACCESS,
                    "Access to unusual resource type: {$resourceType}",
                    Anomaly::SEVERITY_LOW,
                    $score,
                    [
                        'resource'             => $resource,
                        'resource_type'        => $resourceType,
                        'known_resource_types' => array_unique( $knownTypes ),
                        'ip'                   => $data['ip'] ?? null,
                    ],
                    $userId,
                    $data['ip'] ?? null,
                );
            }
        }

        return null;
    }

    /**
     * Check if endpoint is sensitive.
     */
    protected function isSensitiveEndpoint( string $endpoint ): bool
    {
        foreach ( $this->config['sensitive_endpoints'] as $pattern ) {
            if ( str_contains( $pattern, '*' ) ) {
                // Escape all regex metacharacters except *, then convert * to .*
                $escaped = preg_quote( $pattern, '/' );
                $regex   = '/^' . str_replace( '\\*', '.*', $escaped ) . '$/';
                if ( preg_match( $regex, $endpoint ) ) {
                    return true;
                }
            } elseif ( $endpoint === $pattern ) {
                return true;
            }
        }

        return false;
    }

    /**
     * Extract resource type from resource identifier.
     */
    protected function extractResourceType( string $resource ): string
    {
        // Extract type from patterns like "users/123" or "posts:456"
        if ( preg_match( '/^([a-z_]+)[\/:]/', $resource, $matches ) ) {
            return $matches[1];
        }

        return 'unknown';
    }
}
