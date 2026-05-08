<?php

declare( strict_types=1 );

namespace ArtisanPackUI\SecurityAnalytics\Analytics\AnomalyDetection\Detectors;

use ArtisanPackUI\SecurityAnalytics\Models\Anomaly;
use Illuminate\Support\Collection;
use Illuminate\Support\Facades\Cache;

class BruteForceDetector extends AbstractDetector
{
    /**
     * {@inheritdoc}
     */
    public function getName(): string
    {
        return 'brute_force';
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

        // Check for IP-based brute force
        if ( isset( $data['ip'] ) ) {
            $anomaly = $this->checkIpBruteForce( $data['ip'], $data );
            if ( $anomaly ) {
                $anomalies->push( $anomaly );
            }
        }

        // Check for user-targeted brute force
        if ( isset( $data['username'] ) || isset( $data['email'] ) ) {
            $target  = $data['username'] ?? $data['email'];
            $anomaly = $this->checkUserBruteForce( $target, $data );
            if ( $anomaly ) {
                $anomalies->push( $anomaly );
            }
        }

        // Check for distributed brute force
        if ( isset( $data['user_id'] ) ) {
            $anomaly = $this->checkDistributedBruteForce( (int) $data['user_id'], $data );
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
            'enabled'                   => true,
            'failed_attempts_threshold' => 5, // Failed attempts before flagging
            'time_window_minutes'       => 15, // Time window to count attempts
            'ip_threshold'              => 10, // Failed attempts from single IP
            'distributed_threshold'     => 20, // Failed attempts across multiple IPs targeting single user
            'velocity_threshold'        => 3, // Attempts per minute threshold
        ];
    }

    /**
     * Check for brute force from single IP.
     *
     * @param  array<string, mixed>  $data
     */
    protected function checkIpBruteForce( string $ip, array $data ): ?Anomaly
    {
        $cacheKey = "brute_force:ip:{$ip}";
        $attempts = $this->trackAttempt( $cacheKey );

        if ( $attempts >= $this->config['ip_threshold'] ) {
            $score       = min( 100, ( $attempts / $this->config['ip_threshold'] ) * 60 + 40 );
            $suppressKey = "brute_force_ip_{$ip}";

            if ( ! $this->shouldSuppress( $suppressKey ) ) {
                $this->startCooldown( $suppressKey, 15 );

                return $this->createAnomaly(
                    Anomaly::CATEGORY_AUTHENTICATION,
                    "Brute force attack detected from IP: {$ip}",
                    Anomaly::SEVERITY_HIGH,
                    $score,
                    [
                        'attack_type'         => 'ip_brute_force',
                        'failed_attempts'     => $attempts,
                        'threshold'           => $this->config['ip_threshold'],
                        'time_window_minutes' => $this->config['time_window_minutes'],
                        'targets'             => $this->getTargetsFromIp( $ip ),
                        'ip'                  => $ip,
                    ],
                );
            }
        }

        return null;
    }

    /**
     * Check for brute force targeting specific user.
     *
     * @param  array<string, mixed>  $data
     */
    protected function checkUserBruteForce( string $target, array $data ): ?Anomaly
    {
        $cacheKey = "brute_force:user:{$target}";
        $attempts = $this->trackAttempt( $cacheKey, $data['ip'] ?? null );

        if ( $attempts >= $this->config['failed_attempts_threshold'] ) {
            // Check velocity (attempts per minute)
            $velocity = $this->calculateVelocity( $cacheKey );

            if ( $velocity >= $this->config['velocity_threshold'] ) {
                $score       = min( 100, ( $attempts / $this->config['failed_attempts_threshold'] ) * 50 + ( $velocity / $this->config['velocity_threshold'] ) * 30 );
                $suppressKey = 'brute_force_user_' . md5( $target );

                if ( ! $this->shouldSuppress( $suppressKey ) ) {
                    $this->startCooldown( $suppressKey, 15 );

                    return $this->createAnomaly(
                        Anomaly::CATEGORY_AUTHENTICATION,
                        "Brute force attack targeting user: {$target}",
                        Anomaly::SEVERITY_HIGH,
                        $score,
                        [
                            'attack_type'         => 'user_brute_force',
                            'target'              => $target,
                            'failed_attempts'     => $attempts,
                            'threshold'           => $this->config['failed_attempts_threshold'],
                            'velocity_per_minute' => round( $velocity, 2 ),
                            'source_ips'          => $this->getSourceIps( $cacheKey ),
                            'ip'                  => $data['ip'] ?? null,
                        ],
                    );
                }
            }
        }

        return null;
    }

    /**
     * Check for distributed brute force (multiple IPs targeting one user).
     *
     * @param  array<string, mixed>  $data
     */
    protected function checkDistributedBruteForce( int $userId, array $data ): ?Anomaly
    {
        $cacheKey    = "brute_force:distributed:{$userId}";
        $ipsCacheKey = "{$cacheKey}:ips";

        // Track IP
        if ( isset( $data['ip'] ) ) {
            $ips = Cache::get( $ipsCacheKey, [] );
            if ( ! in_array( $data['ip'], $ips, true ) ) {
                $ips[] = $data['ip'];
                Cache::put( $ipsCacheKey, $ips, now()->addMinutes( $this->config['time_window_minutes'] ) );
            }
        }

        $attempts = $this->trackAttempt( $cacheKey );
        $ips      = Cache::get( $ipsCacheKey, [] );
        $ipCount  = count( $ips );

        // Distributed attack: many IPs, many attempts
        if ( $attempts >= $this->config['distributed_threshold'] && $ipCount >= 3 ) {
            $score       = min( 100, ( $attempts / $this->config['distributed_threshold'] ) * 40 + ( $ipCount * 10 ) );
            $suppressKey = "distributed_brute_force_user_{$userId}";

            if ( ! $this->shouldSuppress( $suppressKey ) ) {
                $this->startCooldown( $suppressKey, 30 );

                return $this->createAnomaly(
                    Anomaly::CATEGORY_AUTHENTICATION,
                    'Distributed brute force attack detected - multiple IPs targeting user',
                    Anomaly::SEVERITY_CRITICAL,
                    $score,
                    [
                        'attack_type'     => 'distributed_brute_force',
                        'failed_attempts' => $attempts,
                        'unique_ips'      => $ipCount,
                        'source_ips'      => array_slice( $ips, 0, 10 ), // First 10 IPs
                        'threshold'       => $this->config['distributed_threshold'],
                        'ip'              => $data['ip'] ?? null,
                    ],
                    $userId,
                );
            }
        }

        return null;
    }

    /**
     * Track a failed attempt and return total count.
     */
    protected function trackAttempt( string $cacheKey, ?string $ip = null ): int
    {
        $data = Cache::get( $cacheKey, ['count' => 0, 'timestamps' => [], 'ips' => []] );

        $data['count']++;
        $data['timestamps'][] = now()->timestamp;

        if ( $ip && ! in_array( $ip, $data['ips'], true ) ) {
            $data['ips'][] = $ip;
        }

        // Clean old timestamps outside window
        $cutoff             = now()->subMinutes( $this->config['time_window_minutes'] )->timestamp;
        $data['timestamps'] = array_filter( $data['timestamps'], fn ( $ts ) => $ts >= $cutoff );
        $data['count']      = count( $data['timestamps'] );

        Cache::put( $cacheKey, $data, now()->addMinutes( $this->config['time_window_minutes'] ) );

        return $data['count'];
    }

    /**
     * Calculate attempts velocity (per minute).
     */
    protected function calculateVelocity( string $cacheKey ): float
    {
        $data       = Cache::get( $cacheKey, ['timestamps' => []] );
        $timestamps = $data['timestamps'];

        if ( count( $timestamps ) < 2 ) {
            return 0.0;
        }

        $timeSpan = max( $timestamps ) - min( $timestamps );

        if ( $timeSpan <= 0 ) {
            return count( $timestamps ); // All in same second
        }

        return count( $timestamps ) / ( $timeSpan / 60 );
    }

    /**
     * Get targets from a specific IP.
     *
     * @return array<int, string>
     */
    protected function getTargetsFromIp( string $ip ): array
    {
        $cacheKey = "brute_force:ip_targets:{$ip}";

        return Cache::get( $cacheKey, [] );
    }

    /**
     * Get source IPs for a target.
     *
     * @return array<int, string>
     */
    protected function getSourceIps( string $cacheKey ): array
    {
        $data = Cache::get( $cacheKey, ['ips' => []] );

        return $data['ips'];
    }
}
