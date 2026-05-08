<?php

declare( strict_types=1 );

namespace ArtisanPackUI\SecurityAnalytics\Analytics\AnomalyDetection\Detectors;

use ArtisanPackUI\SecurityAnalytics\Models\Anomaly;
use Illuminate\Support\Collection;
use Illuminate\Support\Facades\Cache;

class CredentialStuffingDetector extends AbstractDetector
{
    /**
     * {@inheritdoc}
     */
    public function getName(): string
    {
        return 'credential_stuffing';
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

        // Track authentication attempt
        $this->trackAuthAttempt( $data );

        // Check for credential stuffing patterns
        if ( isset( $data['ip'] ) ) {
            $anomaly = $this->checkCredentialStuffing( $data['ip'], $data );
            if ( $anomaly ) {
                $anomalies->push( $anomaly );
            }
        }

        // Check for low success rate pattern
        $anomaly = $this->checkGlobalSuccessRate();
        if ( $anomaly ) {
            $anomalies->push( $anomaly );
        }

        return $anomalies;
    }

    /**
     * {@inheritdoc}
     */
    protected function getDefaultConfig(): array
    {
        return [
            'enabled'                    => true,
            'unique_users_threshold'     => 10, // Different users from single IP
            'time_window_minutes'        => 30, // Time window
            'success_rate_threshold'     => 0.1, // Low success rate indicates stuffing
            'min_attempts_for_analysis'  => 20, // Minimum attempts to analyze
            'max_success_rate_variation' => 0.2, // Expected success rate variance
        ];
    }

    /**
     * Track an authentication attempt.
     *
     * @param  array<string, mixed>  $data
     */
    protected function trackAuthAttempt( array $data ): void
    {
        $ip       = $data['ip'] ?? 'unknown';
        $username = $data['username'] ?? $data['email'] ?? 'unknown';
        $success  = $data['success'] ?? false;

        $window  = (int) $this->config['time_window_minutes'];
        $cutoff  = now()->subMinutes( $window )->timestamp;
        $nowTs   = now()->timestamp;

        // Track by IP. Stored as per-attempt records (timestamp + username +
        // success) so we can prune anything older than the window on every
        // write — otherwise the blob grows monotonically and "last N
        // minutes" becomes "all time since the cache was warm".
        $ipKey      = "credential_stuffing:ip:{$ip}";
        $ipAttempts = Cache::get( $ipKey, [] );

        $ipAttempts = array_values( array_filter(
            $ipAttempts,
            fn ( array $a ) => ( $a['ts'] ?? 0 ) >= $cutoff,
        ) );
        $ipAttempts[] = [ 'ts' => $nowTs, 'username' => $username, 'success' => (bool) $success ];

        Cache::put( $ipKey, $ipAttempts, now()->addMinutes( $window ) );

        // Track global stats with the same approach: keep a list of
        // {ts, ip, success} records, prune by cutoff on every write.
        $globalKey      = 'credential_stuffing:global';
        $globalAttempts = Cache::get( $globalKey, [] );

        $globalAttempts = array_values( array_filter(
            $globalAttempts,
            fn ( array $a ) => ( $a['ts'] ?? 0 ) >= $cutoff,
        ) );
        $globalAttempts[] = [ 'ts' => $nowTs, 'ip' => $ip, 'success' => (bool) $success ];

        Cache::put( $globalKey, $globalAttempts, now()->addMinutes( $window ) );
    }

    /**
     * Check for credential stuffing from specific IP.
     *
     * @param  array<string, mixed>  $data
     */
    protected function checkCredentialStuffing( string $ip, array $data ): ?Anomaly
    {
        $ipKey      = "credential_stuffing:ip:{$ip}";
        $ipAttempts = Cache::get( $ipKey, [] );

        // Prune anything outside the active window before computing aggregates
        // — match the bucketing applied on the write side in trackAttempt().
        $cutoff     = now()->subMinutes( (int) $this->config['time_window_minutes'] )->timestamp;
        $ipAttempts = array_values( array_filter(
            $ipAttempts,
            fn ( array $a ) => ( $a['ts'] ?? 0 ) >= $cutoff,
        ) );

        if ( count( $ipAttempts ) < $this->config['min_attempts_for_analysis'] ) {
            return null;
        }

        $attempts    = count( $ipAttempts );
        $successes   = count( array_filter( $ipAttempts, fn ( array $a ) => $a['success'] ?? false ) );
        $uniqueUsers = count( array_unique( array_map(
            fn ( array $a ) => $a['username'] ?? null,
            $ipAttempts,
        ) ) );
        $timestamps  = array_map( fn ( array $a ) => $a['ts'] ?? 0, $ipAttempts );
        $successRate = $attempts > 0 ? $successes / $attempts : 0;

        // Pattern 1: Many different users from single IP
        $isMultiUser = $uniqueUsers >= $this->config['unique_users_threshold'];

        // Pattern 2: Very low success rate (typical of stuffing)
        $isLowSuccessRate = $successRate <= $this->config['success_rate_threshold'];

        // Pattern 3: High velocity
        $velocity       = $this->calculateVelocity( $timestamps );
        $isHighVelocity = $velocity > 2; // More than 2 attempts per minute

        if ( $isMultiUser && ( $isLowSuccessRate || $isHighVelocity ) ) {
            $score       = $this->calculateStuffingScore( $uniqueUsers, $successRate, $velocity, $attempts );
            $suppressKey = "credential_stuffing_ip_{$ip}";

            if ( $score >= $this->getMinConfidence() && ! $this->shouldSuppress( $suppressKey ) ) {
                $this->startCooldown( $suppressKey, 30 );

                return $this->createAnomaly(
                    Anomaly::CATEGORY_AUTHENTICATION,
                    "Credential stuffing attack detected from IP: {$ip}",
                    $this->determineSeverity( $score ),
                    $score,
                    [
                        'attack_type'           => 'credential_stuffing',
                        'unique_users_targeted' => $uniqueUsers,
                        'total_attempts'        => $attempts,
                        'successful_logins'     => $successes,
                        'success_rate'          => round( $successRate * 100, 2 ) . '%',
                        'velocity_per_minute'   => round( $velocity, 2 ),
                        'indicators'            => [
                            'multi_user'       => $isMultiUser,
                            'low_success_rate' => $isLowSuccessRate,
                            'high_velocity'    => $isHighVelocity,
                        ],
                        'ip' => $ip,
                    ],
                    null,
                    $ip,
                );
            }
        }

        return null;
    }

    /**
     * Check global authentication success rate for anomalies.
     */
    protected function checkGlobalSuccessRate(): ?Anomaly
    {
        $globalKey      = 'credential_stuffing:global';
        $globalAttempts = Cache::get( $globalKey, [] );

        $cutoff         = now()->subMinutes( (int) $this->config['time_window_minutes'] )->timestamp;
        $globalAttempts = array_values( array_filter(
            $globalAttempts,
            fn ( array $a ) => ( $a['ts'] ?? 0 ) >= $cutoff,
        ) );

        $totalAttempts = count( $globalAttempts );

        if ( $totalAttempts < $this->config['min_attempts_for_analysis'] * 5 ) {
            return null;
        }

        $successes  = count( array_filter( $globalAttempts, fn ( array $a ) => $a['success'] ?? false ) );
        $uniqueIps  = count( array_unique( array_map(
            fn ( array $a ) => $a['ip'] ?? null,
            $globalAttempts,
        ) ) );

        $successRate = $totalAttempts > 0 ? $successes / $totalAttempts : 0;

        $baselineSuccessRate = 0.7; // Typical expected success rate

        // If success rate drops significantly below baseline, might indicate attack
        if ( $successRate < $baselineSuccessRate - $this->config['max_success_rate_variation'] ) {
            $deviation   = $baselineSuccessRate - $successRate;
            $score       = min( 100, ( $deviation / $baselineSuccessRate ) * 100 );
            $suppressKey = 'credential_stuffing_global';

            if ( $score >= $this->getMinConfidence() && ! $this->shouldSuppress( $suppressKey ) ) {
                $this->startCooldown( $suppressKey, 60 );

                return $this->createAnomaly(
                    Anomaly::CATEGORY_AUTHENTICATION,
                    'Unusual authentication failure rate detected - possible widespread credential stuffing',
                    $this->determineSeverity( $score ),
                    $score,
                    [
                        'attack_type'           => 'global_credential_stuffing',
                        'current_success_rate'  => round( $successRate * 100, 2 ) . '%',
                        'expected_success_rate' => round( $baselineSuccessRate * 100, 2 ) . '%',
                        'total_attempts'        => $totalAttempts,
                        'unique_source_ips'     => $uniqueIps,
                    ],
                );
            }
        }

        return null;
    }

    /**
     * Calculate credential stuffing score.
     */
    protected function calculateStuffingScore( int $uniqueUsers, float $successRate, float $velocity, int $attempts ): float
    {
        $score = 0;

        // Score based on unique users
        $userScore = min( 40, ( $uniqueUsers / $this->config['unique_users_threshold'] ) * 40 );
        $score += $userScore;

        // Score based on low success rate
        $successScore = min( 30, ( 1 - $successRate ) * 30 );
        $score += $successScore;

        // Score based on velocity
        $velocityScore = min( 20, ( $velocity / 5 ) * 20 );
        $score += $velocityScore;

        // Score based on total attempts
        $attemptScore = min( 10, ( $attempts / 100 ) * 10 );
        $score += $attemptScore;

        return min( 100, $score );
    }

    /**
     * Calculate attempts velocity.
     *
     * @param  array<int, int>  $timestamps
     */
    protected function calculateVelocity( array $timestamps ): float
    {
        if ( count( $timestamps ) < 2 ) {
            return 0.0;
        }

        $timeSpan = max( $timestamps ) - min( $timestamps );

        if ( $timeSpan <= 0 ) {
            return count( $timestamps );
        }

        return count( $timestamps ) / ( $timeSpan / 60);
    }
}
