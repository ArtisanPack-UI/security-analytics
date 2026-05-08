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

        // Track by IP
        $ipKey  = "credential_stuffing:ip:{$ip}";
        $ipData = Cache::get( $ipKey, [
            'users'      => [],
            'attempts'   => 0,
            'successes'  => 0,
            'timestamps' => [],
        ] );

        if ( ! in_array( $username, $ipData['users'], true ) ) {
            $ipData['users'][] = $username;
        }

        $ipData['attempts']++;
        if ( $success ) {
            $ipData['successes']++;
        }
        $ipData['timestamps'][] = now()->timestamp;

        Cache::put( $ipKey, $ipData, now()->addMinutes( $this->config['time_window_minutes'] ) );

        // Track global stats
        $globalKey  = 'credential_stuffing:global';
        $globalData = Cache::get( $globalKey, [
            'attempts'   => 0,
            'successes'  => 0,
            'unique_ips' => [],
        ] );

        $globalData['attempts']++;
        if ( $success ) {
            $globalData['successes']++;
        }
        if ( ! in_array( $ip, $globalData['unique_ips'], true ) ) {
            $globalData['unique_ips'][] = $ip;
        }

        Cache::put( $globalKey, $globalData, now()->addMinutes( $this->config['time_window_minutes'] ) );
    }

    /**
     * Check for credential stuffing from specific IP.
     *
     * @param  array<string, mixed>  $data
     */
    protected function checkCredentialStuffing( string $ip, array $data ): ?Anomaly
    {
        $ipKey  = "credential_stuffing:ip:{$ip}";
        $ipData = Cache::get( $ipKey );

        if ( ! $ipData || $ipData['attempts'] < $this->config['min_attempts_for_analysis'] ) {
            return null;
        }

        $uniqueUsers = count( $ipData['users'] );
        $attempts    = $ipData['attempts'];
        $successes   = $ipData['successes'];
        $successRate = $attempts > 0 ? $successes / $attempts : 0;

        // Pattern 1: Many different users from single IP
        $isMultiUser = $uniqueUsers >= $this->config['unique_users_threshold'];

        // Pattern 2: Very low success rate (typical of stuffing)
        $isLowSuccessRate = $successRate <= $this->config['success_rate_threshold'];

        // Pattern 3: High velocity
        $velocity       = $this->calculateVelocity( $ipData['timestamps'] );
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
        $globalKey  = 'credential_stuffing:global';
        $globalData = Cache::get( $globalKey );

        if ( ! $globalData || $globalData['attempts'] < $this->config['min_attempts_for_analysis'] * 5 ) {
            return null;
        }

        $successRate = $globalData['attempts'] > 0
            ? $globalData['successes'] / $globalData['attempts']
            : 0;

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
                        'total_attempts'        => $globalData['attempts'],
                        'unique_source_ips'     => count( $globalData['unique_ips'] ),
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

        $timeSpan = max( $timestamps) - min( $timestamps);

        if ( $timeSpan <= 0) {
            return count( $timestamps);
        }

        return count( $timestamps) / ( $timeSpan / 60);
    }
}
