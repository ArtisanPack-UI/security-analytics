<?php

declare( strict_types=1 );

namespace ArtisanPackUI\SecurityAnalytics\Analytics\AnomalyDetection\Detectors;

use ArtisanPackUI\SecurityAnalytics\Models\Anomaly;
use ArtisanPackUI\SecurityAnalytics\Models\UserBehaviorProfile;
use Illuminate\Support\Collection;

class BehavioralDetector extends AbstractDetector
{
    /**
     * {@inheritdoc}
     */
    public function getName(): string
    {
        return 'behavioral';
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

        // If specific user data is provided, analyze that user
        if ( isset( $data['user_id'] ) ) {
            $anomalies = $anomalies->merge( $this->analyzeUser( (int) $data['user_id'], $data ) );
        }

        // Analyze users with recent activity for deviations
        if ( ! isset( $data['skip_batch_analysis'] ) ) {
            $anomalies = $anomalies->merge( $this->analyzeBatchBehavior() );
        }

        return $anomalies;
    }

    /**
     * {@inheritdoc}
     */
    protected function getDefaultConfig(): array
    {
        return [
            'enabled'              => true,
            'baseline_period_days' => 30,
            'min_samples'          => 100,
            'deviation_threshold'  => 2.5,
        ];
    }

    /**
     * Analyze a specific user's behavior.
     *
     * @param  array<string, mixed>  $data
     *
     * @return Collection<int, Anomaly>
     */
    protected function analyzeUser( int $userId, array $data ): Collection
    {
        $anomalies = collect();

        // Check login patterns
        if ( isset( $data['login_hour'] ) ) {
            $anomaly = $this->checkLoginTimeAnomaly( $userId, (int) $data['login_hour'] );
            if ( $anomaly ) {
                $anomalies->push( $anomaly );
            }
        }

        // Check location patterns
        if ( isset( $data['country'] ) || isset( $data['ip'] ) ) {
            $anomaly = $this->checkLocationAnomaly( $userId, $data );
            if ( $anomaly ) {
                $anomalies->push( $anomaly );
            }
        }

        // Check device patterns
        if ( isset( $data['user_agent'] ) ) {
            $anomaly = $this->checkDeviceAnomaly( $userId, $data['user_agent'] );
            if ( $anomaly ) {
                $anomalies->push( $anomaly );
            }
        }

        // Check session patterns
        if ( isset( $data['session_duration'] ) ) {
            $anomaly = $this->checkSessionAnomaly( $userId, (float) $data['session_duration'] );
            if ( $anomaly ) {
                $anomalies->push( $anomaly );
            }
        }

        return $anomalies;
    }

    /**
     * Analyze batch behavior for all active users.
     *
     * @return Collection<int, Anomaly>
     */
    protected function analyzeBatchBehavior(): Collection
    {
        $anomalies = collect();

        // Get profiles that have sufficient data
        $profiles = UserBehaviorProfile::where( 'sample_count', '>=', $this->config['min_samples'] )
            ->where( 'confidence_score', '>=', 0.5 )
            ->get();

        foreach ( $profiles as $profile ) {
            $deviation = $this->calculateDeviation( $profile );

            if ( $deviation > $this->config['deviation_threshold'] ) {
                $score = min( 100, ( $deviation / ( $this->config['deviation_threshold'] * 2 ) ) * 100 );

                if ( $score >= $this->getMinConfidence() ) {
                    $suppressKey = "user_{$profile->user_id}_{$profile->profile_type}";

                    if ( ! $this->shouldSuppress( $suppressKey ) ) {
                        $this->startCooldown( $suppressKey, 60 );

                        $anomalies->push( $this->createAnomaly(
                            Anomaly::CATEGORY_BEHAVIORAL,
                            "Unusual {$profile->profile_type} detected for user",
                            $this->determineSeverity( $score ),
                            $score,
                            [
                                'profile_type' => $profile->profile_type,
                                'deviation'    => round( $deviation, 2 ),
                                'baseline'     => $profile->baseline_data,
                            ],
                            $profile->user_id,
                        ) );
                    }
                }
            }
        }

        return $anomalies;
    }

    /**
     * Check for login time anomalies.
     */
    protected function checkLoginTimeAnomaly( int $userId, int $loginHour ): ?Anomaly
    {
        $profile = UserBehaviorProfile::where( 'user_id', $userId )
            ->where( 'profile_type', UserBehaviorProfile::TYPE_LOGIN_PATTERNS )
            ->first();

        if ( ! $profile || $profile->sample_count < $this->config['min_samples'] ) {
            return null;
        }

        $baseline         = $profile->baseline_data ?? [];
        $hourDistribution = $baseline['hour_distribution'] ?? [];

        if ( empty( $hourDistribution ) ) {
            return null;
        }

        // Calculate how unusual this hour is
        $hourFrequency = $hourDistribution[ $loginHour ] ?? 0;
        $avgFrequency  = array_sum( $hourDistribution ) / 24;

        if ( 0 == $avgFrequency ) {
            return null;
        }

        $ratio = $hourFrequency / $avgFrequency;

        // If this hour has never or rarely been used, flag it
        if ( $ratio < 0.1 ) {
            $score = ( 1 - $ratio ) * 80; // Max 80 for time-based

            if ( $score >= $this->getMinConfidence() ) {
                $suppressKey = "login_time_user_{$userId}";

                if ( ! $this->shouldSuppress( $suppressKey ) ) {
                    $this->startCooldown( $suppressKey );

                    return $this->createAnomaly(
                        Anomaly::CATEGORY_BEHAVIORAL,
                        "Login at unusual time ({$loginHour}:00)",
                        $this->determineSeverity( $score ),
                        $score,
                        [
                            'login_hour'      => $loginHour,
                            'frequency_ratio' => round( $ratio, 3 ),
                            'typical_hours'   => $this->getTypicalHours( $hourDistribution ),
                        ],
                        $userId,
                    );
                }
            }
        }

        return null;
    }

    /**
     * Check for location anomalies.
     *
     * @param  array<string, mixed>  $data
     */
    protected function checkLocationAnomaly( int $userId, array $data ): ?Anomaly
    {
        $profile = UserBehaviorProfile::where( 'user_id', $userId )
            ->where( 'profile_type', UserBehaviorProfile::TYPE_GEOLOCATION )
            ->first();

        if ( ! $profile || $profile->sample_count < $this->config['min_samples'] ) {
            return null;
        }

        $baseline       = $profile->baseline_data ?? [];
        $knownCountries = $baseline['countries'] ?? [];
        $knownCities    = $baseline['cities'] ?? [];

        $country = $data['country'] ?? null;
        $city    = $data['city'] ?? null;

        // Check if this is a new country
        if ( $country && ! empty( $knownCountries ) && ! in_array( $country, $knownCountries, true ) ) {
            $score       = 85.0; // High score for new country
            $suppressKey = "location_country_user_{$userId}_{$country}";

            if ( ! $this->shouldSuppress( $suppressKey ) ) {
                $this->startCooldown( $suppressKey, 120 ); // 2 hour cooldown for location

                return $this->createAnomaly(
                    Anomaly::CATEGORY_BEHAVIORAL,
                    "Login from new country: {$country}",
                    Anomaly::SEVERITY_HIGH,
                    $score,
                    [
                        'new_country'     => $country,
                        'new_city'        => $city,
                        'known_countries' => $knownCountries,
                        'ip'              => $data['ip'] ?? null,
                    ],
                    $userId,
                );
            }
        }

        return null;
    }

    /**
     * Check for device/user-agent anomalies.
     */
    protected function checkDeviceAnomaly( int $userId, string $userAgent ): ?Anomaly
    {
        $profile = UserBehaviorProfile::where( 'user_id', $userId )
            ->where( 'profile_type', UserBehaviorProfile::TYPE_DEVICE_FINGERPRINTS )
            ->first();

        if ( ! $profile || $profile->sample_count < $this->config['min_samples'] ) {
            return null;
        }

        $baseline    = $profile->baseline_data ?? [];
        $knownAgents = $baseline['user_agents'] ?? [];

        // Normalize user agent for comparison (browser family + version + OS)
        $normalizedAgent = $this->normalizeUserAgent( $userAgent );

        if ( ! empty( $knownAgents ) ) {
            $isKnown = false;
            foreach ( $knownAgents as $knownAgent ) {
                if ( $this->normalizeUserAgent( $knownAgent ) === $normalizedAgent ) {
                    $isKnown = true;
                    break;
                }
            }

            if ( ! $isKnown ) {
                $score       = 65.0; // Medium score for new device
                $suppressKey = "device_user_{$userId}_" . md5( $normalizedAgent );

                if ( ! $this->shouldSuppress( $suppressKey ) ) {
                    $this->startCooldown( $suppressKey, 60 );

                    return $this->createAnomaly(
                        Anomaly::CATEGORY_BEHAVIORAL,
                        'Login from new device/browser',
                        Anomaly::SEVERITY_MEDIUM,
                        $score,
                        [
                            'new_user_agent'      => $userAgent,
                            'known_devices_count' => count( $knownAgents ),
                        ],
                        $userId,
                    );
                }
            }
        }

        return null;
    }

    /**
     * Check for session duration anomalies.
     */
    protected function checkSessionAnomaly( int $userId, float $duration ): ?Anomaly
    {
        $profile = UserBehaviorProfile::where( 'user_id', $userId )
            ->where( 'profile_type', UserBehaviorProfile::TYPE_SESSION_PATTERNS )
            ->first();

        if ( ! $profile || $profile->sample_count < $this->config['min_samples'] ) {
            return null;
        }

        $baseline    = $profile->baseline_data ?? [];
        $avgDuration = $baseline['avg_duration'] ?? 0;
        $stdDev      = $baseline['duration_std_dev'] ?? 0;

        if ( 0 == $avgDuration || 0 == $stdDev ) {
            return null;
        }

        $zScore = $this->zScore( $duration, $avgDuration, $stdDev );

        if ( abs( $zScore ) > $this->config['deviation_threshold'] ) {
            $score = min( 100, ( abs( $zScore ) / ( $this->config['deviation_threshold'] * 2 ) ) * 100 );

            if ( $score >= $this->getMinConfidence() ) {
                $suppressKey = "session_user_{$userId}";

                if ( ! $this->shouldSuppress( $suppressKey ) ) {
                    $this->startCooldown( $suppressKey, 30 );

                    $type = $zScore > 0 ? 'longer' : 'shorter';

                    return $this->createAnomaly(
                        Anomaly::CATEGORY_BEHAVIORAL,
                        "Session duration significantly {$type} than usual",
                        $this->determineSeverity( $score ),
                        $score,
                        [
                            'session_duration' => $duration,
                            'avg_duration'     => round( $avgDuration, 2 ),
                            'z_score'          => round( $zScore, 2 ),
                        ],
                        $userId,
                    );
                }
            }
        }

        return null;
    }

    /**
     * Calculate deviation from baseline.
     */
    protected function calculateDeviation( UserBehaviorProfile $profile ): float
    {
        $baseline = $profile->baseline_data ?? [];
        $current  = $profile->current_data ?? [];

        if ( empty( $baseline ) || empty( $current ) ) {
            return 0.0;
        }

        // Simple deviation calculation based on profile type
        return match ( $profile->profile_type ) {
            UserBehaviorProfile::TYPE_LOGIN_PATTERNS  => $this->calculateLoginDeviation( $baseline, $current ),
            UserBehaviorProfile::TYPE_ACCESS_PATTERNS => $this->calculateAccessDeviation( $baseline, $current ),
            default                                   => 0.0,
        };
    }

    /**
     * Calculate login pattern deviation.
     *
     * @param  array<string, mixed>  $baseline
     * @param  array<string, mixed>  $current
     */
    protected function calculateLoginDeviation( array $baseline, array $current ): float
    {
        $baselineHours = $baseline['hour_distribution'] ?? [];
        $currentHours  = $current['hour_distribution'] ?? [];

        if ( empty( $baselineHours ) || empty( $currentHours ) ) {
            return 0.0;
        }

        // Calculate chi-squared statistic
        $chiSquared = 0.0;
        for ( $h = 0; $h < 24; $h++ ) {
            $expected = $baselineHours[ $h ] ?? 0.001;
            $observed = $currentHours[ $h ] ?? 0;
            $chiSquared += ( ( $observed - $expected ) ** 2 ) / $expected;
        }

        // Normalize to a deviation score
        return sqrt( $chiSquared / 24 );
    }

    /**
     * Calculate access pattern deviation.
     *
     * @param  array<string, mixed>  $baseline
     * @param  array<string, mixed>  $current
     */
    protected function calculateAccessDeviation( array $baseline, array $current ): float
    {
        $baselineFreq = $baseline['resource_frequency'] ?? [];
        $currentFreq  = $current['resource_frequency'] ?? [];

        if ( empty( $baselineFreq ) || empty( $currentFreq ) ) {
            return 0.0;
        }

        // Calculate normalized deviation
        $totalDeviation = 0.0;
        $count          = 0;

        foreach ( $currentFreq as $resource => $freq ) {
            $baselineF = $baselineFreq[ $resource ] ?? 0;
            if ( $baselineF > 0 ) {
                $totalDeviation += abs( $freq - $baselineF ) / $baselineF;
            } else {
                $totalDeviation += 1.0; // New resource
            }
            $count++;
        }

        return $count > 0 ? $totalDeviation / $count : 0.0;
    }

    /**
     * Get typical login hours from distribution.
     *
     * @param  array<int, float>  $distribution
     *
     * @return array<int, int>
     */
    protected function getTypicalHours( array $distribution ): array
    {
        $avg     = array_sum( $distribution ) / 24;
        $typical = [];

        foreach ( $distribution as $hour => $freq ) {
            if ( $freq > $avg ) {
                $typical[] = $hour;
            }
        }

        return $typical;
    }

    /**
     * Normalize user agent string for comparison.
     */
    protected function normalizeUserAgent( string $userAgent ): string
    {
        // Extract browser and OS family for comparison
        $patterns = [
            '/Chrome\/[\d.]+/'  => 'Chrome',
            '/Firefox\/[\d.]+/' => 'Firefox',
            '/Safari\/[\d.]+/'  => 'Safari',
            '/Edge\/[\d.]+/'    => 'Edge',
            '/Windows NT/'      => 'Windows',
            '/Mac OS X/'        => 'MacOS',
            '/Linux/'           => 'Linux',
            '/iPhone|iPad/'     => 'iOS',
            '/Android/'         => 'Android',
        ];

        $normalized = [];
        foreach ( $patterns as $pattern => $name) {
            if ( preg_match( $pattern, $userAgent)) {
                $normalized[] = $name;
            }
        }

        return implode( '|', $normalized);
    }
}
