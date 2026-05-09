<?php

declare( strict_types=1 );

namespace ArtisanPackUI\SecurityAnalytics\Analytics\AnomalyDetection;

use ArtisanPackUI\SecurityAnalytics\Models\UserBehaviorProfile;

class BaselineManager
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
        $this->config = array_merge( [
            'baseline_period_days'  => 30,
            'min_samples'           => 50,
            'confidence_decay_rate' => 0.1,
        ], $config );
    }

    /**
     * Update login patterns baseline for a user.
     *
     * @param  array<string, mixed>  $data
     */
    public function updateLoginPatterns( int $userId, array $data ): UserBehaviorProfile
    {
        $profile = $this->getOrCreateProfile( $userId, UserBehaviorProfile::TYPE_LOGIN_PATTERNS );

        $baseline       = $profile->baseline_data ?? $this->getDefaultLoginBaseline();
        $loginHour      = $data['hour'] ?? now()->hour;
        $loginDayOfWeek = $data['day_of_week'] ?? now()->dayOfWeek;

        // Update hour distribution
        if ( ! isset( $baseline['hour_distribution'][ $loginHour ] ) ) {
            $baseline['hour_distribution'][ $loginHour ] = 0;
        }
        $baseline['hour_distribution'][ $loginHour ]++;

        // Update day of week distribution
        if ( ! isset( $baseline['day_distribution'][ $loginDayOfWeek ] ) ) {
            $baseline['day_distribution'][ $loginDayOfWeek ] = 0;
        }
        $baseline['day_distribution'][ $loginDayOfWeek ]++;

        // Update session count
        $baseline['total_sessions'] = ( $baseline['total_sessions'] ?? 0 ) + 1;

        // Track login times
        $baseline['last_login']    = now()->toIso8601String();
        $baseline['login_times'][] = now()->toIso8601String();

        // Keep only last 100 login times
        if ( count( $baseline['login_times'] ) > 100 ) {
            $baseline['login_times'] = array_slice( $baseline['login_times'], -100 );
        }

        return $this->updateProfile( $profile, $baseline );
    }

    /**
     * Update geolocation baseline for a user.
     *
     * @param  array<string, mixed>  $data
     */
    public function updateGeolocation( int $userId, array $data ): UserBehaviorProfile
    {
        $profile = $this->getOrCreateProfile( $userId, UserBehaviorProfile::TYPE_GEOLOCATION );

        $baseline = $profile->baseline_data ?? $this->getDefaultGeoBaseline();

        $country = $data['country'] ?? null;
        $city    = $data['city'] ?? null;
        $ip      = $data['ip'] ?? null;

        // Update countries
        if ( $country && ! in_array( $country, $baseline['countries'], true ) ) {
            $baseline['countries'][] = $country;
        }

        // Update cities
        if ( $city && ! in_array( $city, $baseline['cities'], true ) ) {
            $baseline['cities'][] = $city;
        }

        // Update IP addresses (keep last 50)
        if ( $ip && ! in_array( $ip, $baseline['ip_addresses'], true ) ) {
            $baseline['ip_addresses'][] = $ip;
            if ( count( $baseline['ip_addresses'] ) > 50 ) {
                $baseline['ip_addresses'] = array_slice( $baseline['ip_addresses'], -50 );
            }
        }

        // Track location frequency
        if ( $country ) {
            $baseline['country_frequency'][ $country ] = ( $baseline['country_frequency'][ $country ] ?? 0 ) + 1;
        }

        return $this->updateProfile( $profile, $baseline );
    }

    /**
     * Update device fingerprints baseline for a user.
     *
     * @param  array<string, mixed>  $data
     */
    public function updateDeviceFingerprints( int $userId, array $data ): UserBehaviorProfile
    {
        $profile = $this->getOrCreateProfile( $userId, UserBehaviorProfile::TYPE_DEVICE_FINGERPRINTS );

        $baseline = $profile->baseline_data ?? $this->getDefaultDeviceBaseline();

        $userAgent = $data['user_agent'] ?? null;
        $deviceId  = $data['device_id'] ?? null;

        // Update user agents (keep last 20)
        if ( $userAgent && ! in_array( $userAgent, $baseline['user_agents'], true ) ) {
            $baseline['user_agents'][] = $userAgent;
            if ( count( $baseline['user_agents'] ) > 20 ) {
                $baseline['user_agents'] = array_slice( $baseline['user_agents'], -20 );
            }
        }

        // Update device IDs (keep last 10)
        if ( $deviceId && ! in_array( $deviceId, $baseline['device_ids'], true ) ) {
            $baseline['device_ids'][] = $deviceId;
            if ( count( $baseline['device_ids'] ) > 10 ) {
                $baseline['device_ids'] = array_slice( $baseline['device_ids'], -10 );
            }
        }

        // Update user agent frequency
        if ( $userAgent ) {
            $normalized                                      = $this->normalizeUserAgent( $userAgent );
            $baseline['user_agent_frequency'][ $normalized ] = ( $baseline['user_agent_frequency'][ $normalized ] ?? 0 ) + 1;
        }

        return $this->updateProfile( $profile, $baseline );
    }

    /**
     * Update session patterns baseline for a user.
     *
     * @param  array<string, mixed>  $data
     */
    public function updateSessionPatterns( int $userId, array $data ): UserBehaviorProfile
    {
        $profile = $this->getOrCreateProfile( $userId, UserBehaviorProfile::TYPE_SESSION_PATTERNS );

        $baseline = $profile->baseline_data ?? $this->getDefaultSessionBaseline();

        $duration  = $data['duration_minutes'] ?? null;
        $pageViews = $data['page_views'] ?? null;

        // Update duration statistics
        if ( null !== $duration ) {
            $durations   = $baseline['durations'] ?? [];
            $durations[] = $duration;

            // Keep last 100 durations
            if ( count( $durations ) > 100 ) {
                $durations = array_slice( $durations, -100 );
            }

            $baseline['durations']        = $durations;
            $baseline['avg_duration']     = array_sum( $durations ) / count( $durations );
            $baseline['duration_std_dev'] = $this->calculateStdDev( $durations );
            $baseline['max_duration']     = max( $durations );
            $baseline['min_duration']     = min( $durations );
        }

        // Update page view statistics
        if ( null !== $pageViews ) {
            $views   = $baseline['page_views'] ?? [];
            $views[] = $pageViews;

            // Keep last 100
            if ( count( $views ) > 100 ) {
                $views = array_slice( $views, -100 );
            }

            $baseline['page_views']     = $views;
            $baseline['avg_page_views'] = array_sum( $views ) / count( $views );
        }

        return $this->updateProfile( $profile, $baseline );
    }

    /**
     * Update access patterns baseline for a user.
     *
     * @param  array<string, mixed>  $data
     */
    public function updateAccessPatterns( int $userId, array $data ): UserBehaviorProfile
    {
        $profile = $this->getOrCreateProfile( $userId, UserBehaviorProfile::TYPE_ACCESS_PATTERNS );

        $baseline = $profile->baseline_data ?? $this->getDefaultAccessBaseline();

        $resource = $data['resource'] ?? null;
        $action   = $data['action'] ?? null;

        // Update resource frequency
        if ( $resource ) {
            $baseline['resource_frequency'][ $resource ] = ( $baseline['resource_frequency'][ $resource ] ?? 0 ) + 1;
        }

        // Update action frequency
        if ( $action ) {
            $baseline['action_frequency'][ $action ] = ( $baseline['action_frequency'][ $action ] ?? 0 ) + 1;
        }

        // Update resource-action combinations
        if ( $resource && $action ) {
            $key                                           = "{$resource}:{$action}";
            $baseline['resource_action_frequency'][ $key ] = ( $baseline['resource_action_frequency'][ $key ] ?? 0 ) + 1;
        }

        return $this->updateProfile( $profile, $baseline );
    }

    /**
     * Cleanup old profiles that haven't been updated.
     */
    public function cleanupStaleProfiles( int $staleDays = 90 ): int
    {
        return UserBehaviorProfile::where( 'last_updated_at', '<', now()->subDays( $staleDays ) )
            ->delete();
    }

    /**
     * Recalculate confidence scores for all profiles.
     */
    public function recalculateConfidenceScores(): void
    {
        UserBehaviorProfile::chunk( 100, function ( $profiles ): void {
            foreach ( $profiles as $profile ) {
                $profile->confidence_score = $this->calculateConfidence( $profile );
                $profile->save();
            }
        } );
    }

    /**
     * Get a summary of user behavior for risk assessment.
     *
     * @return array<string, mixed>
     */
    public function getUserRiskProfile( int $userId ): array
    {
        $profiles = UserBehaviorProfile::where( 'user_id', $userId )->get();

        $summary = [
            'user_id'            => $userId,
            'profiles'           => [],
            'overall_confidence' => 0,
            'risk_factors'       => [],
        ];

        $totalConfidence = 0;
        $profileCount    = 0;

        foreach ( $profiles as $profile ) {
            $summary['profiles'][ $profile->profile_type ] = [
                'confidence'   => $profile->confidence_score,
                'sample_count' => $profile->sample_count,
                'last_updated' => $profile->last_updated_at?->toIso8601String(),
            ];

            $totalConfidence += $profile->confidence_score;
            $profileCount++;
        }

        if ( $profileCount > 0 ) {
            $summary['overall_confidence'] = round( $totalConfidence / $profileCount, 2 );
        }

        return $summary;
    }

    /**
     * Get or create a user behavior profile.
     */
    protected function getOrCreateProfile( int $userId, string $profileType ): UserBehaviorProfile
    {
        return UserBehaviorProfile::firstOrCreate(
            [
                'user_id'      => $userId,
                'profile_type' => $profileType,
            ],
            [
                'baseline_data'    => [],
                'sample_count'     => 0,
                'confidence_score' => 0.0,
            ],
        );
    }

    /**
     * Update a profile with new baseline data.
     *
     * @param  array<string, mixed>  $baseline
     */
    protected function updateProfile( UserBehaviorProfile $profile, array $baseline ): UserBehaviorProfile
    {
        $profile->baseline_data = $baseline;
        $profile->sample_count++;
        $profile->confidence_score = $this->calculateConfidence( $profile );
        $profile->last_updated_at  = now();
        $profile->save();

        return $profile;
    }

    /**
     * Calculate confidence score based on sample count and age.
     */
    protected function calculateConfidence( UserBehaviorProfile $profile ): float
    {
        $minSamples  = $this->config['min_samples'];
        $sampleCount = $profile->sample_count;

        // Base confidence from sample count (0 to 0.8)
        $sampleConfidence = min( 0.8, ( $sampleCount / $minSamples ) * 0.8 );

        // Age factor - profiles older than baseline period get bonus
        $daysSinceCreation = now()->diffInDays( $profile->created_at );
        $baselinePeriod    = $this->config['baseline_period_days'];
        $ageFactor         = min( 0.2, ( $daysSinceCreation / $baselinePeriod ) * 0.2 );

        return round( $sampleConfidence + $ageFactor, 2 );
    }

    /**
     * Calculate standard deviation.
     *
     * @param  array<int, float>  $values
     */
    protected function calculateStdDev( array $values ): float
    {
        if ( count( $values ) < 2 ) {
            return 0.0;
        }

        $mean         = array_sum( $values ) / count( $values );
        $squaredDiffs = array_map( fn ( $value ) => ( $value - $mean ) ** 2, $values );
        $variance     = array_sum( $squaredDiffs ) / ( count( $values ) - 1 );

        return sqrt( $variance );
    }

    /**
     * Normalize user agent for comparison.
     */
    protected function normalizeUserAgent( string $userAgent ): string
    {
        $patterns = [
            '/Chrome\/[\d.]+/'  => 'Chrome',
            '/Firefox\/[\d.]+/' => 'Firefox',
            '/Safari\/[\d.]+/'  => 'Safari',
            '/Edge\/[\d.]+/'    => 'Edge',
            '/Windows NT/'      => 'Windows',
            '/Mac OS X/'        => 'MacOS',
            '/Linux/'           => 'Linux',
        ];

        $normalized = [];
        foreach ( $patterns as $pattern => $name ) {
            if ( preg_match( $pattern, $userAgent ) ) {
                $normalized[] = $name;
            }
        }

        return implode( '|', $normalized );
    }

    /**
     * Get default login patterns baseline structure.
     *
     * @return array<string, mixed>
     */
    protected function getDefaultLoginBaseline(): array
    {
        return [
            'hour_distribution' => array_fill( 0, 24, 0 ),
            'day_distribution'  => array_fill( 0, 7, 0 ),
            'total_sessions'    => 0,
            'login_times'       => [],
            'last_login'        => null,
        ];
    }

    /**
     * Get default geolocation baseline structure.
     *
     * @return array<string, mixed>
     */
    protected function getDefaultGeoBaseline(): array
    {
        return [
            'countries'         => [],
            'cities'            => [],
            'ip_addresses'      => [],
            'country_frequency' => [],
        ];
    }

    /**
     * Get default device baseline structure.
     *
     * @return array<string, mixed>
     */
    protected function getDefaultDeviceBaseline(): array
    {
        return [
            'user_agents'          => [],
            'device_ids'           => [],
            'user_agent_frequency' => [],
        ];
    }

    /**
     * Get default session baseline structure.
     *
     * @return array<string, mixed>
     */
    protected function getDefaultSessionBaseline(): array
    {
        return [
            'durations'        => [],
            'avg_duration'     => 0,
            'duration_std_dev' => 0,
            'max_duration'     => 0,
            'min_duration'     => 0,
            'page_views'       => [],
            'avg_page_views'   => 0,
        ];
    }

    /**
     * Get default access baseline structure.
     *
     * @return array<string, mixed>
     */
    protected function getDefaultAccessBaseline(): array
    {
        return [
            'resource_frequency'        => [],
            'action_frequency'          => [],
            'resource_action_frequency' => [],
        ];
    }
}
