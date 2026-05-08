<?php

declare( strict_types=1 );

namespace ArtisanPackUI\SecurityAnalytics\Analytics\AnomalyDetection\Detectors;

use ArtisanPackUI\SecurityAnalytics\Models\Anomaly;
use Illuminate\Support\Collection;
use Illuminate\Support\Facades\Cache;

class RuleBasedDetector extends AbstractDetector
{
    /**
     * {@inheritdoc}
     */
    public function getName(): string
    {
        return 'rule_based';
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

        $rules = $this->config['rules'] ?? $this->getDefaultRules();

        foreach ( $rules as $ruleName => $rule ) {
            if ( $this->ruleMatches( $rule, $data ) ) {
                $anomaly = $this->createAnomalyFromRule( $ruleName, $rule, $data );
                if ( $anomaly ) {
                    $anomalies->push( $anomaly );
                }
            }
        }

        return $anomalies;
    }

    /**
     * Add a custom rule.
     *
     * @param  array<string, mixed>  $rule
     */
    public function addRule( string $name, array $rule ): void
    {
        $this->config['rules'][ $name ] = $rule;
    }

    /**
     * Remove a rule.
     */
    public function removeRule( string $name ): void
    {
        unset( $this->config['rules'][ $name ] );
    }

    /**
     * Track an event for rule evaluation.
     *
     * @param  array<string, mixed>  $data
     */
    public function trackEvent( string $eventType, array $data ): void
    {
        $ip            = $data['ip'] ?? null;
        $userId        = $data['user_id'] ?? null;
        $username      = $data['username'] ?? null;
        $windowMinutes = 15;

        // Track count per IP/user
        if ( $ip || $userId ) {
            $countKey = 'rule_count_' . md5( ( $ip ?? '' ) . ( $userId ?? '' ) );
            // Use Cache::add to initialize with TTL if key doesn't exist, then increment
            Cache::add( $countKey, 0, now()->addMinutes( $windowMinutes ) );
            Cache::increment( $countKey );
        }

        // Track unique usernames per IP
        if ( $ip && $username ) {
            $uniqueKey = 'rule_unique_users_' . md5( $ip );
            $usernames = Cache::get( $uniqueKey, [] );
            if ( ! in_array( $username, $usernames, true ) ) {
                $usernames[] = $username;
                Cache::put( $uniqueKey, $usernames, now()->addMinutes( $windowMinutes ) );
            }
        }
    }

    /**
     * {@inheritdoc}
     */
    protected function getDefaultConfig(): array
    {
        return [
            'enabled' => true,
            'rules'   => $this->getDefaultRules(),
        ];
    }

    /**
     * Get default detection rules.
     *
     * @return array<string, array<string, mixed>>
     */
    protected function getDefaultRules(): array
    {
        return [
            'brute_force_attempt' => [
                'conditions' => [
                    'event_type'          => 'login_failed',
                    'count_threshold'     => 5,
                    'time_window_minutes' => 15,
                ],
                'severity'         => Anomaly::SEVERITY_HIGH,
                'score'            => 85,
                'category'         => Anomaly::CATEGORY_AUTHENTICATION,
                'description'      => 'Potential brute force attack detected',
                'cooldown_minutes' => 30,
            ],
            'credential_stuffing' => [
                'conditions' => [
                    'event_type'                 => 'login_failed',
                    'unique_usernames_threshold' => 10,
                    'time_window_minutes'        => 30,
                ],
                'severity'         => Anomaly::SEVERITY_CRITICAL,
                'score'            => 95,
                'category'         => Anomaly::CATEGORY_AUTHENTICATION,
                'description'      => 'Credential stuffing attack suspected',
                'cooldown_minutes' => 60,
            ],
            'impossible_travel' => [
                'conditions' => [
                    'event_type'        => 'login_success',
                    'max_speed_kmh'     => 800, // Faster than typical flight
                    'min_distance_km'   => 500,
                    'time_window_hours' => 2,
                ],
                'severity'         => Anomaly::SEVERITY_HIGH,
                'score'            => 90,
                'category'         => Anomaly::CATEGORY_BEHAVIORAL,
                'description'      => 'Impossible travel detected between logins',
                'cooldown_minutes' => 120,
            ],
            'privilege_escalation' => [
                'conditions' => [
                    'event_type'      => 'role_change',
                    'escalation_type' => 'admin',
                ],
                'severity'         => Anomaly::SEVERITY_HIGH,
                'score'            => 80,
                'category'         => Anomaly::CATEGORY_ACCESS,
                'description'      => 'Suspicious privilege escalation detected',
                'cooldown_minutes' => 60,
            ],
            'mass_data_access' => [
                'conditions' => [
                    'event_type'          => 'data_access',
                    'records_threshold'   => 1000,
                    'time_window_minutes' => 5,
                ],
                'severity'         => Anomaly::SEVERITY_MEDIUM,
                'score'            => 70,
                'category'         => Anomaly::CATEGORY_DATA,
                'description'      => 'Unusual volume of data access detected',
                'cooldown_minutes' => 30,
            ],
            'off_hours_access' => [
                'conditions' => [
                    'event_type'         => 'login_success',
                    'off_hours'          => true,
                    'sensitive_resource' => true,
                ],
                'severity'         => Anomaly::SEVERITY_MEDIUM,
                'score'            => 60,
                'category'         => Anomaly::CATEGORY_BEHAVIORAL,
                'description'      => 'Sensitive resource accessed during off-hours',
                'cooldown_minutes' => 60,
            ],
            'api_abuse' => [
                'conditions' => [
                    'event_type'          => 'api_request',
                    'requests_threshold'  => 100,
                    'time_window_minutes' => 1,
                ],
                'severity'         => Anomaly::SEVERITY_MEDIUM,
                'score'            => 75,
                'category'         => Anomaly::CATEGORY_THREAT,
                'description'      => 'Potential API abuse detected',
                'cooldown_minutes' => 15,
            ],
            'session_hijacking' => [
                'conditions' => [
                    'event_type'         => 'session_activity',
                    'ip_changed'         => true,
                    'user_agent_changed' => true,
                ],
                'severity'         => Anomaly::SEVERITY_CRITICAL,
                'score'            => 95,
                'category'         => Anomaly::CATEGORY_THREAT,
                'description'      => 'Possible session hijacking detected',
                'cooldown_minutes' => 30,
            ],
            'password_spray' => [
                'conditions' => [
                    'event_type'            => 'login_failed',
                    'unique_passwords_low'  => true, // Same password tried on multiple accounts
                    'unique_usernames_high' => true,
                    'time_window_minutes'   => 60,
                ],
                'severity'         => Anomaly::SEVERITY_CRITICAL,
                'score'            => 90,
                'category'         => Anomaly::CATEGORY_AUTHENTICATION,
                'description'      => 'Password spray attack detected',
                'cooldown_minutes' => 60,
            ],
            'concurrent_sessions' => [
                'conditions' => [
                    'event_type'          => 'login_success',
                    'concurrent_sessions' => 3, // Max allowed concurrent sessions
                    'different_locations' => true,
                ],
                'severity'         => Anomaly::SEVERITY_MEDIUM,
                'score'            => 65,
                'category'         => Anomaly::CATEGORY_BEHAVIORAL,
                'description'      => 'Multiple concurrent sessions from different locations',
                'cooldown_minutes' => 60,
            ],
        ];
    }

    /**
     * Check if a rule matches the given data.
     *
     * @param  array<string, mixed>  $rule
     * @param  array<string, mixed>  $data
     */
    protected function ruleMatches( array $rule, array $data ): bool
    {
        $conditions = $rule['conditions'] ?? [];

        foreach ( $conditions as $field => $expected ) {
            // Skip threshold conditions - they're checked separately
            if ( str_contains( $field, '_threshold' ) || str_contains( $field, '_window' ) ) {
                continue;
            }

            $actual = $data[ $field ] ?? null;

            // Handle special condition types
            if ( 'count_threshold' === $field ) {
                if ( ! $this->checkCountThreshold( $conditions, $data ) ) {
                    return false;
                }
                continue;
            }

            if ( 'unique_usernames_threshold' === $field ) {
                if ( ! $this->checkUniqueUsernamesThreshold( $conditions, $data ) ) {
                    return false;
                }
                continue;
            }

            if ( 'off_hours' === $field ) {
                if ( ! $this->isOffHours( $data ) ) {
                    return false;
                }
                continue;
            }

            // Standard comparison
            if ( is_array( $expected ) ) {
                if ( ! in_array( $actual, $expected, true ) ) {
                    return false;
                }
            } elseif ( $actual !== $expected ) {
                return false;
            }
        }

        return true;
    }

    /**
     * Check count threshold condition.
     *
     * @param  array<string, mixed>  $conditions
     * @param  array<string, mixed>  $data
     */
    protected function checkCountThreshold( array $conditions, array $data ): bool
    {
        $threshold     = $conditions['count_threshold'] ?? 5;
        $windowMinutes = $conditions['time_window_minutes'] ?? 15;
        $eventType     = $conditions['event_type'] ?? 'unknown';

        $ip     = $data['ip'] ?? null;
        $userId = $data['user_id'] ?? null;

        if ( ! $ip && ! $userId ) {
            return false;
        }

        $cacheKey = 'rule_count_' . md5( $eventType . ( $ip ?? '' ) . ( $userId ?? '' ) );
        $count    = (int) Cache::get( $cacheKey, 0 );

        return $count >= $threshold;
    }

    /**
     * Check unique usernames threshold condition.
     *
     * @param  array<string, mixed>  $conditions
     * @param  array<string, mixed>  $data
     */
    protected function checkUniqueUsernamesThreshold( array $conditions, array $data ): bool
    {
        $threshold = $conditions['unique_usernames_threshold'] ?? 10;
        $ip        = $data['ip'] ?? null;

        if ( ! $ip ) {
            return false;
        }

        $cacheKey  = 'rule_unique_users_' . md5( $ip );
        $usernames = Cache::get( $cacheKey, [] );

        return count( $usernames ) >= $threshold;
    }

    /**
     * Check if current time is off-hours.
     *
     * @param  array<string, mixed>  $data
     */
    protected function isOffHours( array $data ): bool
    {
        $hour = (int) ( $data['hour'] ?? now()->hour );

        // Off hours: before 6 AM or after 10 PM
        return $hour < 6 || $hour >= 22;
    }

    /**
     * Create an anomaly from a matched rule.
     *
     * @param  array<string, mixed>  $rule
     * @param  array<string, mixed>  $data
     */
    protected function createAnomalyFromRule( string $ruleName, array $rule, array $data ): ?Anomaly
    {
        $cooldownMinutes = $rule['cooldown_minutes'] ?? 30;
        $suppressKey     = $this->getSuppressKey( $ruleName, $data );

        if ( $this->shouldSuppress( $suppressKey ) ) {
            return null;
        }

        $score = $rule['score'] ?? 75;

        if ( $score < $this->getMinConfidence() ) {
            return null;
        }

        $this->startCooldown( $suppressKey, $cooldownMinutes );

        return $this->createAnomaly(
            $rule['category'] ?? Anomaly::CATEGORY_THREAT,
            $rule['description'] ?? "Rule '{$ruleName}' triggered",
            $rule['severity'] ?? Anomaly::SEVERITY_MEDIUM,
            (float) $score,
            [
                'rule'         => $ruleName,
                'conditions'   => $rule['conditions'] ?? [],
                'matched_data' => $this->sanitizeDataForLog( $data ),
            ],
            $data['user_id'] ?? null,
        );
    }

    /**
     * Get the suppress key for a rule and data combination.
     *
     * @param  array<string, mixed>  $data
     */
    protected function getSuppressKey( string $ruleName, array $data ): string
    {
        $ip     = $data['ip'] ?? '';
        $userId = $data['user_id'] ?? '';

        return "{$ruleName}_{$ip}_{$userId}";
    }

    /**
     * Sanitize data for logging (remove sensitive fields).
     *
     * @param  array<string, mixed>  $data
     *
     * @return array<string, mixed>
     */
    protected function sanitizeDataForLog( array $data ): array
    {
        $sensitiveFields = ['password', 'token', 'secret', 'key', 'credential'];

        return array_filter( $data, function ( $key ) use ( $sensitiveFields) {
            foreach ( $sensitiveFields as $field) {
                if ( str_contains( strtolower( $key), $field)) {
                    return false;
                }
            }

            return true;
        }, ARRAY_FILTER_USE_KEY);
    }
}
