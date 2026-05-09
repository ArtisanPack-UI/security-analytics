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
        $ip       = $data['ip'] ?? null;
        $userId   = $data['user_id'] ?? null;
        $username = $data['username'] ?? null;

        // Use a generous TTL that covers the longest configured rule window
        // — the consumers (checkCountThreshold, checkUniqueUsernamesThreshold)
        // prune by their rule-specific time_window_minutes when reading.
        $maxWindow = $this->maxRuleWindowMinutes();
        $now       = now()->timestamp;

        // Track count per IP/user. Store timestamps (not a raw counter) so
        // readers can re-aggregate against any rule window. Key includes
        // $eventType so it matches checkCountThreshold's read key.
        if ( $ip || $userId ) {
            $countKey     = 'rule_count_' . md5( $eventType . ( $ip ?? '' ) . ( $userId ?? '' ) );
            $timestamps   = Cache::get( $countKey, [] );
            $cutoff       = now()->subMinutes( $maxWindow )->timestamp;
            $timestamps   = array_values( array_filter( $timestamps, fn ( $ts ) => $ts >= $cutoff ) );
            $timestamps[] = $now;
            Cache::put( $countKey, $timestamps, now()->addMinutes( $maxWindow ) );
        }

        // Track unique usernames per IP. Same approach: store {username, ts}
        // tuples and prune on the read side.
        if ( $ip && $username ) {
            $uniqueKey = 'rule_unique_users_' . md5( $ip );
            $entries   = Cache::get( $uniqueKey, [] );
            $cutoff    = now()->subMinutes( $maxWindow )->timestamp;
            $entries   = array_values( array_filter(
                $entries,
                fn ( array $e ) => ( $e['ts'] ?? 0 ) >= $cutoff,
            ) );
            $entries[] = [ 'username' => $username, 'ts' => $now ];
            Cache::put( $uniqueKey, $entries, now()->addMinutes( $maxWindow ) );
        }
    }

    /**
     * Highest `time_window_minutes` across all configured rules. Used as
     * the cache TTL for tracking entries.
     */
    protected function maxRuleWindowMinutes(): int
    {
        $rules = $this->config['rules'] ?? $this->getDefaultRules();
        $max   = 15;

        foreach ( $rules as $rule ) {
            $window = $rule['conditions']['time_window_minutes'] ?? null;
            if ( is_int( $window ) && $window > $max ) {
                $max = $window;
            }
        }

        return $max;
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
            // Handle special condition types FIRST — these are aggregate
            // checks against the conditions+data tuple rather than per-field
            // equality, so they have to run before the generic skip below.
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

            // Skip only the explicit ancillary fields that the aggregate
            // checks consume (windows, distance/speed parameters). A blanket
            // *_threshold substring check used to here let *_threshold rules
            // like `records_threshold` and `requests_threshold` fall through
            // unchecked, which made `mass_data_access` and `api_abuse`
            // match on event_type alone and emit anomalies for every event.
            $ancillary = [
                'time_window_minutes',
                'time_window_hours',
                'max_speed_kmh',
                'min_distance_km',
            ];
            if ( in_array( $field, $ancillary, true ) ) {
                continue;
            }

            $actual = $data[ $field ] ?? null;

            // Numeric *_threshold conditions (records_threshold,
            // requests_threshold, etc.) are evaluated against the data
            // field that drops the `_threshold` suffix.
            if ( str_ends_with( $field, '_threshold' ) ) {
                $dataField = substr( $field, 0, -strlen( '_threshold' ) );
                $value     = $data[ $dataField ] ?? null;
                if ( ! is_numeric( $value ) || (float) $value < (float) $expected ) {
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

        $cacheKey   = 'rule_count_' . md5( $eventType . ( $ip ?? '' ) . ( $userId ?? '' ) );
        $timestamps = Cache::get( $cacheKey, [] );

        // The writer stores a list of timestamps; re-bucket against this
        // rule's specific window so longer/shorter windows count correctly.
        $cutoff = now()->subMinutes( (int) $windowMinutes )->timestamp;
        $count  = count( array_filter( $timestamps, fn ( $ts ) => $ts >= $cutoff ) );

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
        $threshold     = $conditions['unique_usernames_threshold'] ?? 10;
        $windowMinutes = $conditions['time_window_minutes'] ?? 15;
        $ip            = $data['ip'] ?? null;

        if ( ! $ip ) {
            return false;
        }

        $cacheKey = 'rule_unique_users_' . md5( $ip );
        $entries  = Cache::get( $cacheKey, [] );

        // Prune to the rule window before counting unique users. Without
        // this filter the cache blob grows unbounded and arbitrarily-old
        // attempts get mixed into "last N minutes" counts.
        $cutoff   = now()->subMinutes( (int) $windowMinutes )->timestamp;
        $unique   = array_unique( array_map(
            fn ( array $e ) => $e['username'] ?? null,
            array_filter( $entries, fn ( array $e ) => ( $e['ts'] ?? 0 ) >= $cutoff ),
        ) );

        return count( $unique ) >= $threshold;
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

        return array_filter( $data, function ( $key ) use ( $sensitiveFields ) {
            foreach ( $sensitiveFields as $field ) {
                if ( str_contains( strtolower( $key ), $field ) ) {
                    return false;
                }
            }

            return true;
        }, ARRAY_FILTER_USE_KEY);
    }
}
