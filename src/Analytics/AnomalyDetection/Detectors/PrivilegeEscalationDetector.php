<?php

declare( strict_types=1 );

namespace ArtisanPackUI\SecurityAnalytics\Analytics\AnomalyDetection\Detectors;

use ArtisanPackUI\SecurityAnalytics\Models\Anomaly;
use Illuminate\Support\Collection;
use Illuminate\Support\Facades\Cache;

class PrivilegeEscalationDetector extends AbstractDetector
{
    /**
     * {@inheritdoc}
     */
    public function getName(): string
    {
        return 'privilege_escalation';
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

        // Check for unauthorized privilege attempts
        if ( isset( $data['permission'] ) && isset( $data['user_id'] ) ) {
            $anomaly = $this->checkUnauthorizedPermissionAttempt(
                (int) $data['user_id'],
                $data['permission'],
                $data,
            );
            if ( $anomaly ) {
                $anomalies->push( $anomaly );
            }
        }

        // Check for suspicious role changes
        if ( isset( $data['event_type'] ) && 'role_changed' === $data['event_type'] ) {
            $anomaly = $this->checkSuspiciousRoleChange( $data );
            if ( $anomaly ) {
                $anomalies->push( $anomaly );
            }
        }

        // Check for self-role assignment attempts
        if ( isset( $data['event_type'] ) && 'role_assignment_attempted' === $data['event_type'] ) {
            $anomaly = $this->checkSelfRoleAssignment( $data );
            if ( $anomaly ) {
                $anomalies->push( $anomaly );
            }
        }

        // Check for pattern of denied access attempts
        if ( isset( $data['user_id'] ) && isset( $data['access_denied'] ) && $data['access_denied'] ) {
            $anomaly = $this->checkDeniedAccessPattern( (int) $data['user_id'], $data );
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
            'enabled'               => true,
            'sensitive_permissions' => [
                'admin.*',
                'users.delete',
                'users.manage',
                'roles.assign',
                'roles.create',
                'permissions.manage',
                'system.*',
            ],
            'sensitive_roles' => [
                'admin',
                'administrator',
                'super-admin',
                'root',
            ],
            'failed_attempts_threshold' => 3, // Failed attempts to access restricted resources
            'time_window_minutes'       => 15,
        ];
    }

    /**
     * Check for unauthorized permission access attempts.
     *
     * @param  array<string, mixed>  $data
     */
    protected function checkUnauthorizedPermissionAttempt( int $userId, string $permission, array $data ): ?Anomaly
    {
        // Check if this is a sensitive permission
        if ( ! $this->isSensitivePermission( $permission ) ) {
            return null;
        }

        // Track the attempt
        $cacheKey = "privilege_escalation:user:{$userId}";
        $attempts = $this->trackAttempt( $cacheKey, $permission );

        if ( $attempts >= $this->config['failed_attempts_threshold'] ) {
            $score       = min( 100, ( $attempts / $this->config['failed_attempts_threshold'] ) * 60 + 40 );
            $suppressKey = "privilege_escalation_user_{$userId}";

            if ( ! $this->shouldSuppress( $suppressKey ) ) {
                $this->startCooldown( $suppressKey, 30 );

                return $this->createAnomaly(
                    Anomaly::CATEGORY_AUTHORIZATION,
                    'Potential privilege escalation attempt - user repeatedly accessing restricted resources',
                    Anomaly::SEVERITY_HIGH,
                    $score,
                    [
                        'attack_type'           => 'privilege_escalation_attempt',
                        'permission_attempted'  => $permission,
                        'failed_attempts'       => $attempts,
                        'attempted_permissions' => $this->getAttemptedPermissions( $cacheKey ),
                        'ip'                    => $data['ip'] ?? null,
                    ],
                    $userId,
                    $data['ip'] ?? null,
                );
            }
        }

        return null;
    }

    /**
     * Check for suspicious role changes.
     *
     * @param  array<string, mixed>  $data
     */
    protected function checkSuspiciousRoleChange( array $data ): ?Anomaly
    {
        $newRole      = $data['new_role'] ?? null;
        $targetUserId = $data['target_user_id'] ?? null;
        $actorUserId  = $data['actor_user_id'] ?? null;

        if ( ! $newRole || ! $targetUserId ) {
            return null;
        }

        // Check if the new role is a sensitive one
        if ( ! $this->isSensitiveRole( $newRole ) ) {
            return null;
        }

        // Check if this is unusual (first time getting admin role, etc.)
        $isFirstTimeAdmin = $this->isFirstTimeSensitiveRole( $targetUserId, $newRole );

        if ( $isFirstTimeAdmin ) {
            $score       = 70.0;
            $suppressKey = "role_change_user_{$targetUserId}_{$newRole}";

            if ( ! $this->shouldSuppress( $suppressKey ) ) {
                $this->startCooldown( $suppressKey, 120 );

                return $this->createAnomaly(
                    Anomaly::CATEGORY_AUTHORIZATION,
                    "User granted sensitive role: {$newRole}",
                    Anomaly::SEVERITY_MEDIUM,
                    $score,
                    [
                        'event_type'     => 'sensitive_role_granted',
                        'new_role'       => $newRole,
                        'target_user_id' => $targetUserId,
                        'actor_user_id'  => $actorUserId,
                        'first_time'     => true,
                        'ip'             => $data['ip'] ?? null,
                    ],
                    $targetUserId,
                    $data['ip'] ?? null,
                );
            }
        }

        return null;
    }

    /**
     * Check for self-role assignment attempts.
     *
     * @param  array<string, mixed>  $data
     */
    protected function checkSelfRoleAssignment( array $data ): ?Anomaly
    {
        $targetUserId = $data['target_user_id'] ?? null;
        $actorUserId  = $data['actor_user_id'] ?? null;
        $role         = $data['role'] ?? null;

        if ( ! $targetUserId || ! $actorUserId || ! $role ) {
            return null;
        }

        // Check if user is trying to assign role to themselves
        if ( $targetUserId === $actorUserId && $this->isSensitiveRole( $role ) ) {
            $score       = 90.0;
            $suppressKey = "self_role_assignment_user_{$actorUserId}";

            if ( ! $this->shouldSuppress( $suppressKey ) ) {
                $this->startCooldown( $suppressKey, 60 );

                return $this->createAnomaly(
                    Anomaly::CATEGORY_AUTHORIZATION,
                    'Self-privilege escalation attempt - user trying to assign sensitive role to themselves',
                    Anomaly::SEVERITY_CRITICAL,
                    $score,
                    [
                        'attack_type'    => 'self_role_assignment',
                        'role_attempted' => $role,
                        'ip'             => $data['ip'] ?? null,
                    ],
                    $actorUserId,
                    $data['ip'] ?? null,
                );
            }
        }

        return null;
    }

    /**
     * Check for pattern of denied access attempts.
     *
     * @param  array<string, mixed>  $data
     */
    protected function checkDeniedAccessPattern( int $userId, array $data ): ?Anomaly
    {
        $cacheKey = "access_denied:user:{$userId}";

        $deniedAttempts = Cache::get( $cacheKey, [
            'count'      => 0,
            'resources'  => [],
            'timestamps' => [],
        ] );

        $deniedAttempts['count']++;
        $deniedAttempts['timestamps'][] = now()->timestamp;

        if ( isset( $data['resource'] ) ) {
            $deniedAttempts['resources'][] = $data['resource'];
        }

        // Clean old entries
        $cutoff                       = now()->subMinutes( $this->config['time_window_minutes'] )->timestamp;
        $deniedAttempts['timestamps'] = array_filter(
            $deniedAttempts['timestamps'],
            fn ( $ts ) => $ts >= $cutoff,
        );
        $deniedAttempts['count'] = count( $deniedAttempts['timestamps'] );

        Cache::put( $cacheKey, $deniedAttempts, now()->addMinutes( $this->config['time_window_minutes'] ) );

        // Check for suspicious pattern
        if ( $deniedAttempts['count'] >= $this->config['failed_attempts_threshold'] ) {
            $uniqueResources = count( array_unique( $deniedAttempts['resources'] ) );
            $score           = min( 100, ( $deniedAttempts['count'] / $this->config['failed_attempts_threshold'] ) * 40 + ( $uniqueResources * 10 ) );

            $suppressKey = "access_denied_pattern_user_{$userId}";

            if ( $score >= $this->getMinConfidence() && ! $this->shouldSuppress( $suppressKey ) ) {
                $this->startCooldown( $suppressKey, 30 );

                return $this->createAnomaly(
                    Anomaly::CATEGORY_AUTHORIZATION,
                    'Suspicious pattern of access denied - user probing for unauthorized resources',
                    $this->determineSeverity( $score ),
                    $score,
                    [
                        'attack_type'         => 'resource_probing',
                        'denied_attempts'     => $deniedAttempts['count'],
                        'unique_resources'    => $uniqueResources,
                        'resources_attempted' => array_slice( array_unique( $deniedAttempts['resources'] ), 0, 10 ),
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
     * Check if permission is sensitive.
     */
    protected function isSensitivePermission( string $permission ): bool
    {
        foreach ( $this->config['sensitive_permissions'] as $pattern ) {
            if ( str_contains( $pattern, '*' ) ) {
                $regex = '/^' . str_replace( ['*', '.'], ['.*', '\.'], $pattern ) . '$/';
                if ( preg_match( $regex, $permission ) ) {
                    return true;
                }
            } elseif ( $permission === $pattern ) {
                return true;
            }
        }

        return false;
    }

    /**
     * Check if role is sensitive.
     */
    protected function isSensitiveRole( string $role ): bool
    {
        return in_array( strtolower( $role ), array_map( 'strtolower', $this->config['sensitive_roles'] ), true );
    }

    /**
     * Check if this is user's first time getting a sensitive role.
     */
    protected function isFirstTimeSensitiveRole( int $userId, string $role ): bool
    {
        // Check historical role assignments
        $cacheKey      = "user_sensitive_roles:{$userId}";
        $previousRoles = Cache::get( $cacheKey, [] );

        if ( in_array( $role, $previousRoles, true ) ) {
            return false;
        }

        $previousRoles[] = $role;
        Cache::put( $cacheKey, $previousRoles, now()->addDays( 30 ) );

        return true;
    }

    /**
     * Track a failed permission attempt.
     */
    protected function trackAttempt( string $cacheKey, string $permission ): int
    {
        $data = Cache::get( $cacheKey, ['count' => 0, 'permissions' => [], 'timestamps' => []] );

        $data['count']++;
        $data['permissions'][] = $permission;
        $data['timestamps'][]  = now()->timestamp;

        // Clean old entries
        $cutoff             = now()->subMinutes( $this->config['time_window_minutes'] )->timestamp;
        $data['timestamps'] = array_filter( $data['timestamps'], fn ( $ts ) => $ts >= $cutoff );
        $data['count']      = count( $data['timestamps'] );

        Cache::put( $cacheKey, $data, now()->addMinutes( $this->config['time_window_minutes']));

        return $data['count'];
    }

    /**
     * Get list of permissions attempted.
     *
     * @return array<int, string>
     */
    protected function getAttemptedPermissions( string $cacheKey): array
    {
        $data = Cache::get( $cacheKey, ['permissions' => []]);

        return array_unique( $data['permissions']);
    }
}
