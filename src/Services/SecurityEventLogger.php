<?php

/**
 * SecurityEventLogger service.
 *
 * @package    ArtisanPack_UI
 * @subpackage SecurityAnalytics
 *
 * @author     Jacob Martella <support@artisanpackui.dev>
 *
 * @since      1.0.0
 */

declare( strict_types=1 );

namespace ArtisanPackUI\SecurityAnalytics\Services;

use ArtisanPackUI\SecurityAnalytics\Contracts\SecurityEventLoggerInterface;
use ArtisanPackUI\SecurityAnalytics\Models\SecurityEvent;
use Illuminate\Support\Collection;
use Illuminate\Support\Facades\Log;

class SecurityEventLogger implements SecurityEventLoggerInterface
{
    /**
     * Log a security event.
     */
    public function log( string $type, string $name, array $data = [], string $severity = 'info' ): ?SecurityEvent
    {
        if ( ! $this->isEnabled() ) {
            return null;
        }

        if ( ! $this->isEventTypeEnabled( $type ) ) {
            return null;
        }

        $request   = request();
        $ipAddress = $request?->ip() ?? '0.0.0.0';

        $eventData = [
            'event_type'  => $type,
            'event_name'  => $name,
            'severity'    => $severity,
            'user_id'     => auth()->id(),
            'ip_address'  => $ipAddress,
            'user_agent'  => $request?->userAgent(),
            'url'         => $request?->getRequestUri(),
            'method'      => $request?->method(),
            'details'     => $data,
            'fingerprint' => SecurityEvent::generateFingerprint( $type, $name, $ipAddress ),
        ];

        $event = null;

        if ( $this->shouldStoreInDatabase() ) {
            $event = SecurityEvent::create( $eventData );
        }

        $this->logToChannel( $type, $name, $severity, $eventData );

        return $event;
    }

    /**
     * Log an authentication event.
     */
    public function authentication( string $event, array $data = [], string $severity = 'info' ): ?SecurityEvent
    {
        return $this->log( SecurityEvent::TYPE_AUTHENTICATION, $event, $data, $severity );
    }

    /**
     * Log an authorization event.
     */
    public function authorization( string $event, array $data = [], string $severity = 'warning' ): ?SecurityEvent
    {
        return $this->log( SecurityEvent::TYPE_AUTHORIZATION, $event, $data, $severity );
    }

    /**
     * Log an API access event.
     */
    public function apiAccess( string $event, array $data = [], string $severity = 'info' ): ?SecurityEvent
    {
        return $this->log( SecurityEvent::TYPE_API_ACCESS, $event, $data, $severity );
    }

    /**
     * Log a security violation event.
     */
    public function securityViolation( string $event, array $data = [], string $severity = 'error' ): ?SecurityEvent
    {
        return $this->log( SecurityEvent::TYPE_SECURITY_VIOLATION, $event, $data, $severity );
    }

    /**
     * Log a role change event.
     */
    public function roleChange( string $event, array $data = [], string $severity = 'info' ): ?SecurityEvent
    {
        return $this->log( SecurityEvent::TYPE_ROLE_CHANGE, $event, $data, $severity );
    }

    /**
     * Log a permission change event.
     */
    public function permissionChange( string $event, array $data = [], string $severity = 'info' ): ?SecurityEvent
    {
        return $this->log( SecurityEvent::TYPE_PERMISSION_CHANGE, $event, $data, $severity );
    }

    /**
     * Log a token management event.
     */
    public function tokenManagement( string $event, array $data = [], string $severity = 'info' ): ?SecurityEvent
    {
        return $this->log( SecurityEvent::TYPE_TOKEN_MANAGEMENT, $event, $data, $severity );
    }

    /**
     * Get recent security events.
     */
    public function getRecentEvents( int $limit = 50 ): Collection
    {
        if ( ! $this->shouldStoreInDatabase() ) {
            return collect();
        }

        return SecurityEvent::query()
            ->latest( 'created_at' )
            ->limit( $limit )
            ->get();
    }

    /**
     * Get events by type.
     */
    public function getEventsByType( string $type, int $limit = 50 ): Collection
    {
        if ( ! $this->shouldStoreInDatabase() ) {
            return collect();
        }

        return SecurityEvent::query()
            ->byType( $type )
            ->latest( 'created_at' )
            ->limit( $limit )
            ->get();
    }

    /**
     * Get event statistics for a given number of days.
     */
    public function getEventStats( int $days = 7 ): array
    {
        if ( ! $this->shouldStoreInDatabase() ) {
            return [
                'total'                 => 0,
                'byType'                => [],
                'bySeverity'            => [],
                'topIps'                => [],
                'topUsers'              => [],
                'failedLogins'          => 0,
                'authorizationFailures' => 0,
            ];
        }

        $startDate = now()->subDays( $days );

        return [
            'total'  => SecurityEvent::where( 'created_at', '>=', $startDate )->count(),
            'byType' => SecurityEvent::where( 'created_at', '>=', $startDate )
                ->selectRaw( 'event_type, COUNT(*) as count' )
                ->groupBy( 'event_type' )
                ->pluck( 'count', 'event_type' )
                ->toArray(),
            'bySeverity' => SecurityEvent::where( 'created_at', '>=', $startDate )
                ->selectRaw( 'severity, COUNT(*) as count' )
                ->groupBy( 'severity' )
                ->pluck( 'count', 'severity' )
                ->toArray(),
            'topIps' => SecurityEvent::where( 'created_at', '>=', $startDate )
                ->selectRaw( 'ip_address, COUNT(*) as count' )
                ->groupBy( 'ip_address' )
                ->orderByDesc( 'count' )
                ->limit( 10 )
                ->pluck( 'count', 'ip_address' )
                ->toArray(),
            'topUsers' => SecurityEvent::where( 'created_at', '>=', $startDate )
                ->whereNotNull( 'user_id' )
                ->selectRaw( 'user_id, COUNT(*) as count' )
                ->groupBy( 'user_id' )
                ->orderByDesc( 'count' )
                ->limit( 10 )
                ->pluck( 'count', 'user_id' )
                ->toArray(),
            'failedLogins' => SecurityEvent::where( 'created_at', '>=', $startDate )
                ->where( 'event_type', SecurityEvent::TYPE_AUTHENTICATION )
                ->where( 'event_name', 'login_failed' )
                ->count(),
            'authorizationFailures' => SecurityEvent::where( 'created_at', '>=', $startDate )
                ->where( 'event_type', SecurityEvent::TYPE_AUTHORIZATION )
                ->count(),
        ];
    }

    /**
     * Detect suspicious activity patterns.
     */
    public function detectSuspiciousActivity(): Collection
    {
        if ( ! $this->shouldStoreInDatabase() ) {
            return collect();
        }

        $suspicious = collect();
        $config     = config( 'artisanpack.security-analytics.suspiciousActivity', [] );

        if ( ! ( $config['enabled'] ?? true ) ) {
            return $suspicious;
        }

        $windowMinutes = $config['windowMinutes'] ?? 15;
        $thresholds    = $config['thresholds'] ?? [];
        $startTime     = now()->subMinutes( $windowMinutes );

        // Check failed logins per IP
        $failedLoginsPerIp = $thresholds['failedLoginsPerIp'] ?? 5;
        $suspiciousIps     = SecurityEvent::where( 'event_name', 'login_failed' )
            ->where( 'created_at', '>=', $startTime )
            ->selectRaw( 'ip_address, COUNT(*) as count' )
            ->groupBy( 'ip_address' )
            ->having( 'count', '>=', $failedLoginsPerIp )
            ->get();

        foreach ( $suspiciousIps as $ip ) {
            $suspicious->push( [
                'type'           => 'failed_logins_per_ip',
                'ip_address'     => $ip->ip_address,
                'count'          => $ip->count,
                'threshold'      => $failedLoginsPerIp,
                'window_minutes' => $windowMinutes,
            ] );
        }

        // Check failed logins per user
        $failedLoginsPerUser = $thresholds['failedLoginsPerUser'] ?? 3;
        $suspiciousUsers     = SecurityEvent::where( 'event_name', 'login_failed' )
            ->where( 'created_at', '>=', $startTime )
            ->whereNotNull( 'user_id' )
            ->selectRaw( 'user_id, COUNT(*) as count' )
            ->groupBy( 'user_id' )
            ->having( 'count', '>=', $failedLoginsPerUser )
            ->get();

        foreach ( $suspiciousUsers as $user ) {
            $suspicious->push( [
                'type'           => 'failed_logins_per_user',
                'user_id'        => $user->user_id,
                'count'          => $user->count,
                'threshold'      => $failedLoginsPerUser,
                'window_minutes' => $windowMinutes,
            ] );
        }

        // Check permission denials per user
        $permissionDenialsPerUser  = $thresholds['permissionDenialsPerUser'] ?? 5;
        $suspiciousPermissionUsers = SecurityEvent::where( 'event_type', SecurityEvent::TYPE_AUTHORIZATION )
            ->where( 'created_at', '>=', $startTime )
            ->whereNotNull( 'user_id' )
            ->selectRaw( 'user_id, COUNT(*) as count' )
            ->groupBy( 'user_id' )
            ->having( 'count', '>=', $permissionDenialsPerUser )
            ->get();

        foreach ( $suspiciousPermissionUsers as $user ) {
            $suspicious->push( [
                'type'           => 'permission_denials_per_user',
                'user_id'        => $user->user_id,
                'count'          => $user->count,
                'threshold'      => $permissionDenialsPerUser,
                'window_minutes' => $windowMinutes,
            ] );
        }

        return $suspicious;
    }

    /**
     * Prune old events based on retention policy.
     *
     * @param int|null $days Number of days to retain events (uses config default if null)
     * @param bool|null $keepCritical Whether to keep critical severity events (uses config default if null)
     */
    public function pruneOldEvents( ?int $days = null, ?bool $keepCritical = null ): int
    {
        if ( ! $this->shouldStoreInDatabase() ) {
            return 0;
        }

        $retentionDays      = $days ?? config( 'artisanpack.security-analytics.retention.days', 90 );
        $shouldKeepCritical = $keepCritical ?? config( 'artisanpack.security-analytics.retention.keepCritical', true );

        $query = SecurityEvent::where( 'created_at', '<', now()->subDays( $retentionDays ) );

        if ( $shouldKeepCritical ) {
            $query->where( 'severity', '!=', SecurityEvent::SEVERITY_CRITICAL );
        }

        return $query->delete();
    }

    /**
     * Check if event logging is enabled.
     */
    protected function isEnabled(): bool
    {
        return config( 'artisanpack.security-analytics.enabled', true );
    }

    /**
     * Check if a specific event type is enabled.
     */
    protected function isEventTypeEnabled( string $type ): bool
    {
        $typeKey = match ( $type ) {
            SecurityEvent::TYPE_AUTHENTICATION     => 'authentication',
            SecurityEvent::TYPE_AUTHORIZATION      => 'authorization',
            SecurityEvent::TYPE_API_ACCESS         => 'apiAccess',
            SecurityEvent::TYPE_SECURITY_VIOLATION => 'securityViolations',
            SecurityEvent::TYPE_ROLE_CHANGE        => 'roleChanges',
            SecurityEvent::TYPE_PERMISSION_CHANGE  => 'permissionChanges',
            SecurityEvent::TYPE_TOKEN_MANAGEMENT   => 'tokenManagement',
            default                                => null,
        };

        if ( null === $typeKey ) {
            return true;
        }

        return config( "artisanpack.security-analytics.events.{$typeKey}.enabled", true );
    }

    /**
     * Check if events should be stored in the database.
     */
    protected function shouldStoreInDatabase(): bool
    {
        return config( 'artisanpack.security-analytics.storage.database', true );
    }

    /**
     * Log event to the configured log channel.
     */
    protected function logToChannel( string $type, string $name, string $severity, array $data ): void
    {
        $channel = config( 'artisanpack.security-analytics.storage.logChannel' );

        $logMethod = match ( $severity ) {
            SecurityEvent::SEVERITY_DEBUG    => 'debug',
            SecurityEvent::SEVERITY_INFO     => 'info',
            SecurityEvent::SEVERITY_WARNING  => 'warning',
            SecurityEvent::SEVERITY_ERROR    => 'error',
            SecurityEvent::SEVERITY_CRITICAL => 'critical',
            default                          => 'info',
        };

        $message = "Security Event [{$type}]: {$name}";

        if ( $channel ) {
            Log::channel( $channel )->{$logMethod}( $message, $data );
        } else {
            Log::{$logMethod}( $message, $data);
        }
    }
}
