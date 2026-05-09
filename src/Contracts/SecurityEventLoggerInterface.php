<?php

declare( strict_types=1 );

namespace ArtisanPackUI\SecurityAnalytics\Contracts;

use ArtisanPackUI\SecurityAnalytics\Models\SecurityEvent;
use Illuminate\Support\Collection;

interface SecurityEventLoggerInterface
{
    /**
     * Log a security event.
     */
    public function log( string $type, string $name, array $data = [], string $severity = 'info' ): ?SecurityEvent;

    /**
     * Log an authentication event.
     */
    public function authentication( string $event, array $data = [], string $severity = 'info' ): ?SecurityEvent;

    /**
     * Log an authorization event.
     */
    public function authorization( string $event, array $data = [], string $severity = 'warning' ): ?SecurityEvent;

    /**
     * Log an API access event.
     */
    public function apiAccess( string $event, array $data = [], string $severity = 'info' ): ?SecurityEvent;

    /**
     * Log a security violation event.
     */
    public function securityViolation( string $event, array $data = [], string $severity = 'error' ): ?SecurityEvent;

    /**
     * Log a role change event.
     */
    public function roleChange( string $event, array $data = [], string $severity = 'info' ): ?SecurityEvent;

    /**
     * Log a permission change event.
     */
    public function permissionChange( string $event, array $data = [], string $severity = 'info' ): ?SecurityEvent;

    /**
     * Log a token management event.
     */
    public function tokenManagement( string $event, array $data = [], string $severity = 'info' ): ?SecurityEvent;

    /**
     * Get recent security events.
     */
    public function getRecentEvents( int $limit = 50 ): Collection;

    /**
     * Get events by type.
     */
    public function getEventsByType( string $type, int $limit = 50 ): Collection;

    /**
     * Get event statistics for a given number of days.
     */
    public function getEventStats( int $days = 7 ): array;

    /**
     * Detect suspicious activity patterns.
     */
    public function detectSuspiciousActivity(): Collection;

    /**
     * Prune old events based on retention policy.
     *
     * @param int|null $days Number of days to retain events (uses config default if null)
     * @param bool|null $keepCritical Whether to keep critical severity events (uses config default if null)
     */
    public function pruneOldEvents( ?int $days = null, ?bool $keepCritical = null): int;
}
