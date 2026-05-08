<?php

declare( strict_types=1 );

namespace ArtisanPackUI\SecurityAnalytics\Authentication\Contracts;

use ArtisanPackUI\SecurityAnalytics\Models\SuspiciousActivity;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Http\Request;

interface SuspiciousActivityDetectorInterface
{
    /**
     * Analyze a request for suspicious activity.
     *
     * @param  array<string, mixed>  $context
     *
     * @return array{suspicious: bool, risk_score: float, detections: array<array{type: string, severity: string, details: array}>}
     */
    public function analyze( Request $request, ?Authenticatable $user = null, array $context = [] ): array;

    /**
     * Record a suspicious activity.
     *
     * @param  array<string, mixed>  $details
     */
    public function record(
        Request $request,
        string $type,
        string $severity,
        float $riskScore,
        array $details,
        ?Authenticatable $user = null,
    ): SuspiciousActivity;

    /**
     * Get the recommended action based on severity.
     *
     * @return string One of: none, captcha, step_up, block, lockout, notify
     */
    public function getRecommendedAction( string $severity ): string;

    /**
     * Check if an IP address is known to be malicious.
     */
    public function isKnownMaliciousIp( string $ipAddress ): bool;

    /**
     * Check if an IP is a Tor exit node.
     */
    public function isTorExitNode( string $ipAddress ): bool;

    /**
     * Check if an IP is from a VPN or proxy.
     */
    public function isProxyOrVpn( string $ipAddress ): bool;

    /**
     * Check if an IP is from a datacenter.
     */
    public function isDatacenterIp( string $ipAddress ): bool;

    /**
     * Detect impossible travel (login from geographically distant locations in short time).
     *
     * @param  array<string, mixed>  $previousLogin
     * @param  array<string, mixed>  $currentLogin
     */
    public function detectImpossibleTravel( array $previousLogin, array $currentLogin ): bool;

    /**
     * Calculate risk score based on multiple factors (0-100 scale).
     *
     * @param  array<array{type: string, severity: string, weight?: int}>  $factors
     */
    public function calculateRiskScore( array $factors ): int;

    /**
     * Get unresolved suspicious activities for a user.
     *
     * @return \Illuminate\Support\Collection<int, SuspiciousActivity>
     */
    public function getUnresolvedActivities( ?Authenticatable $user = null ): \Illuminate\Support\Collection;

    /**
     * Resolve a suspicious activity.
     */
    public function resolve( SuspiciousActivity $activity, ?Authenticatable $resolvedBy = null ): void;

    /**
     * Prune old suspicious activity records.
     */
    public function pruneOldRecords( int $retentionDays): int;
}
