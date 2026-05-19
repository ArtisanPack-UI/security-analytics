<?php

/**
 * RateLimitIpAction incident response action.
 *
 * @package    ArtisanPack_UI
 * @subpackage SecurityAnalytics
 *
 * @author     Jacob Martella <support@artisanpackui.dev>
 *
 * @since      1.0.0
 */

declare( strict_types=1 );

namespace ArtisanPackUI\SecurityAnalytics\Analytics\IncidentResponse\Actions;

use ArtisanPackUI\SecurityAnalytics\Models\Anomaly;
use ArtisanPackUI\SecurityAnalytics\Models\SecurityIncident;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\RateLimiter;

class RateLimitIpAction extends AbstractAction
{
    /**
     * {@inheritdoc}
     */
    public function getName(): string
    {
        return 'rate_limit_ip';
    }

    /**
     * {@inheritdoc}
     */
    public function execute( Anomaly $anomaly, ?SecurityIncident $incident = null, array $config = [] ): array
    {
        $ip = $config['ip'] ?? $this->getIpFromAnomaly( $anomaly );

        if ( ! $ip ) {
            return $this->failure( 'No IP address found' );
        }

        $maxAttempts  = $config['max_attempts'] ?? 10;
        $decayMinutes = $config['decay_minutes'] ?? 60;
        $duration     = $config['duration_hours'] ?? 24;
        $reason       = $config['reason'] ?? $anomaly->description;

        // Store enhanced rate limit info
        $cacheKey = "enhanced_rate_limit:{$ip}";
        Cache::put( $cacheKey, [
            'max_attempts'  => $maxAttempts,
            'decay_minutes' => $decayMinutes,
            'reason'        => $reason,
            'anomaly_id'    => $anomaly->id,
            'incident_id'   => $incident?->id,
            'applied_at'    => now()->toIso8601String(),
            'expires_at'    => now()->addHours( $duration )->toIso8601String(),
        ], now()->addHours( $duration ) );

        // Hit the rate limiter to immediately apply limits
        $limiterKey = "security_rate_limit:{$ip}";
        RateLimiter::hit( $limiterKey, $decayMinutes * 60 );

        // Add to incident if available
        if ( $incident ) {
            $incident->addAffectedIp( $ip );
            $this->logToIncident( $incident, [
                'ip'             => $ip,
                'max_attempts'   => $maxAttempts,
                'decay_minutes'  => $decayMinutes,
                'duration_hours' => $duration,
                'reason'         => $reason,
            ] );
        }

        return $this->success( "Rate limit applied to IP {$ip}: {$maxAttempts} requests per {$decayMinutes} minutes", [
            'ip'             => $ip,
            'max_attempts'   => $maxAttempts,
            'decay_minutes'  => $decayMinutes,
            'duration_hours' => $duration,
            'expires_at'     => now()->addHours( $duration )->toIso8601String(),
        ] );
    }

    /**
     * {@inheritdoc}
     */
    public function validate( array $config = [] ): array
    {
        $errors = [];

        if ( isset( $config['ip'] ) && ! filter_var( $config['ip'], FILTER_VALIDATE_IP ) ) {
            $errors[] = 'Invalid IP address format';
        }

        if ( isset( $config['max_attempts'] ) && ( ! is_numeric( $config['max_attempts'] ) || $config['max_attempts'] < 1 ) ) {
            $errors[] = 'Max attempts must be at least 1';
        }

        if ( isset( $config['decay_minutes'] ) && ( ! is_numeric( $config['decay_minutes'] ) || $config['decay_minutes'] < 1 ) ) {
            $errors[] = 'Decay minutes must be at least 1';
        }

        return $errors;
    }

    /**
     * Check if enhanced rate limit is applied to an IP.
     */
    public static function isRateLimited( string $ip ): bool
    {
        return Cache::has( "enhanced_rate_limit:{$ip}" );
    }

    /**
     * Get rate limit info for an IP.
     *
     * @return array<string, mixed>|null
     */
    public static function getRateLimitInfo( string $ip ): ?array
    {
        return Cache::get( "enhanced_rate_limit:{$ip}" );
    }

    /**
     * Check if request should be allowed.
     */
    public static function shouldAllowRequest( string $ip ): bool
    {
        $limitInfo = self::getRateLimitInfo( $ip );

        if ( ! $limitInfo ) {
            return true;
        }

        $limiterKey  = "security_rate_limit:{$ip}";
        $maxAttempts = $limitInfo['max_attempts'] ?? 10;

        return RateLimiter::remaining( $limiterKey, $maxAttempts ) > 0;
    }

    /**
     * Remove rate limit from IP.
     */
    public static function removeRateLimit( string $ip ): bool
    {
        Cache::forget( "enhanced_rate_limit:{$ip}" );
        RateLimiter::clear( "security_rate_limit:{$ip}" );

        return true;
    }
}
