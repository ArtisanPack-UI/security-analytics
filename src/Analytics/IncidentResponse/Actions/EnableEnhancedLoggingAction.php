<?php

declare( strict_types=1 );

namespace ArtisanPackUI\SecurityAnalytics\Analytics\IncidentResponse\Actions;

use ArtisanPackUI\SecurityAnalytics\Models\Anomaly;
use ArtisanPackUI\SecurityAnalytics\Models\SecurityIncident;
use Illuminate\Support\Facades\Cache;

class EnableEnhancedLoggingAction extends AbstractAction
{
    /**
     * {@inheritdoc}
     */
    public function getName(): string
    {
        return 'enable_enhanced_logging';
    }

    /**
     * {@inheritdoc}
     */
    public function execute( Anomaly $anomaly, ?SecurityIncident $incident = null, array $config = [] ): array
    {
        $userId   = $config['user_id'] ?? $anomaly->user_id;
        $ip       = $config['ip'] ?? $this->getIpFromAnomaly( $anomaly );
        $duration = (int) ( $config['duration_hours'] ?? 24 );
        $logLevel = $config['log_level'] ?? 'debug';
        $reason   = $config['reason'] ?? $anomaly->description;

        $targets = [];

        // Enable enhanced logging for user
        if ( $userId ) {
            $this->enableForUser( $userId, $duration, $logLevel, $reason, $anomaly->id, $incident?->id );
            $targets[] = "user:{$userId}";
        }

        // Enable enhanced logging for IP
        if ( $ip ) {
            $this->enableForIp( $ip, $duration, $logLevel, $reason, $anomaly->id, $incident?->id );
            $targets[] = "ip:{$ip}";
        }

        if ( empty( $targets ) ) {
            return $this->failure( 'No user or IP to enable enhanced logging for' );
        }

        // Add to incident if available
        if ( $incident ) {
            if ( $userId ) {
                $incident->addAffectedUser( $userId );
            }
            if ( $ip ) {
                $incident->addAffectedIp( $ip );
            }
            $this->logToIncident( $incident, [
                'targets'        => $targets,
                'duration_hours' => $duration,
                'log_level'      => $logLevel,
                'reason'         => $reason,
            ] );
        }

        return $this->success( 'Enhanced logging enabled for ' . implode( ', ', $targets ), [
            'targets'        => $targets,
            'duration_hours' => $duration,
            'log_level'      => $logLevel,
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

        if ( isset( $config['log_level'] ) && ! in_array( $config['log_level'], ['debug', 'info', 'warning'], true ) ) {
            $errors[] = 'Invalid log level. Must be: debug, info, or warning';
        }

        if ( isset( $config['duration_hours'] ) && ( ! is_numeric( $config['duration_hours'] ) || $config['duration_hours'] < 1 ) ) {
            $errors[] = 'Duration must be at least 1 hour';
        }

        return $errors;
    }

    /**
     * Check if enhanced logging is enabled for a user.
     */
    public static function isEnabledForUser( int $userId ): bool
    {
        return Cache::has( "enhanced_logging:user:{$userId}" );
    }

    /**
     * Check if enhanced logging is enabled for an IP.
     */
    public static function isEnabledForIp( string $ip ): bool
    {
        return Cache::has( "enhanced_logging:ip:{$ip}" );
    }

    /**
     * Get enhanced logging config for user.
     *
     * @return array<string, mixed>|null
     */
    public static function getConfigForUser( int $userId ): ?array
    {
        return Cache::get( "enhanced_logging:user:{$userId}" );
    }

    /**
     * Get enhanced logging config for IP.
     *
     * @return array<string, mixed>|null
     */
    public static function getConfigForIp( string $ip ): ?array
    {
        return Cache::get( "enhanced_logging:ip:{$ip}" );
    }

    /**
     * Disable enhanced logging for user.
     */
    public static function disableForUser( int $userId ): bool
    {
        return Cache::forget( "enhanced_logging:user:{$userId}" );
    }

    /**
     * Disable enhanced logging for IP.
     */
    public static function disableForIp( string $ip ): bool
    {
        return Cache::forget( "enhanced_logging:ip:{$ip}" );
    }

    /**
     * Enable enhanced logging for a user.
     */
    protected function enableForUser(
        int $userId,
        int $duration,
        string $logLevel,
        string $reason,
        int $anomalyId,
        ?int $incidentId,
    ): void {
        $cacheKey = "enhanced_logging:user:{$userId}";
        Cache::put( $cacheKey, [
            'log_level'   => $logLevel,
            'reason'      => $reason,
            'anomaly_id'  => $anomalyId,
            'incident_id' => $incidentId,
            'enabled_at'  => now()->toIso8601String(),
            'expires_at'  => now()->addHours( $duration )->toIso8601String(),
        ], now()->addHours( $duration ) );
    }

    /**
     * Enable enhanced logging for an IP.
     */
    protected function enableForIp(
        string $ip,
        int $duration,
        string $logLevel,
        string $reason,
        int $anomalyId,
        ?int $incidentId,
    ): void {
        $cacheKey = "enhanced_logging:ip:{$ip}";
        Cache::put( $cacheKey, [
            'log_level'   => $logLevel,
            'reason'      => $reason,
            'anomaly_id'  => $anomalyId,
            'incident_id' => $incidentId,
            'enabled_at'  => now()->toIso8601String(),
            'expires_at'  => now()->addHours( $duration)->toIso8601String(),
        ], now()->addHours( $duration));
    }
}
