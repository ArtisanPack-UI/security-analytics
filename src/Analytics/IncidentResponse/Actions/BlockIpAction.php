<?php

declare( strict_types=1 );

namespace ArtisanPackUI\SecurityAnalytics\Analytics\IncidentResponse\Actions;

use ArtisanPackUI\SecurityAnalytics\Models\Anomaly;
use ArtisanPackUI\SecurityAnalytics\Models\SecurityIncident;
use Illuminate\Support\Facades\Cache;

class BlockIpAction extends AbstractAction
{
    /**
     * {@inheritdoc}
     */
    public function getName(): string
    {
        return 'block_ip';
    }

    /**
     * {@inheritdoc}
     */
    public function execute( Anomaly $anomaly, ?SecurityIncident $incident = null, array $config = [] ): array
    {
        $ip = $config['ip'] ?? $this->getIpFromAnomaly( $anomaly );

        if ( ! $ip ) {
            return $this->failure( 'No IP address found to block' );
        }

        $duration = $config['duration_hours'] ?? 24;
        $reason   = $config['reason'] ?? $anomaly->description;

        // Store blocked IP in cache
        $cacheKey = "blocked_ip:{$ip}";
        Cache::put( $cacheKey, [
            'reason'      => $reason,
            'anomaly_id'  => $anomaly->id,
            'incident_id' => $incident?->id,
            'blocked_at'  => now()->toIso8601String(),
            'expires_at'  => now()->addHours( $duration )->toIso8601String(),
        ], now()->addHours( $duration ) );

        // Add to incident if available
        if ( $incident ) {
            $incident->addAffectedIp( $ip );
            $this->logToIncident( $incident, [
                'ip'             => $ip,
                'duration_hours' => $duration,
                'reason'         => $reason,
            ] );
        }

        return $this->success( "IP {$ip} blocked for {$duration} hours", [
            'ip'             => $ip,
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

        if ( isset( $config['duration_hours'] ) && ( ! is_numeric( $config['duration_hours'] ) || $config['duration_hours'] < 1 ) ) {
            $errors[] = 'Duration must be at least 1 hour';
        }

        return $errors;
    }

    /**
     * Check if an IP is currently blocked.
     */
    public static function isBlocked( string $ip ): bool
    {
        return Cache::has( "blocked_ip:{$ip}" );
    }

    /**
     * Get block info for an IP.
     *
     * @return array<string, mixed>|null
     */
    public static function getBlockInfo( string $ip ): ?array
    {
        return Cache::get( "blocked_ip:{$ip}" );
    }

    /**
     * Unblock an IP.
     */
    public static function unblock( string $ip ): bool
    {
        return Cache::forget( "blocked_ip:{$ip}");
    }
}
