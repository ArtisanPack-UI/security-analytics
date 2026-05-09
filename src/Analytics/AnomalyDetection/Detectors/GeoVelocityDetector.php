<?php

declare( strict_types=1 );

namespace ArtisanPackUI\SecurityAnalytics\Analytics\AnomalyDetection\Detectors;

use ArtisanPackUI\SecurityAnalytics\Models\Anomaly;
use Illuminate\Support\Collection;
use Illuminate\Support\Facades\Cache;

class GeoVelocityDetector extends AbstractDetector
{
    /**
     * Average earth radius in kilometers.
     */
    protected const EARTH_RADIUS_KM = 6371;

    /**
     * {@inheritdoc}
     */
    public function getName(): string
    {
        return 'geo_velocity';
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

        // Need user_id and location data
        if ( ! isset( $data['user_id'] ) || ! isset( $data['latitude'] ) || ! isset( $data['longitude'] ) ) {
            return $anomalies;
        }

        $userId      = (int) $data['user_id'];
        $currentLat  = (float) $data['latitude'];
        $currentLon  = (float) $data['longitude'];
        $currentTime = $data['timestamp'] ?? now();

        $anomaly = $this->checkImpossibleTravel( $userId, $currentLat, $currentLon, $currentTime, $data );

        if ( $anomaly ) {
            $anomalies->push( $anomaly );
        }

        // Store current location for future checks
        $this->storeUserLocation( $userId, $currentLat, $currentLon, $currentTime );

        return $anomalies;
    }

    /**
     * {@inheritdoc}
     */
    protected function getDefaultConfig(): array
    {
        return [
            'enabled'          => true,
            'max_speed_kmh'    => 1000, // Maximum realistic speed (airplane ~900 km/h)
            'min_distance_km'  => 100, // Minimum distance to consider
            'lookback_minutes' => 60, // How far back to look for previous logins
        ];
    }

    /**
     * Check for impossible travel scenario.
     *
     * @param  mixed  $currentTime
     * @param  array<string, mixed>  $data
     */
    protected function checkImpossibleTravel(
        int $userId,
        float $currentLat,
        float $currentLon,
        $currentTime,
        array $data,
    ): ?Anomaly {
        $previousLocation = $this->getPreviousLocation( $userId );

        if ( ! $previousLocation ) {
            return null;
        }

        $distance = $this->calculateDistance(
            $previousLocation['latitude'],
            $previousLocation['longitude'],
            $currentLat,
            $currentLon,
        );

        // Skip if distance is too small
        if ( $distance < $this->config['min_distance_km'] ) {
            return null;
        }

        $currentTime  = is_string( $currentTime ) ? \Carbon\Carbon::parse( $currentTime ) : $currentTime;
        $previousTime = \Carbon\Carbon::parse( $previousLocation['timestamp'] );

        $timeDiffHours = $previousTime->diffInMinutes( $currentTime ) / 60;

        // Avoid division by zero
        if ( $timeDiffHours < 0.01 ) {
            $timeDiffHours = 0.01;
        }

        $speed = $distance / $timeDiffHours;

        if ( $speed > $this->config['max_speed_kmh'] ) {
            $score       = min( 100, ( $speed / $this->config['max_speed_kmh'] ) * 50 + 50 );
            $suppressKey = "geo_velocity_user_{$userId}";

            if ( ! $this->shouldSuppress( $suppressKey ) ) {
                $this->startCooldown( $suppressKey, 30 );

                return $this->createAnomaly(
                    Anomaly::CATEGORY_BEHAVIORAL,
                    'Impossible travel detected - login from geographically distant location',
                    Anomaly::SEVERITY_HIGH,
                    $score,
                    [
                        'current_location' => [
                            'latitude'  => $currentLat,
                            'longitude' => $currentLon,
                            'country'   => $data['country'] ?? null,
                            'city'      => $data['city'] ?? null,
                        ],
                        'previous_location' => [
                            'latitude'  => $previousLocation['latitude'],
                            'longitude' => $previousLocation['longitude'],
                            'country'   => $previousLocation['country'] ?? null,
                            'city'      => $previousLocation['city'] ?? null,
                        ],
                        'distance_km'           => round( $distance, 2 ),
                        'time_diff_hours'       => round( $timeDiffHours, 2 ),
                        'calculated_speed_kmh'  => round( $speed, 2 ),
                        'max_allowed_speed_kmh' => $this->config['max_speed_kmh'],
                        'ip'                    => $data['ip'] ?? null,
                    ],
                    $userId,
                );
            }
        }

        return null;
    }

    /**
     * Calculate distance between two points using Haversine formula.
     */
    protected function calculateDistance( float $lat1, float $lon1, float $lat2, float $lon2 ): float
    {
        $lat1Rad  = deg2rad( $lat1 );
        $lat2Rad  = deg2rad( $lat2 );
        $deltaLat = deg2rad( $lat2 - $lat1 );
        $deltaLon = deg2rad( $lon2 - $lon1 );

        $a = sin( $deltaLat / 2 ) * sin( $deltaLat / 2 ) +
             cos( $lat1Rad ) * cos( $lat2Rad ) *
             sin( $deltaLon / 2 ) * sin( $deltaLon / 2 );

        $c = 2 * atan2( sqrt( $a ), sqrt( 1 - $a ) );

        return self::EARTH_RADIUS_KM * $c;
    }

    /**
     * Get user's previous location from cache/database.
     *
     * @return array<string, mixed>|null
     */
    protected function getPreviousLocation( int $userId ): ?array
    {
        $cacheKey = "user_location:{$userId}";

        return Cache::get( $cacheKey );
    }

    /**
     * Store user's current location.
     *
     * @param  mixed  $timestamp
     */
    protected function storeUserLocation( int $userId, float $lat, float $lon, $timestamp, array $data = [] ): void
    {
        $cacheKey = "user_location:{$userId}";

        Cache::put( $cacheKey, [
            'latitude'  => $lat,
            'longitude' => $lon,
            'timestamp' => is_string( $timestamp ) ? $timestamp : $timestamp->toIso8601String(),
            'country'   => $data['country'] ?? null,
            'city'      => $data['city'] ?? null,
        ], now()->addMinutes( $this->config['lookback_minutes'] ) );
    }
}
