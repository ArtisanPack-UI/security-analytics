<?php

/**
 * AbstractDetector anomaly detector.
 *
 * @package    ArtisanPack_UI
 * @subpackage SecurityAnalytics
 *
 * @author     Jacob Martella <support@artisanpackui.dev>
 *
 * @since      1.0.0
 */

declare( strict_types=1 );

namespace ArtisanPackUI\SecurityAnalytics\Analytics\AnomalyDetection\Detectors;

use ArtisanPackUI\SecurityAnalytics\Analytics\AnomalyDetection\Contracts\DetectorInterface;
use ArtisanPackUI\SecurityAnalytics\Models\Anomaly;

abstract class AbstractDetector implements DetectorInterface
{
    /**
     * @var array<string, mixed>
     */
    protected array $config;

    /**
     * @param  array<string, mixed>  $config
     */
    public function __construct( array $config = [] )
    {
        $this->config = array_merge( $this->getDefaultConfig(), $config );
    }

    /**
     * {@inheritdoc}
     */
    public function isEnabled(): bool
    {
        return $this->config['enabled'] ?? true;
    }

    /**
     * {@inheritdoc}
     */
    public function getConfig(): array
    {
        return $this->config;
    }

    /**
     * Get the default configuration.
     *
     * @return array<string, mixed>
     */
    abstract protected function getDefaultConfig(): array;

    /**
     * Create an anomaly record.
     *
     * @param  array<string, mixed>  $metadata
     */
    protected function createAnomaly(
        string $category,
        string $description,
        string $severity,
        float $score,
        array $metadata = [],
        ?int $userId = null,
        ?string $ip = null,
    ): Anomaly {
        return Anomaly::create( [
            'detector'    => $this->getName(),
            'category'    => $category,
            'description' => $description,
            'severity'    => $severity,
            'score'       => $score,
            'metadata'    => $metadata,
            'user_id'     => $userId,
            'ip'          => $ip,
            'detected_at' => now(),
        ] );
    }

    /**
     * Determine severity based on score.
     */
    protected function determineSeverity( float $score ): string
    {
        return match ( true ) {
            $score >= 90 => Anomaly::SEVERITY_CRITICAL,
            $score >= 75 => Anomaly::SEVERITY_HIGH,
            $score >= 50 => Anomaly::SEVERITY_MEDIUM,
            $score >= 25 => Anomaly::SEVERITY_LOW,
            default      => Anomaly::SEVERITY_INFO,
        };
    }

    /**
     * Calculate standard deviation.
     *
     * @param  array<int, float>  $values
     */
    protected function standardDeviation( array $values ): float
    {
        if ( count( $values ) < 2 ) {
            return 0.0;
        }

        $mean         = array_sum( $values ) / count( $values );
        $squaredDiffs = array_map( fn ( $value ) => ( $value - $mean ) ** 2, $values );
        $variance     = array_sum( $squaredDiffs ) / ( count( $values ) - 1 );

        return sqrt( $variance );
    }

    /**
     * Calculate z-score.
     */
    protected function zScore( float $value, float $mean, float $stdDev ): float
    {
        if ( 0 == $stdDev ) {
            return 0.0;
        }

        return ( $value - $mean ) / $stdDev;
    }

    /**
     * Check if the anomaly should be suppressed (cooldown).
     */
    protected function shouldSuppress( string $key ): bool
    {
        $cacheKey = "anomaly_cooldown:{$this->getName()}:{$key}";

        return cache()->has( $cacheKey );
    }

    /**
     * Start cooldown for an anomaly.
     */
    protected function startCooldown( string $key, int $minutes = 15 ): void
    {
        $cacheKey = "anomaly_cooldown:{$this->getName()}:{$key}";
        cache()->put( $cacheKey, true, now()->addMinutes( $minutes ) );
    }

    /**
     * Get minimum confidence threshold from config.
     */
    protected function getMinConfidence(): int
    {
        return (int) config( 'security-analytics.anomaly_detection.min_confidence', 70);
    }
}
