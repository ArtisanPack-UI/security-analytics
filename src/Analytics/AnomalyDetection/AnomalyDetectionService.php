<?php

/**
 * AnomalyDetectionService anomaly detection service.
 *
 * @package    ArtisanPack_UI
 * @subpackage SecurityAnalytics
 *
 * @author     Jacob Martella <support@artisanpackui.dev>
 *
 * @since      1.0.0
 */

declare( strict_types=1 );

namespace ArtisanPackUI\SecurityAnalytics\Analytics\AnomalyDetection;

use ArtisanPackUI\SecurityAnalytics\Analytics\AnomalyDetection\Contracts\DetectorInterface;
use ArtisanPackUI\SecurityAnalytics\Analytics\AnomalyDetection\Detectors\BehavioralDetector;
use ArtisanPackUI\SecurityAnalytics\Analytics\AnomalyDetection\Detectors\RuleBasedDetector;
use ArtisanPackUI\SecurityAnalytics\Analytics\AnomalyDetection\Detectors\StatisticalDetector;
use ArtisanPackUI\SecurityAnalytics\Events\AnomalyDetected;
use ArtisanPackUI\SecurityAnalytics\Models\Anomaly;
use Illuminate\Support\Collection;

class AnomalyDetectionService
{
    /**
     * @var array<string, DetectorInterface>
     */
    protected array $detectors = [];

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
        $this->registerDefaultDetectors();
    }

    /**
     * Register a detector.
     */
    public function registerDetector( DetectorInterface $detector ): self
    {
        $this->detectors[ $detector->getName() ] = $detector;

        return $this;
    }

    /**
     * Remove a detector.
     */
    public function removeDetector( string $name ): self
    {
        unset( $this->detectors[ $name ] );

        return $this;
    }

    /**
     * Get a registered detector.
     */
    public function getDetector( string $name ): ?DetectorInterface
    {
        return $this->detectors[ $name ] ?? null;
    }

    /**
     * Get all registered detectors.
     *
     * @return array<string, DetectorInterface>
     */
    public function getDetectors(): array
    {
        return $this->detectors;
    }

    /**
     * Run all detectors and collect anomalies.
     *
     * @param  array<string, mixed>  $data
     *
     * @return Collection<int, Anomaly>
     */
    public function detect( array $data = [] ): Collection
    {
        if ( ! $this->isEnabled() ) {
            return collect();
        }

        $anomalies = collect();

        foreach ( $this->detectors as $detector ) {
            if ( $detector->isEnabled() ) {
                $detected  = $detector->detect( $data );
                $anomalies = $anomalies->merge( $detected );
            }
        }

        // Dispatch events for each anomaly
        if ( $this->config['dispatch_events'] ) {
            $this->dispatchAnomalyEvents( $anomalies );
        }

        return $anomalies;
    }

    /**
     * Run a specific detector.
     *
     * @param  array<string, mixed>  $data
     *
     * @return Collection<int, Anomaly>
     */
    public function detectWith( string $detectorName, array $data = [] ): Collection
    {
        $detector = $this->getDetector( $detectorName );

        if ( ! $detector || ! $detector->isEnabled() ) {
            return collect();
        }

        $anomalies = $detector->detect( $data );

        if ( $this->config['dispatch_events'] ) {
            $this->dispatchAnomalyEvents( $anomalies );
        }

        return $anomalies;
    }

    /**
     * Analyze a specific user's behavior for anomalies.
     *
     * @param  array<string, mixed>  $context
     *
     * @return Collection<int, Anomaly>
     */
    public function analyzeUser( int $userId, array $context = [] ): Collection
    {
        $data = array_merge( ['user_id' => $userId], $context );

        return $this->detect( $data );
    }

    /**
     * Analyze an authentication event for anomalies.
     *
     * @param  array<string, mixed>  $context
     *
     * @return Collection<int, Anomaly>
     */
    public function analyzeAuthEvent( string $eventType, array $context = [] ): Collection
    {
        $data = array_merge( [
            'event_type'  => $eventType,
            'hour'        => now()->hour,
            'day_of_week' => now()->dayOfWeek,
        ], $context );

        // Track the event for rule-based detection
        $ruleDetector = $this->getDetector( 'rule_based' );
        if ( $ruleDetector instanceof RuleBasedDetector ) {
            $ruleDetector->trackEvent( $eventType, $data );
        }

        return $this->detect( $data );
    }

    /**
     * Check if anomaly detection is enabled.
     */
    public function isEnabled(): bool
    {
        return $this->config['enabled'] ?? true;
    }

    /**
     * Enable anomaly detection.
     */
    public function enable(): self
    {
        $this->config['enabled'] = true;

        return $this;
    }

    /**
     * Disable anomaly detection.
     */
    public function disable(): self
    {
        $this->config['enabled'] = false;

        return $this;
    }

    /**
     * Get recent anomalies.
     *
     * @return Collection<int, Anomaly>
     */
    public function getRecentAnomalies( int $hours = 24, ?string $severity = null ): Collection
    {
        $query = Anomaly::where( 'detected_at', '>=', now()->subHours( $hours ) )
            ->orderByDesc( 'detected_at' );

        if ( $severity ) {
            $query->where( 'severity', $severity );
        }

        return $query->get();
    }

    /**
     * Get unresolved anomalies.
     *
     * @return Collection<int, Anomaly>
     */
    public function getUnresolvedAnomalies( ?string $severity = null ): Collection
    {
        $query = Anomaly::unresolved()->orderByDesc( 'score' );

        if ( $severity ) {
            $query->where( 'severity', $severity );
        }

        return $query->get();
    }

    /**
     * Get anomaly statistics.
     *
     * @return array<string, mixed>
     */
    public function getStatistics( int $days = 7 ): array
    {
        $startDate = now()->subDays( $days );

        $anomalies = Anomaly::where( 'detected_at', '>=', $startDate )->get();

        return [
            'total_count'      => $anomalies->count(),
            'by_severity'      => $anomalies->groupBy( 'severity' )->map->count(),
            'by_category'      => $anomalies->groupBy( 'category' )->map->count(),
            'by_detector'      => $anomalies->groupBy( 'detector' )->map->count(),
            'resolved_count'   => $anomalies->whereNotNull( 'resolved_at' )->count(),
            'unresolved_count' => $anomalies->whereNull( 'resolved_at' )->count(),
            'avg_score'        => round( $anomalies->avg( 'score' ), 2 ),
            'max_score'        => $anomalies->max( 'score' ),
            'period'           => [
                'start' => $startDate->toIso8601String(),
                'end'   => now()->toIso8601String(),
                'days'  => $days,
            ],
        ];
    }

    /**
     * Get anomaly trends over time.
     *
     * @return array<int, array<string, mixed>>
     */
    public function getTrends( int $days = 30, string $interval = 'day' ): array
    {
        $startDate = now()->subDays( $days );

        return Anomaly::where( 'detected_at', '>=', $startDate )
            ->select( \ArtisanPackUI\SecurityAnalytics\Analytics\Support\TimeBucket::periodExpression( 'detected_at', $interval ) )
            ->selectRaw( 'COUNT(*) as count' )
            ->selectRaw( 'AVG(score) as avg_score' )
            ->selectRaw( "SUM(CASE WHEN severity = 'critical' THEN 1 ELSE 0 END) as critical_count" )
            ->selectRaw( "SUM(CASE WHEN severity = 'high' THEN 1 ELSE 0 END) as high_count" )
            ->groupBy( 'period' )
            ->orderBy( 'period' )
            ->get()
            ->toArray();
    }

    /**
     * Resolve an anomaly.
     */
    public function resolveAnomaly( int $anomalyId, ?int $userId = null, ?string $notes = null ): bool
    {
        $anomaly = Anomaly::find( $anomalyId );

        if ( ! $anomaly ) {
            return false;
        }

        $anomaly->resolve( $userId, $notes );

        return true;
    }

    /**
     * Bulk resolve anomalies.
     *
     * @param  array<int, int>  $anomalyIds
     */
    public function bulkResolve( array $anomalyIds, ?int $userId = null, ?string $notes = null ): int
    {
        $count = 0;

        foreach ( $anomalyIds as $id ) {
            if ( $this->resolveAnomaly( $id, $userId, $notes ) ) {
                $count++;
            }
        }

        return $count;
    }

    /**
     * Auto-resolve old anomalies.
     */
    public function autoResolveOld( int $hoursOld = 72 ): int
    {
        $cutoff = now()->subHours( $hoursOld );

        $anomalies = Anomaly::unresolved()
            ->where( 'detected_at', '<', $cutoff )
            ->get();

        $count = 0;
        foreach ( $anomalies as $anomaly ) {
            $anomaly->resolve( null, 'Auto-resolved due to age' );
            $count++;
        }

        return $count;
    }

    /**
     * Get default configuration.
     *
     * @return array<string, mixed>
     */
    protected function getDefaultConfig(): array
    {
        return [
            'enabled'         => true,
            'min_confidence'  => 70,
            'dispatch_events' => true,
            'detectors'       => [
                'statistical' => ['enabled' => true],
                'behavioral'  => ['enabled' => true],
                'rule_based'  => ['enabled' => true],
            ],
        ];
    }

    /**
     * Register default detectors.
     */
    protected function registerDefaultDetectors(): void
    {
        $detectorConfig = $this->config['detectors'] ?? [];

        if ( $detectorConfig['statistical']['enabled'] ?? true ) {
            $this->registerDetector( new StatisticalDetector( $detectorConfig['statistical'] ?? [] ) );
        }

        if ( $detectorConfig['behavioral']['enabled'] ?? true ) {
            $this->registerDetector( new BehavioralDetector( $detectorConfig['behavioral'] ?? [] ) );
        }

        if ( $detectorConfig['rule_based']['enabled'] ?? true ) {
            $this->registerDetector( new RuleBasedDetector( $detectorConfig['rule_based'] ?? [] ) );
        }
    }

    /**
     * Dispatch events for detected anomalies.
     *
     * @param  Collection<int, Anomaly>  $anomalies
     */
    protected function dispatchAnomalyEvents( Collection $anomalies ): void
    {
        foreach ( $anomalies as $anomaly ) {
            if ( class_exists( AnomalyDetected::class ) ) {
                event( new AnomalyDetected( $anomaly));
            }
        }
    }
}
