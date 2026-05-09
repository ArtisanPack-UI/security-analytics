<?php

declare( strict_types=1 );

namespace ArtisanPackUI\SecurityAnalytics\Analytics;

use ArtisanPackUI\SecurityAnalytics\Models\SecurityMetric;
use DateTimeInterface;
use Illuminate\Support\Facades\Cache;

class MetricsCollector
{
    /**
     * Buffer for batched metrics.
     *
     * @var array<int, array<string, mixed>>
     */
    protected array $buffer = [];

    /**
     * Whether batching is enabled.
     */
    protected bool $batchingEnabled = false;

    /**
     * Maximum buffer size before auto-flush.
     */
    protected int $maxBufferSize = 100;

    /**
     * Record a counter metric (increments).
     *
     * @param  array<string, mixed>  $tags
     */
    public function counter(
        string $name,
        float $value = 1.0,
        string $category = SecurityMetric::CATEGORY_AUTHENTICATION,
        array $tags = [],
    ): void {
        $this->record( $name, $value, SecurityMetric::TYPE_COUNTER, $category, $tags );
    }

    /**
     * Record a gauge metric (point-in-time value).
     *
     * @param  array<string, mixed>  $tags
     */
    public function gauge(
        string $name,
        float $value,
        string $category = SecurityMetric::CATEGORY_SYSTEM,
        array $tags = [],
    ): void {
        $this->record( $name, $value, SecurityMetric::TYPE_GAUGE, $category, $tags );
    }

    /**
     * Record a timing metric (duration in milliseconds).
     *
     * @param  array<string, mixed>  $tags
     */
    public function timing(
        string $name,
        float $milliseconds,
        string $category = SecurityMetric::CATEGORY_PERFORMANCE,
        array $tags = [],
    ): void {
        $this->record( $name, $milliseconds, SecurityMetric::TYPE_TIMING, $category, $tags );
    }

    /**
     * Record a histogram metric (distribution of values).
     *
     * @param  array<string, mixed>  $tags
     */
    public function histogram(
        string $name,
        float $value,
        string $category = SecurityMetric::CATEGORY_ACCESS,
        array $tags = [],
    ): void {
        $this->record( $name, $value, SecurityMetric::TYPE_HISTOGRAM, $category, $tags );
    }

    /**
     * Time a callback and record the duration.
     *
     * @template T
     *
     * @param  callable(): T  $callback
     * @param  array<string, mixed>  $tags
     *
     * @return T
     */
    public function time(
        string $name,
        callable $callback,
        string $category = SecurityMetric::CATEGORY_PERFORMANCE,
        array $tags = [],
    ): mixed {
        $start = hrtime( true );

        try {
            return $callback();
        } finally {
            $duration = ( hrtime( true ) - $start ) / 1_000_000; // Convert to milliseconds
            $this->timing( $name, $duration, $category, $tags );
        }
    }

    /**
     * Increment a counter in the cache for real-time tracking.
     *
     * @param  array<string, mixed>  $tags
     */
    public function increment(
        string $name,
        int $amount = 1,
        string $category = SecurityMetric::CATEGORY_AUTHENTICATION,
        array $tags = [],
        int $ttlMinutes = 60,
    ): int {
        $cacheKey = $this->getCacheKey( $name, $category, $tags );

        // Use atomic Cache::add to avoid race conditions
        // add() only sets the key if it doesn't exist, then we increment
        Cache::add( $cacheKey, 0, now()->addMinutes( $ttlMinutes ) );

        $newValue = Cache::increment( $cacheKey, $amount );

        // Handle edge case where increment might return false for some cache drivers
        return is_numeric( $newValue ) ? (int) $newValue : 0;
    }

    /**
     * Get the current value of a cached counter.
     *
     * @param  array<string, mixed>  $tags
     */
    public function getCounter( string $name, string $category = SecurityMetric::CATEGORY_AUTHENTICATION, array $tags = [] ): int
    {
        $cacheKey = $this->getCacheKey( $name, $category, $tags );

        return (int) Cache::get( $cacheKey, 0 );
    }

    /**
     * Record a generic metric.
     *
     * @param  array<string, mixed>  $tags
     */
    public function record(
        string $name,
        float $value,
        string $type = SecurityMetric::TYPE_COUNTER,
        string $category = SecurityMetric::CATEGORY_SYSTEM,
        array $tags = [],
    ): void {
        $metric = [
            'metric_name' => $name,
            'metric_type' => $type,
            'category'    => $category,
            'value'       => $value,
            'tags'        => $tags,
            'recorded_at' => now(),
        ];

        if ( $this->batchingEnabled ) {
            $this->buffer[] = $metric;

            if ( count( $this->buffer ) >= $this->maxBufferSize ) {
                $this->flush();
            }
        } else {
            SecurityMetric::create( $metric );
        }
    }

    /**
     * Enable batching mode.
     */
    public function enableBatching( int $maxBufferSize = 100 ): self
    {
        $this->batchingEnabled = true;
        $this->maxBufferSize   = $maxBufferSize;

        return $this;
    }

    /**
     * Disable batching mode and flush remaining metrics.
     */
    public function disableBatching(): self
    {
        $this->flush();
        $this->batchingEnabled = false;

        return $this;
    }

    /**
     * Flush the metrics buffer to the database.
     */
    public function flush(): void
    {
        if ( empty( $this->buffer ) ) {
            return;
        }

        // JSON encode tags for raw insert since Eloquent casts won't apply
        $metricsToInsert = array_map( function ( $metric ) {
            $metric['tags'] = json_encode( $metric['tags'] ?? [] );

            return $metric;
        }, $this->buffer );

        SecurityMetric::insert( $metricsToInsert );
        $this->buffer = [];
    }

    /**
     * Record an authentication event.
     *
     * @param  array<string, mixed>  $context
     */
    public function recordAuthEvent( string $event, bool $success, array $context = [] ): void
    {
        $this->counter(
            "auth.{$event}",
            1,
            SecurityMetric::CATEGORY_AUTHENTICATION,
            array_merge( ['success' => $success], $context ),
        );
    }

    /**
     * Record a security threat event.
     *
     * @param  array<string, mixed>  $context
     */
    public function recordThreatEvent( string $threatType, string $severity, array $context = [] ): void
    {
        $this->counter(
            "threat.{$threatType}",
            1,
            SecurityMetric::CATEGORY_THREAT,
            array_merge( ['severity' => $severity], $context ),
        );
    }

    /**
     * Record an access control event.
     *
     * @param  array<string, mixed>  $context
     */
    public function recordAccessEvent( string $resource, string $action, bool $allowed, array $context = [] ): void
    {
        $this->counter(
            "access.{$resource}.{$action}",
            1,
            SecurityMetric::CATEGORY_ACCESS,
            array_merge( ['allowed' => $allowed], $context ),
        );
    }

    /**
     * Record a compliance-related event.
     *
     * @param  array<string, mixed>  $context
     */
    public function recordComplianceEvent( string $control, string $status, array $context = [] ): void
    {
        $this->counter(
            "compliance.{$control}",
            1,
            SecurityMetric::CATEGORY_COMPLIANCE,
            array_merge( ['status' => $status], $context ),
        );
    }

    /**
     * Record a performance metric for security operations.
     *
     * @param  array<string, mixed>  $context
     */
    public function recordSecurityPerformance( string $operation, float $durationMs, array $context = [] ): void
    {
        $this->timing(
            "security.{$operation}",
            $durationMs,
            SecurityMetric::CATEGORY_PERFORMANCE,
            $context,
        );
    }

    /**
     * Get aggregated metrics for a time period.
     *
     * @param  array<string, mixed>  $filters
     *
     * @return array<string, mixed>
     */
    public function getAggregatedMetrics(
        string $category,
        DateTimeInterface $startDate,
        DateTimeInterface $endDate,
        array $filters = [],
    ): array {
        $query = SecurityMetric::query()
            ->where( 'category', $category )
            ->whereBetween( 'recorded_at', [$startDate, $endDate] );

        if ( isset( $filters['metric_name'] ) ) {
            $query->where( 'metric_name', $filters['metric_name'] );
        }

        if ( isset( $filters['metric_type'] ) ) {
            $query->where( 'metric_type', $filters['metric_type'] );
        }

        $metrics = $query->get();

        return [
            'count'  => $metrics->count(),
            'sum'    => $metrics->sum( 'value' ),
            'avg'    => $metrics->avg( 'value' ),
            'min'    => $metrics->min( 'value' ),
            'max'    => $metrics->max( 'value' ),
            'period' => [
                'start' => $startDate->format( 'Y-m-d H:i:s' ),
                'end'   => $endDate->format( 'Y-m-d H:i:s' ),
            ],
        ];
    }

    /**
     * Get metrics grouped by time intervals.
     *
     * @return array<int, array<string, mixed>>
     */
    public function getMetricsByInterval(
        string $metricName,
        DateTimeInterface $startDate,
        DateTimeInterface $endDate,
        string $interval = 'hour',
    ): array {
        return SecurityMetric::query()
            ->where( 'metric_name', $metricName )
            ->whereBetween( 'recorded_at', [$startDate, $endDate] )
            ->select( Support\TimeBucket::periodExpression( 'recorded_at', $interval ) )
            ->selectRaw( 'SUM(value) as total' )
            ->selectRaw( 'AVG(value) as average' )
            ->selectRaw( 'COUNT(*) as count' )
            ->groupBy( 'period' )
            ->orderBy( 'period' )
            ->get()
            ->toArray();
    }

    /**
     * Clean up old metrics beyond the retention period.
     */
    public function cleanup( int $retentionDays = 90 ): int
    {
        $cutoffDate = now()->subDays( $retentionDays );

        return SecurityMetric::where( 'recorded_at', '<', $cutoffDate )->delete();
    }

    /**
     * Get the cache key for a metric.
     *
     * @param  array<string, mixed>  $tags
     */
    protected function getCacheKey( string $name, string $category, array $tags ): string
    {
        $tagHash = empty( $tags ) ? '' : '_' . md5( serialize( $tags ) );

        return "security_metric:{$category}:{$name}{$tagHash}";
    }
}
