<?php

declare( strict_types=1 );

namespace ArtisanPackUI\SecurityAnalytics\Analytics\Dashboard;

use ArtisanPackUI\SecurityAnalytics\Models\AlertHistory;
use ArtisanPackUI\SecurityAnalytics\Models\Anomaly;
use ArtisanPackUI\SecurityAnalytics\Models\SecurityIncident;
use ArtisanPackUI\SecurityAnalytics\Models\SecurityMetric;
use ArtisanPackUI\SecurityAnalytics\Models\ThreatIndicator;
use Illuminate\Support\Collection;

class DashboardDataProvider
{
    /**
     * Get complete dashboard data.
     *
     * @return array<string, mixed>
     */
    public function getDashboardData( int $hours = 24 ): array
    {
        return [
            'overview'                => $this->getOverview( $hours ),
            'threat_summary'          => $this->getThreatSummary( $hours ),
            'authentication_activity' => $this->getAuthenticationActivity( $hours ),
            'anomaly_feed'            => $this->getAnomalyFeed( $hours ),
            'incident_status'         => $this->getIncidentStatus(),
            'alert_summary'           => $this->getAlertSummary( $hours ),
            'top_threats'             => $this->getTopThreats( $hours ),
            'geographic_data'         => $this->getGeographicData( $hours ),
            'generated_at'            => now()->toIso8601String(),
        ];
    }

    /**
     * Get security overview statistics.
     *
     * @return array<string, mixed>
     */
    public function getOverview( int $hours = 24 ): array
    {
        $startTime = now()->subHours( $hours );

        return [
            'total_events'       => SecurityMetric::where( 'recorded_at', '>=', $startTime )->count(),
            'anomalies_detected' => Anomaly::where( 'detected_at', '>=', $startTime )->count(),
            'active_incidents'   => SecurityIncident::active()->count(),
            'alerts_sent'        => AlertHistory::where( 'created_at', '>=', $startTime )
                ->where( 'status', AlertHistory::STATUS_SENT )
                ->count(),
            'threat_indicators'  => ThreatIndicator::active()->count(),
            'critical_anomalies' => Anomaly::where( 'detected_at', '>=', $startTime )
                ->where( 'severity', 'critical' )
                ->count(),
            'unresolved_anomalies' => Anomaly::unresolved()->count(),
            'period_hours'         => $hours,
        ];
    }

    /**
     * Get threat summary.
     *
     * @return array<string, mixed>
     */
    public function getThreatSummary( int $hours = 24 ): array
    {
        $startTime = now()->subHours( $hours );

        $anomalies = Anomaly::where( 'detected_at', '>=', $startTime )->get();

        return [
            'by_severity' => [
                'critical' => $anomalies->where( 'severity', 'critical' )->count(),
                'high'     => $anomalies->where( 'severity', 'high' )->count(),
                'medium'   => $anomalies->where( 'severity', 'medium' )->count(),
                'low'      => $anomalies->where( 'severity', 'low' )->count(),
                'info'     => $anomalies->where( 'severity', 'info' )->count(),
            ],
            'by_category' => $anomalies->groupBy( 'category' )->map->count()->toArray(),
            'by_detector' => $anomalies->groupBy( 'detector' )->map->count()->toArray(),
            'trend'       => $this->calculateTrend( $anomalies ),
        ];
    }

    /**
     * Get authentication activity.
     *
     * @return array<string, mixed>
     */
    public function getAuthenticationActivity( int $hours = 24 ): array
    {
        $startTime = now()->subHours( $hours );

        $metrics = SecurityMetric::category( SecurityMetric::CATEGORY_AUTHENTICATION )
            ->where( 'recorded_at', '>=', $startTime )
            ->get();

        $successMetrics = $metrics->where( 'metric_name', 'auth.login' )->where( 'tags.success', true );
        $failedMetrics  = $metrics->where( 'metric_name', 'auth.failed' );
        $lockoutMetrics = $metrics->where( 'metric_name', 'auth.lockout' );

        return [
            'total_attempts'    => $metrics->where( 'metric_name', 'auth.attempts' )->sum( 'value' ),
            'successful_logins' => $successMetrics->sum( 'value' ),
            'failed_logins'     => $failedMetrics->sum( 'value' ),
            'lockouts'          => $lockoutMetrics->sum( 'value' ),
            'success_rate'      => $this->calculateSuccessRate( $successMetrics, $failedMetrics ),
            'hourly_activity'   => $this->getHourlyActivity( $metrics, $hours ),
        ];
    }

    /**
     * Get recent anomalies for the feed.
     *
     * @return array<int, array<string, mixed>>
     */
    public function getAnomalyFeed( int $hours = 24, int $limit = 20 ): array
    {
        return Anomaly::where( 'detected_at', '>=', now()->subHours( $hours ) )
            ->orderByDesc( 'detected_at' )
            ->limit( $limit )
            ->get()
            ->map( fn ( Anomaly $a ) => [
                'id'          => $a->id,
                'category'    => $a->category,
                'severity'    => $a->severity,
                'description' => $a->description,
                'score'       => $a->score,
                'detector'    => $a->detector,
                'user_id'     => $a->user_id,
                'detected_at' => $a->detected_at->toIso8601String(),
                'is_resolved' => $a->isResolved(),
            ] )
            ->toArray();
    }

    /**
     * Get incident status summary.
     *
     * @return array<string, mixed>
     */
    public function getIncidentStatus(): array
    {
        $incidents = SecurityIncident::all();

        return [
            'total'     => $incidents->count(),
            'by_status' => [
                'open'          => $incidents->where( 'status', SecurityIncident::STATUS_OPEN )->count(),
                'investigating' => $incidents->where( 'status', SecurityIncident::STATUS_INVESTIGATING )->count(),
                'contained'     => $incidents->where( 'status', SecurityIncident::STATUS_CONTAINED )->count(),
                'resolved'      => $incidents->where( 'status', SecurityIncident::STATUS_RESOLVED )->count(),
                'closed'        => $incidents->where( 'status', SecurityIncident::STATUS_CLOSED )->count(),
            ],
            'by_severity'         => $incidents->groupBy( 'severity' )->map->count()->toArray(),
            'unassigned'          => $incidents->whereNull( 'assigned_to' )->where( 'status', '!=', SecurityIncident::STATUS_CLOSED )->count(),
            'avg_time_to_resolve' => $this->calculateAvgTimeToResolve( $incidents ),
        ];
    }

    /**
     * Get alert summary.
     *
     * @return array<string, mixed>
     */
    public function getAlertSummary( int $hours = 24 ): array
    {
        $startTime = now()->subHours( $hours );

        $alerts = AlertHistory::where( 'created_at', '>=', $startTime )->get();

        return [
            'total'          => $alerts->count(),
            'by_status'      => $alerts->groupBy( 'status' )->map->count()->toArray(),
            'by_channel'     => $alerts->groupBy( 'channel' )->map->count()->toArray(),
            'unacknowledged' => $alerts->whereIn( 'status', [AlertHistory::STATUS_PENDING, AlertHistory::STATUS_SENT] )->count(),
            'failed'         => $alerts->where( 'status', AlertHistory::STATUS_FAILED )->count(),
        ];
    }

    /**
     * Get top threats.
     *
     * @return array<int, array<string, mixed>>
     */
    public function getTopThreats( int $hours = 24, int $limit = 10 ): array
    {
        return Anomaly::where( 'detected_at', '>=', now()->subHours( $hours ) )
            ->orderByDesc( 'score' )
            ->limit( $limit )
            ->get()
            ->map( fn ( Anomaly $a ) => [
                'id'          => $a->id,
                'category'    => $a->category,
                'severity'    => $a->severity,
                'score'       => $a->score,
                'description' => $a->description,
                'detected_at' => $a->detected_at->toIso8601String(),
            ] )
            ->toArray();
    }

    /**
     * Get geographic data for threat visualization.
     *
     * @return array<string, mixed>
     */
    public function getGeographicData( int $hours = 24 ): array
    {
        $startTime = now()->subHours( $hours );

        // Get threat indicators by country
        $threats = ThreatIndicator::active()
            ->whereNotNull( 'metadata->country' )
            ->get()
            ->groupBy( fn ( $t ) => $t->metadata['country'] ?? 'Unknown' )
            ->map->count()
            ->toArray();

        // Get anomalies by country from metadata
        $anomalies = Anomaly::where( 'detected_at', '>=', $startTime )
            ->whereNotNull( 'metadata->country' )
            ->get()
            ->groupBy( fn ( $a ) => $a->metadata['country'] ?? 'Unknown' )
            ->map->count()
            ->toArray();

        return [
            'threats_by_country'   => $threats,
            'anomalies_by_country' => $anomalies,
        ];
    }

    /**
     * Get time series data for charts.
     *
     * @return array<int, array<string, mixed>>
     */
    public function getTimeSeriesData( string $metric, int $hours = 24, string $interval = 'hour' ): array
    {
        $startTime = now()->subHours( $hours );

        $format = match ( $interval ) {
            'minute' => '%Y-%m-%d %H:%i',
            'hour'   => '%Y-%m-%d %H:00',
            'day'    => '%Y-%m-%d',
            default  => '%Y-%m-%d %H:00',
        };

        return SecurityMetric::where( 'metric_name', $metric )
            ->where( 'recorded_at', '>=', $startTime )
            ->selectRaw( "DATE_FORMAT(recorded_at, '{$format}') as period" )
            ->selectRaw( 'SUM(value) as total' )
            ->selectRaw( 'AVG(value) as average' )
            ->selectRaw( 'COUNT(*) as count' )
            ->groupBy( 'period' )
            ->orderBy( 'period' )
            ->get()
            ->toArray();
    }

    /**
     * Calculate trend compared to previous period.
     *
     * @param  Collection<int, Anomaly>  $anomalies
     *
     * @return array<string, mixed>
     */
    protected function calculateTrend( Collection $anomalies, int $hours = 24 ): array
    {
        $currentCount = $anomalies->count();

        // Get count from previous period
        $previousStart = now()->subHours( $hours * 2 );
        $previousEnd   = now()->subHours( $hours );

        $previousCount = Anomaly::whereBetween( 'detected_at', [$previousStart, $previousEnd] )->count();

        if ( 0 === $previousCount ) {
            $changePercent = $currentCount > 0 ? 100 : 0;
        } else {
            $changePercent = round( ( ( $currentCount - $previousCount ) / $previousCount ) * 100, 1 );
        }

        return [
            'current'        => $currentCount,
            'previous'       => $previousCount,
            'change_percent' => $changePercent,
            'direction'      => $changePercent > 0 ? 'up' : ( $changePercent < 0 ? 'down' : 'stable' ),
        ];
    }

    /**
     * Calculate success rate.
     *
     * @param  Collection<int, SecurityMetric>  $success
     * @param  Collection<int, SecurityMetric>  $failed
     */
    protected function calculateSuccessRate( Collection $success, Collection $failed ): float
    {
        $total = $success->sum( 'value' ) + $failed->sum( 'value' );

        if ( 0 === $total ) {
            return 0;
        }

        return round( ( $success->sum( 'value' ) / $total ) * 100, 2 );
    }

    /**
     * Get hourly activity breakdown.
     *
     * @param  Collection<int, SecurityMetric>  $metrics
     *
     * @return array<int, array<string, mixed>>
     */
    protected function getHourlyActivity( Collection $metrics, int $hours ): array
    {
        $hourlyData = [];

        for ( $i = $hours - 1; $i >= 0; $i-- ) {
            $hourStart = now()->subHours( $i )->startOfHour();
            $hourEnd   = now()->subHours( $i )->endOfHour();

            $hourMetrics = $metrics->filter( function ( $m ) use ( $hourStart, $hourEnd ) {
                return $m->recorded_at >= $hourStart && $m->recorded_at <= $hourEnd;
            } );

            $hourlyData[] = [
                'hour'      => $hourStart->format( 'H:00' ),
                'timestamp' => $hourStart->toIso8601String(),
                'count'     => $hourMetrics->sum( 'value' ),
            ];
        }

        return $hourlyData;
    }

    /**
     * Calculate average time to resolve incidents.
     *
     * @param  Collection<int, SecurityIncident>  $incidents
     */
    protected function calculateAvgTimeToResolve( Collection $incidents): ?float
    {
        $resolvedIncidents = $incidents->whereNotNull( 'resolved_at');

        if ( $resolvedIncidents->isEmpty()) {
            return null;
        }

        $totalMinutes = $resolvedIncidents->sum( fn ( $i) => $i->getTimeToResolve() ?? 0);

        return round( $totalMinutes / $resolvedIncidents->count(), 1);
    }
}
