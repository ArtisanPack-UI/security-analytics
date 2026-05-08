<?php

declare( strict_types=1 );

namespace ArtisanPackUI\SecurityAnalytics\Http\Controllers;

use ArtisanPackUI\SecurityAnalytics\Analytics\AnomalyDetection\AnomalyDetectionService;
use ArtisanPackUI\SecurityAnalytics\Analytics\Dashboard\DashboardDataProvider;
use ArtisanPackUI\SecurityAnalytics\Analytics\MetricsCollector;
use ArtisanPackUI\SecurityAnalytics\Analytics\ThreatIntelligence\ThreatIntelligenceService;
use ArtisanPackUI\SecurityAnalytics\Models\AlertHistory;
use ArtisanPackUI\SecurityAnalytics\Models\Anomaly;
use ArtisanPackUI\SecurityAnalytics\Models\SecurityIncident;
use ArtisanPackUI\SecurityAnalytics\Models\SecurityMetric;
use Carbon\Carbon;
use DB;
use Exception;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Routing\Controller;
use Symfony\Component\HttpFoundation\StreamedResponse;

class SecurityDashboardController extends Controller
{
    public function __construct(
        protected DashboardDataProvider $dashboardProvider,
        protected MetricsCollector $metricsCollector,
        protected AnomalyDetectionService $anomalyDetection,
        protected ThreatIntelligenceService $threatIntel,
    ) {
    }

    /**
     * Get dashboard summary.
     */
    public function summary( Request $request ): JsonResponse
    {
        // Validate date inputs
        $validator = \Illuminate\Support\Facades\Validator::make( $request->all(), [
            'from' => 'nullable|date',
            'to'   => 'nullable|date',
        ] );

        if ( $validator->fails() ) {
            return response()->json( [
                'error'   => 'Invalid date format',
                'details' => $validator->errors(),
            ], 400 );
        }

        try {
            $from = $request->input( 'from' ) ? Carbon::parse( $request->input( 'from' ) ) : now()->subHours( 24 );
            $to   = $request->input( 'to' ) ? Carbon::parse( $request->input( 'to' ) ) : now();
        } catch ( Exception $e ) {
            return response()->json( [
                'error'   => 'Failed to parse date',
                'details' => $e->getMessage(),
            ], 400 );
        }

        $summary = [
            'threat_level' => $this->calculateThreatLevel(),
            'period'       => [
                'from' => $from->toIso8601String(),
                'to'   => $to->toIso8601String(),
            ],
            'metrics' => [
                'total_events'    => SecurityMetric::whereBetween( 'recorded_at', [$from, $to] )->count(),
                'auth_attempts'   => $this->getMetricCount( 'auth', $from, $to ),
                'failed_logins'   => $this->getFailedLoginCount( $from, $to ),
                'active_sessions' => $this->getActiveSessionCount(),
            ],
            'anomalies' => [
                'total'      => Anomaly::whereBetween( 'detected_at', [$from, $to] )->count(),
                'unresolved' => Anomaly::unresolved()->count(),
                'critical'   => Anomaly::where( 'severity', 'critical' )->unresolved()->count(),
                'high'       => Anomaly::where( 'severity', 'high' )->unresolved()->count(),
            ],
            'incidents' => [
                'open'           => SecurityIncident::where( 'status', SecurityIncident::STATUS_OPEN )->count(),
                'investigating'  => SecurityIncident::where( 'status', SecurityIncident::STATUS_INVESTIGATING )->count(),
                'resolved_today' => SecurityIncident::whereDate( 'resolved_at', today() )->count(),
            ],
            'alerts' => [
                'sent_today' => AlertHistory::whereDate( 'sent_at', today() )->count(),
                'failed'     => AlertHistory::where( 'status', AlertHistory::STATUS_FAILED )->whereDate( 'created_at', today() )->count(),
            ],
        ];

        return response()->json( $summary );
    }

    /**
     * Get live events stream (Server-Sent Events).
     */
    public function liveEvents( Request $request ): StreamedResponse
    {
        return response()->stream( function (): void {
            $lastEventId = 0;
            $startTime   = time();
            $maxDuration = 300; // 5 minutes max
            $eventCount  = 0;
            $maxEvents   = 10000;

            while ( time() - $startTime < $maxDuration && $eventCount < $maxEvents ) {
                // Get new events since last check
                $events = SecurityMetric::where( 'id', '>', $lastEventId )
                    ->orderBy( 'id' )
                    ->limit( 50 )
                    ->get();

                foreach ( $events as $event ) {
                    echo "id: {$event->id}\n";
                    echo 'data: ' . json_encode( [
                        'id'          => $event->id,
                        'category'    => $event->category,
                        'metric_name' => $event->metric_name,
                        'value'       => $event->value,
                        'tags'        => $event->tags,
                        'recorded_at' => $event->recorded_at->toIso8601String(),
                    ] ) . "\n\n";

                    $lastEventId = $event->id;
                    $eventCount++;
                }

                // Send heartbeat comment to keep connection alive
                if ( $events->isEmpty() ) {
                    echo ": heartbeat\n\n";
                }

                // Flush output
                if ( ob_get_level() > 0 ) {
                    ob_flush();
                }
                flush();

                // Check if client disconnected
                if ( connection_aborted() ) {
                    break;
                }

                // Wait before next poll
                sleep( 2 );
            }

            // Send reconnect instruction when closing
            echo "retry: 3000\n\n";
        }, 200, [
            'Content-Type'      => 'text/event-stream',
            'Cache-Control'     => 'no-cache',
            'Connection'        => 'keep-alive',
            'X-Accel-Buffering' => 'no',
        ] );
    }

    /**
     * Get specific metric data.
     */
    public function metric( string $metric, Request $request ): JsonResponse
    {
        $from     = $request->input( 'from' ) ? Carbon::parse( $request->input( 'from' ) ) : now()->subHours( 24 );
        $to       = $request->input( 'to' ) ? Carbon::parse( $request->input( 'to' ) ) : now();
        $interval = $request->input( 'interval', 'hour' );

        $data = $this->metricsCollector->getMetricsByInterval( $metric, $from, $to, $interval );

        return response()->json( [
            'metric'   => $metric,
            'interval' => $interval,
            'period'   => [
                'from' => $from->toIso8601String(),
                'to'   => $to->toIso8601String(),
            ],
            'data' => $data,
        ] );
    }

    /**
     * Get current threat assessment.
     */
    public function threats( Request $request ): JsonResponse
    {
        $limit = $request->input( 'limit', 10 );

        $threats = [
            'threat_level'     => $this->calculateThreatLevel(),
            'recent_anomalies' => Anomaly::with( 'user' )
                ->orderByDesc( 'detected_at' )
                ->limit( $limit )
                ->get()
                ->map( fn ( $a ) => [
                    'id'          => $a->id,
                    'detector'    => $a->detector,
                    'category'    => $a->category,
                    'severity'    => $a->severity,
                    'score'       => $a->score,
                    'description' => $a->description,
                    'user_id'     => $a->user_id,
                    'ip_address'  => $a->ip_address,
                    'detected_at' => $a->detected_at->toIso8601String(),
                    'resolved'    => null !== $a->resolved_at,
                ] ),
            'top_threat_sources' => $this->getTopThreatSources( $limit ),
            'threat_stats'       => $this->threatIntel->getStatistics(),
        ];

        return response()->json( $threats );
    }

    /**
     * Get geographic distribution of events.
     */
    public function geographic( Request $request ): JsonResponse
    {
        $from = $request->input( 'from' ) ? Carbon::parse( $request->input( 'from' ) ) : now()->subHours( 24 );
        $to   = $request->input( 'to' ) ? Carbon::parse( $request->input( 'to' ) ) : now();

        // Get events with location data from tags
        $events = SecurityMetric::whereBetween( 'recorded_at', [$from, $to] )
            ->whereNotNull( 'tags->country' )
            ->selectRaw( "JSON_UNQUOTE(JSON_EXTRACT(tags, '$.country')) as country" )
            ->selectRaw( 'COUNT(*) as count' )
            ->groupBy( 'country' )
            ->orderByDesc( 'count' )
            ->limit( 50 )
            ->get();

        return response()->json( [
            'period' => [
                'from' => $from->toIso8601String(),
                'to'   => $to->toIso8601String(),
            ],
            'countries' => $events,
        ] );
    }

    /**
     * Get timeline data for charts.
     */
    public function timeline( Request $request ): JsonResponse
    {
        $from     = $request->input( 'from' ) ? Carbon::parse( $request->input( 'from' ) ) : now()->subDays( 7 );
        $to       = $request->input( 'to' ) ? Carbon::parse( $request->input( 'to' ) ) : now();
        $interval = $request->input( 'interval', 'hour' );
        $category = $request->input( 'category' );

        $query = SecurityMetric::whereBetween( 'recorded_at', [$from, $to] );

        if ( $category ) {
            $query->where( 'category', $category );
        }

        $data = $query
            ->select( \ArtisanPackUI\SecurityAnalytics\Analytics\Support\TimeBucket::periodExpression( 'recorded_at', $interval ) )
            ->selectRaw( 'COUNT(*) as count' )
            ->selectRaw( 'SUM(value) as total_value' )
            ->groupBy( 'period' )
            ->orderBy( 'period' )
            ->get();

        return response()->json( [
            'interval' => $interval,
            'period'   => [
                'from' => $from->toIso8601String(),
                'to'   => $to->toIso8601String(),
            ],
            'data' => $data,
        ] );
    }

    /**
     * Acknowledge an alert.
     */
    public function acknowledgeAlert( int $alertId, Request $request ): JsonResponse
    {
        $alert = AlertHistory::findOrFail( $alertId );

        $alert->update( [
            'status'          => AlertHistory::STATUS_ACKNOWLEDGED,
            'acknowledged_at' => now(),
            'acknowledged_by' => $request->user()?->id,
        ] );

        return response()->json( [
            'success'  => true,
            'message'  => 'Alert acknowledged',
            'alert_id' => $alertId,
        ] );
    }

    /**
     * Get anomaly statistics.
     */
    public function anomalyStats( Request $request ): JsonResponse
    {
        $days = $request->input( 'days', 7 );

        $stats  = $this->anomalyDetection->getStatistics( $days );
        $trends = $this->anomalyDetection->getTrends( $days );

        return response()->json( [
            'statistics' => $stats,
            'trends'     => $trends,
        ] );
    }

    /**
     * Get incident list.
     */
    public function incidents( Request $request ): JsonResponse
    {
        $status   = $request->input( 'status' );
        $severity = $request->input( 'severity' );
        $limit    = $request->input( 'limit', 20 );

        $query = SecurityIncident::query();

        if ( $status ) {
            $query->where( 'status', $status );
        }

        if ( $severity ) {
            $query->where( 'severity', $severity );
        }

        $incidents = $query
            ->orderByDesc( 'opened_at' )
            ->limit( $limit )
            ->get();

        return response()->json( [
            'incidents' => $incidents,
            'counts'    => [
                'open'          => SecurityIncident::where( 'status', SecurityIncident::STATUS_OPEN )->count(),
                'investigating' => SecurityIncident::where( 'status', SecurityIncident::STATUS_INVESTIGATING )->count(),
                'contained'     => SecurityIncident::where( 'status', SecurityIncident::STATUS_CONTAINED )->count(),
                'resolved'      => SecurityIncident::where( 'status', SecurityIncident::STATUS_RESOLVED )->count(),
            ],
        ] );
    }

    /**
     * Calculate current threat level (0-100).
     */
    protected function calculateThreatLevel(): int
    {
        $criticalAnomalies = Anomaly::where( 'severity', 'critical' )->unresolved()->count();
        $highAnomalies     = Anomaly::where( 'severity', 'high' )->unresolved()->count();
        $mediumAnomalies   = Anomaly::where( 'severity', 'medium' )->unresolved()->count();

        $openIncidents = SecurityIncident::whereIn( 'status', [
            SecurityIncident::STATUS_OPEN,
            SecurityIncident::STATUS_INVESTIGATING,
        ] )->count();

        // Calculate weighted score
        $score = 0;
        $score += min( $criticalAnomalies * 20, 40 ); // Max 40 from critical
        $score += min( $highAnomalies * 10, 30 );     // Max 30 from high
        $score += min( $mediumAnomalies * 5, 20 );    // Max 20 from medium
        $score += min( $openIncidents * 5, 10 );      // Max 10 from incidents

        return min( $score, 100 );
    }

    /**
     * Get metric count for a category.
     */
    protected function getMetricCount( string $category, Carbon $from, Carbon $to ): int
    {
        return SecurityMetric::where( 'category', $category )
            ->whereBetween( 'recorded_at', [$from, $to] )
            ->count();
    }

    /**
     * Get failed login count.
     */
    protected function getFailedLoginCount( Carbon $from, Carbon $to ): int
    {
        return SecurityMetric::where( 'metric_name', 'like', 'auth.login%' )
            ->whereRaw( "JSON_EXTRACT(tags, '$.success') = false" )
            ->whereBetween( 'recorded_at', [$from, $to] )
            ->count();
    }

    /**
     * Get active session count.
     */
    protected function getActiveSessionCount(): int
    {
        if ( 'database' !== config( 'session.driver' ) ) {
            return 0; // Cannot count sessions for non-database drivers
        }

        return DB::table( config( 'session.table', 'sessions' ) )
            ->where( 'last_activity', '>=', now()->subMinutes( 30 )->timestamp )
            ->count();
    }

    /**
     * Get top threat sources.
     *
     * @return array<int, array<string, mixed>>
     */
    protected function getTopThreatSources( int $limit ): array
    {
        return Anomaly::whereNotNull( 'ip_address' )
            ->selectRaw( 'ip_address, COUNT(*) as count' )
            ->groupBy( 'ip_address' )
            ->orderByDesc( 'count' )
            ->limit( $limit)
            ->get()
            ->toArray();
    }
}
