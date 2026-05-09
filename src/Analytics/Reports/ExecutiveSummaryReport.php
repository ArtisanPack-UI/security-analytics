<?php

declare( strict_types=1 );

namespace ArtisanPackUI\SecurityAnalytics\Analytics\Reports;

use ArtisanPackUI\SecurityAnalytics\Models\AlertHistory;
use ArtisanPackUI\SecurityAnalytics\Models\Anomaly;
use ArtisanPackUI\SecurityAnalytics\Models\SecurityIncident;
use ArtisanPackUI\SecurityAnalytics\Models\SecurityMetric;
use InvalidArgumentException;

class ExecutiveSummaryReport extends AbstractReport
{
    /**
     * {@inheritdoc}
     */
    public function generate(): array
    {
        $startDate = $this->options['start_date'] ?? throw new InvalidArgumentException( 'start_date option is required' );
        $endDate   = $this->options['end_date'] ?? throw new InvalidArgumentException( 'end_date option is required' );

        return [
            'summary'          => $this->getSummaryStats( $startDate, $endDate ),
            'threat_overview'  => $this->getThreatOverview( $startDate, $endDate ),
            'incident_summary' => $this->getIncidentSummary( $startDate, $endDate ),
            'alert_summary'    => $this->getAlertSummary( $startDate, $endDate ),
            'recommendations'  => $this->getRecommendations( $startDate, $endDate ),
            'period'           => [
                'start' => $startDate->format( 'Y-m-d' ),
                'end'   => $endDate->format( 'Y-m-d' ),
            ],
        ];
    }

    /**
     * {@inheritdoc}
     */
    protected function getTitle(): string
    {
        return 'Executive Security Summary';
    }

    /**
     * Get summary statistics.
     *
     * @return array<string, mixed>
     */
    protected function getSummaryStats( $startDate, $endDate ): array
    {
        return [
            'total_events'       => SecurityMetric::whereBetween( 'recorded_at', [$startDate, $endDate] )->count(),
            'anomalies_detected' => Anomaly::whereBetween( 'detected_at', [$startDate, $endDate] )->count(),
            'incidents_created'  => SecurityIncident::whereBetween( 'opened_at', [$startDate, $endDate] )->count(),
            'incidents_resolved' => SecurityIncident::whereBetween( 'resolved_at', [$startDate, $endDate] )->count(),
            'alerts_sent'        => AlertHistory::whereBetween( 'created_at', [$startDate, $endDate] )
                ->where( 'status', AlertHistory::STATUS_SENT )->count(),
            'critical_threats' => Anomaly::whereBetween( 'detected_at', [$startDate, $endDate] )
                ->where( 'severity', 'critical' )->count(),
        ];
    }

    /**
     * Get threat overview.
     *
     * @return array<string, mixed>
     */
    protected function getThreatOverview( $startDate, $endDate ): array
    {
        $anomalies = Anomaly::whereBetween( 'detected_at', [$startDate, $endDate] )->get();

        return [
            'by_severity' => $anomalies->groupBy( 'severity' )->map->count()->toArray(),
            'by_category' => $anomalies->groupBy( 'category' )->map->count()->toArray(),
            'top_threats' => $anomalies->sortByDesc( 'score' )->take( 5 )->map( fn ( $a ) => [
                'category'    => $a->category,
                'severity'    => $a->severity,
                'description' => $a->description,
                'score'       => $a->score,
            ] )->values()->toArray(),
        ];
    }

    /**
     * Get incident summary.
     *
     * @return array<string, mixed>
     */
    protected function getIncidentSummary( $startDate, $endDate ): array
    {
        $incidents = SecurityIncident::whereBetween( 'opened_at', [$startDate, $endDate] )->get();
        $resolved  = $incidents->whereNotNull( 'resolved_at' );

        return [
            'total'                       => $incidents->count(),
            'by_status'                   => $incidents->groupBy( 'status' )->map->count()->toArray(),
            'by_severity'                 => $incidents->groupBy( 'severity' )->map->count()->toArray(),
            'avg_resolution_time_minutes' => $resolved->avg( fn ( $i ) => $i->getTimeToResolve() ),
        ];
    }

    /**
     * Get alert summary.
     *
     * @return array<string, mixed>
     */
    protected function getAlertSummary( $startDate, $endDate ): array
    {
        $alerts = AlertHistory::whereBetween( 'created_at', [$startDate, $endDate] )->get();

        return [
            'total'               => $alerts->count(),
            'by_status'           => $alerts->groupBy( 'status' )->map->count()->toArray(),
            'by_channel'          => $alerts->groupBy( 'channel' )->map->count()->toArray(),
            'acknowledgment_rate' => $alerts->count() > 0
                ? round( $alerts->where( 'status', AlertHistory::STATUS_ACKNOWLEDGED )->count() / $alerts->count() * 100, 1 )
                : 0,
        ];
    }

    /**
     * Generate recommendations based on data.
     *
     * @return array<int, string>
     */
    protected function getRecommendations( $startDate, $endDate ): array
    {
        $recommendations = [];

        // Check for unresolved high-severity anomalies
        $unresolvedHighSeverity = Anomaly::unresolved()
            ->whereIn( 'severity', ['critical', 'high'] )
            ->whereBetween( 'detected_at', [$startDate, $endDate] )
            ->count();

        if ( $unresolvedHighSeverity > 0 ) {
            $recommendations[] = "There are {$unresolvedHighSeverity} unresolved high/critical severity anomalies that require immediate attention.";
        }

        // Check for unassigned incidents
        $unassignedIncidents = SecurityIncident::active()
            ->whereNull( 'assigned_to' )
            ->whereBetween( 'opened_at', [$startDate, $endDate] )
            ->count();

        if ( $unassignedIncidents > 0 ) {
            $recommendations[] = "{$unassignedIncidents} active incidents are unassigned. Consider assigning team members to these incidents.";
        }

        // Check for failed alerts
        $failedAlerts = AlertHistory::whereBetween( 'created_at', [$startDate, $endDate] )
            ->where( 'status', AlertHistory::STATUS_FAILED )
            ->count();

        if ( $failedAlerts > 5 ) {
            $recommendations[] = "Multiple alert failures detected ({$failedAlerts}). Review alert channel configurations.";
        }

        if ( empty( $recommendations ) ) {
            $recommendations[] = 'No critical recommendations at this time. Continue monitoring security metrics.';
        }

        return $recommendations;
    }

    /**
     * {@inheritdoc}
     */
    protected function renderHtmlContent( array $data ): string
    {
        $html = '';

        // Summary Stats
        $html .= '<h2>Overview</h2>';
        $html .= $this->renderStatCards( $data['summary'] );

        // Threat Overview
        $html .= '<h2>Threat Analysis</h2>';
        $html .= '<h3>By Severity</h3>';
        $html .= $this->renderTable(
            collect( $data['threat_overview']['by_severity'] )->map( fn ( $count, $severity ) => [
                'severity' => $severity,
                'count'    => $count,
            ] )->values()->toArray(),
        );

        $html .= '<h3>Top Threats</h3>';
        $html .= $this->renderTable( $data['threat_overview']['top_threats'] );

        // Incident Summary
        $html .= '<h2>Incident Summary</h2>';
        $html .= $this->renderTable(
            collect( $data['incident_summary']['by_status'] )->map( fn ( $count, $status ) => [
                'status' => $status,
                'count'  => $count,
            ] )->values()->toArray(),
        );

        // Recommendations
        $html .= '<h2>Recommendations</h2>';
        $html .= '<ul>';
        foreach ( $data['recommendations'] as $rec ) {
            $html .= '<li>' . htmlspecialchars( $rec ) . '</li>';
        }
        $html .= '</ul>';

        return $html;
    }

    /**
     * {@inheritdoc}
     */
    protected function getCsvRows( array $data ): array
    {
        $rows = [];

        // Summary row
        foreach ( $data['summary'] as $key => $value ) {
            $rows[] = [
                'category' => 'Summary',
                'metric'   => $key,
                'value'    => $value,
            ];
        }

        // Threat rows
        foreach ( $data['threat_overview']['by_severity'] as $severity => $count ) {
            $rows[] = [
                'category' => 'Threats by Severity',
                'metric'   => $severity,
                'value'    => $count,
            ];
        }

        return $rows;
    }
}
