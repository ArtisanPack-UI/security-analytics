<?php

/**
 * TrendReport report.
 *
 * @package    ArtisanPack_UI
 * @subpackage SecurityAnalytics
 *
 * @author     Jacob Martella <support@artisanpackui.dev>
 *
 * @since      1.0.0
 */

declare( strict_types=1 );

namespace ArtisanPackUI\SecurityAnalytics\Analytics\Reports;

use ArtisanPackUI\SecurityAnalytics\Models\Anomaly;
use ArtisanPackUI\SecurityAnalytics\Models\SecurityIncident;
use ArtisanPackUI\SecurityAnalytics\Models\SecurityMetric;

class TrendReport extends AbstractReport
{
    public function generate(): array
    {
        $startDate = $this->options['start_date'];
        $endDate   = $this->options['end_date'];

        return [
            'anomaly_trends'  => $this->getAnomalyTrends( $startDate, $endDate ),
            'incident_trends' => $this->getIncidentTrends( $startDate, $endDate ),
            'metric_trends'   => $this->getMetricTrends( $startDate, $endDate ),
            'comparison'      => $this->getPeriodComparison( $startDate, $endDate ),
            'period'          => ['start' => $startDate->format( 'Y-m-d' ), 'end' => $endDate->format( 'Y-m-d' )],
        ];
    }

    protected function getTitle(): string
    {
        return 'Security Trends Report';
    }

    protected function getAnomalyTrends( $startDate, $endDate ): array
    {
        return Anomaly::whereBetween( 'detected_at', [$startDate, $endDate] )
            ->selectRaw( 'DATE(detected_at) as date' )
            ->selectRaw( 'COUNT(*) as count' )
            ->selectRaw( 'AVG(score) as avg_score' )
            ->groupBy( 'date' )
            ->orderBy( 'date' )
            ->get()
            ->toArray();
    }

    protected function getIncidentTrends( $startDate, $endDate ): array
    {
        return SecurityIncident::whereBetween( 'opened_at', [$startDate, $endDate] )
            ->selectRaw( 'DATE(opened_at) as date' )
            ->selectRaw( 'COUNT(*) as opened' )
            ->groupBy( 'date' )
            ->orderBy( 'date' )
            ->get()
            ->toArray();
    }

    protected function getMetricTrends( $startDate, $endDate ): array
    {
        return SecurityMetric::whereBetween( 'recorded_at', [$startDate, $endDate] )
            ->selectRaw( 'DATE(recorded_at) as date' )
            ->selectRaw( 'category' )
            ->selectRaw( 'SUM(value) as total' )
            ->groupBy( 'date', 'category' )
            ->orderBy( 'date' )
            ->get()
            ->groupBy( 'category' )
            ->toArray();
    }

    protected function getPeriodComparison( $startDate, $endDate ): array
    {
        $days          = $startDate->diffInDays( $endDate );
        $previousStart = $startDate->copy()->subDays( $days );
        $previousEnd   = $startDate->copy()->subDay();

        $current  = Anomaly::whereBetween( 'detected_at', [$startDate, $endDate] )->count();
        $previous = Anomaly::whereBetween( 'detected_at', [$previousStart, $previousEnd] )->count();

        return [
            'current_period'  => $current,
            'previous_period' => $previous,
            'change'          => $previous > 0 ? round( ( ( $current - $previous ) / $previous ) * 100, 1 ) : 0,
            'direction'       => $current > $previous ? 'increase' : ( $current < $previous ? 'decrease' : 'stable' ),
        ];
    }

    protected function renderHtmlContent( array $data ): string
    {
        $html = '<h2>Period Comparison</h2>';
        $html .= $this->renderStatCards( $data['comparison'] );

        $html .= '<h2>Daily Anomaly Trends</h2>';
        $html .= $this->renderTable( $data['anomaly_trends'] );

        $html .= '<h2>Daily Incident Trends</h2>';
        $html .= $this->renderTable( $data['incident_trends'] );

        return $html;
    }

    protected function getCsvRows( array $data ): array
    {
        return $data['anomaly_trends'];
    }
}
