<?php

/**
 * ThreatReport report.
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
use ArtisanPackUI\SecurityAnalytics\Models\ThreatIndicator;

class ThreatReport extends AbstractReport
{
    /**
     * {@inheritdoc}
     */
    public function generate(): array
    {
        $startDate = $this->options['start_date'];
        $endDate   = $this->options['end_date'];

        return [
            'summary'           => $this->getSummary( $startDate, $endDate ),
            'anomalies'         => $this->getAnomalies( $startDate, $endDate ),
            'threat_indicators' => $this->getThreatIndicators(),
            'attack_patterns'   => $this->getAttackPatterns( $startDate, $endDate ),
            'period'            => [
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
        return 'Threat Intelligence Report';
    }

    /**
     * Get summary statistics.
     *
     * @return array<string, mixed>
     */
    protected function getSummary( $startDate, $endDate ): array
    {
        $anomalies = Anomaly::whereBetween( 'detected_at', [$startDate, $endDate] )->get();

        return [
            'total_anomalies'          => $anomalies->count(),
            'critical'                 => $anomalies->where( 'severity', 'critical' )->count(),
            'high'                     => $anomalies->where( 'severity', 'high' )->count(),
            'medium'                   => $anomalies->where( 'severity', 'medium' )->count(),
            'low'                      => $anomalies->where( 'severity', 'low' )->count(),
            'resolved'                 => $anomalies->whereNotNull( 'resolved_at' )->count(),
            'unresolved'               => $anomalies->whereNull( 'resolved_at' )->count(),
            'active_threat_indicators' => ThreatIndicator::active()->count(),
        ];
    }

    /**
     * Get anomalies for the period.
     *
     * @return array<int, array<string, mixed>>
     */
    protected function getAnomalies( $startDate, $endDate ): array
    {
        return Anomaly::whereBetween( 'detected_at', [$startDate, $endDate] )
            ->orderByDesc( 'score' )
            ->get()
            ->map( fn ( Anomaly $a ) => [
                'id'          => $a->id,
                'category'    => $a->category,
                'severity'    => $a->severity,
                'description' => $a->description,
                'score'       => $a->score,
                'detector'    => $a->detector,
                'detected_at' => $a->detected_at->format( 'Y-m-d H:i:s' ),
                'resolved'    => $a->isResolved() ? 'Yes' : 'No',
            ] )
            ->toArray();
    }

    /**
     * Get active threat indicators.
     *
     * @return array<string, mixed>
     */
    protected function getThreatIndicators(): array
    {
        $indicators = ThreatIndicator::active()->get();

        return [
            'total'          => $indicators->count(),
            'by_type'        => $indicators->groupBy( 'type' )->map->count()->toArray(),
            'by_threat_type' => $indicators->groupBy( 'threat_type' )->map->count()->toArray(),
            'recent'         => $indicators->sortByDesc( 'last_seen_at' )->take( 10 )->map( fn ( $i ) => [
                'type'        => $i->type,
                'value'       => $i->value,
                'threat_type' => $i->threat_type,
                'confidence'  => $i->confidence,
                'source'      => $i->source,
            ] )->values()->toArray(),
        ];
    }

    /**
     * Analyze attack patterns.
     *
     * @return array<string, mixed>
     */
    protected function getAttackPatterns( $startDate, $endDate ): array
    {
        $anomalies = Anomaly::whereBetween( 'detected_at', [$startDate, $endDate] )->get();

        // Group by hour to find attack timing patterns
        $byHour = $anomalies->groupBy( fn ( $a ) => $a->detected_at->format( 'H' ) )
            ->map->count()
            ->toArray();

        // Group by day of week
        $byDayOfWeek = $anomalies->groupBy( fn ( $a ) => $a->detected_at->format( 'l' ) )
            ->map->count()
            ->toArray();

        // Identify repeat offenders (same user/IP with multiple anomalies)
        $byUser = $anomalies->whereNotNull( 'user_id' )
            ->groupBy( 'user_id' )
            ->filter( fn ( $group ) => $group->count() > 1 )
            ->map( fn ( $group ) => $group->count() )
            ->toArray();

        return [
            'by_hour'          => $byHour,
            'by_day_of_week'   => $byDayOfWeek,
            'repeat_offenders' => count( $byUser ),
            'peak_hour'        => ! empty( $byHour ) ? array_search( max( $byHour ), $byHour ) . ':00' : 'N/A',
        ];
    }

    /**
     * {@inheritdoc}
     */
    protected function renderHtmlContent( array $data ): string
    {
        $html = '';

        // Summary
        $html .= '<h2>Summary</h2>';
        $html .= $this->renderStatCards( $data['summary'] );

        // Anomalies Table
        $html .= '<h2>Detected Anomalies</h2>';
        $html .= $this->renderTable( $data['anomalies'] );

        // Threat Indicators
        $html .= '<h2>Active Threat Indicators</h2>';
        $html .= '<h3>By Type</h3>';
        $html .= $this->renderTable(
            collect( $data['threat_indicators']['by_type'] )->map( fn ( $count, $type ) => [
                'type'  => $type,
                'count' => $count,
            ] )->values()->toArray(),
        );

        // Attack Patterns
        $html .= '<h2>Attack Patterns</h2>';
        $html .= '<p>Peak activity hour: ' . htmlspecialchars( $data['attack_patterns']['peak_hour'] ) . '</p>';
        $html .= '<p>Repeat offenders: ' . $data['attack_patterns']['repeat_offenders'] . '</p>';

        return $html;
    }

    /**
     * {@inheritdoc}
     */
    protected function getCsvRows( array $data ): array
    {
        return $data['anomalies'];
    }
}
