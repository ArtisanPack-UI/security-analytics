<?php

declare( strict_types=1 );

namespace ArtisanPackUI\SecurityAnalytics\Analytics\Reports;

use ArtisanPackUI\SecurityAnalytics\Models\Anomaly;
use ArtisanPackUI\SecurityAnalytics\Models\SecurityMetric;

class UserActivityReport extends AbstractReport
{
    public function generate(): array
    {
        $startDate = $this->options['start_date'];
        $endDate   = $this->options['end_date'];
        $userId    = $this->options['user_id'] ?? null;

        $authMetrics = SecurityMetric::category( SecurityMetric::CATEGORY_AUTHENTICATION )
            ->whereBetween( 'recorded_at', [$startDate, $endDate] );

        if ( $userId ) {
            $authMetrics->whereJsonContains( 'tags->user_id', $userId );
        }

        $authMetrics = $authMetrics->get();

        $anomalies = Anomaly::whereBetween( 'detected_at', [$startDate, $endDate] );
        if ( $userId ) {
            $anomalies->where( 'user_id', $userId );
        }
        $anomalies = $anomalies->get();

        return [
            'summary' => [
                'total_logins'    => $authMetrics->where( 'metric_name', 'auth.login' )->whereIn( 'tags.success', [true, 'true', 1] )->sum( 'value' ),
                'failed_logins'   => $authMetrics->where( 'metric_name', 'auth.failed' )->sum( 'value' ),
                'password_resets' => $authMetrics->where( 'metric_name', 'auth.password_reset' )->sum( 'value' ),
                'anomalies'       => $anomalies->count(),
            ],
            'activity_by_hour' => $authMetrics->groupBy( fn ( $m ) => $m->recorded_at->format( 'H' ) )
                ->map->sum( 'value' )
                ->toArray(),
            'anomalies' => $anomalies->map( fn ( $a ) => [
                'category'    => $a->category,
                'severity'    => $a->severity,
                'description' => $a->description,
                'detected_at' => $a->detected_at->format( 'Y-m-d H:i:s' ),
            ] )->toArray(),
            'period' => ['start' => $startDate->format( 'Y-m-d' ), 'end' => $endDate->format( 'Y-m-d' )],
        ];
    }

    protected function getTitle(): string
    {
        return 'User Activity Report';
    }

    protected function renderHtmlContent( array $data ): string
    {
        $html = '<h2>Summary</h2>';
        $html .= $this->renderStatCards( $data['summary'] );
        $html .= '<h2>User Anomalies</h2>';
        $html .= $this->renderTable( $data['anomalies'] );

        return $html;
    }

    protected function getCsvRows( array $data): array
    {
        return $data['anomalies'];
    }
}
