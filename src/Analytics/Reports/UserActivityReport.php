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

        // Build a single query that filters at the database level — pulling
        // every authentication metric and post-filtering with Collection::where
        // doesn't scale, and `Collection::whereIn` doesn't even exist (the
        // method is on the query builder).
        $authQuery = SecurityMetric::category( SecurityMetric::CATEGORY_AUTHENTICATION )
            ->whereBetween( 'recorded_at', [$startDate, $endDate] );

        if ( $userId ) {
            $authQuery->whereJsonContains( 'tags->user_id', $userId );
        }

        $authMetrics = $authQuery->get();

        $loginSuccessQuery = ( clone $authQuery )
            ->where( 'metric_name', 'auth.login' )
            ->where( function ( $q ): void {
                $q->whereJsonContains( 'tags->success', true )
                    ->orWhereJsonContains( 'tags->success', 'true' )
                    ->orWhereJsonContains( 'tags->success', 1 );
            } );

        $totalLogins     = (int) $loginSuccessQuery->sum( 'value' );
        $failedLogins    = (int) ( clone $authQuery )->where( 'metric_name', 'auth.failed' )->sum( 'value' );
        $passwordResets  = (int) ( clone $authQuery )->where( 'metric_name', 'auth.password_reset' )->sum( 'value' );

        $anomalies = Anomaly::whereBetween( 'detected_at', [$startDate, $endDate] );
        if ( $userId ) {
            $anomalies->where( 'user_id', $userId );
        }
        $anomalies = $anomalies->get();

        return [
            'summary' => [
                'total_logins'    => $totalLogins,
                'failed_logins'   => $failedLogins,
                'password_resets' => $passwordResets,
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

    protected function getCsvRows( array $data ): array
    {
        return $data['anomalies'];
    }
}
