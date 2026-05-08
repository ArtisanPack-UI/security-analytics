<?php

declare( strict_types=1 );

namespace ArtisanPackUI\SecurityAnalytics\Analytics\Reports;

use ArtisanPackUI\SecurityAnalytics\Models\SecurityMetric;

class ComplianceReport extends AbstractReport
{
    public function generate(): array
    {
        $startDate = $this->options['start_date'] ?? now()->subMonth();
        $endDate   = $this->options['end_date'] ?? now();

        // Ensure dates are Carbon instances
        $startDate = $startDate instanceof \Carbon\Carbon ? $startDate : \Carbon\Carbon::parse( $startDate );
        $endDate   = $endDate instanceof \Carbon\Carbon ? $endDate : \Carbon\Carbon::parse( $endDate );

        $metrics = SecurityMetric::category( SecurityMetric::CATEGORY_COMPLIANCE )
            ->whereBetween( 'recorded_at', [$startDate, $endDate] )
            ->get();

        return [
            'summary' => [
                'total_checks' => $metrics->count(),
                'passed'       => $metrics->where( 'tags.status', 'passed' )->count(),
                'failed'       => $metrics->where( 'tags.status', 'failed' )->count(),
            ],
            'controls' => $metrics->groupBy( 'metric_name' )->map( fn ( $group ) => [
                'checks' => $group->count(),
                'passed' => $group->where( 'tags.status', 'passed' )->count(),
                'failed' => $group->where( 'tags.status', 'failed' )->count(),
            ] )->toArray(),
            'period' => ['start' => $startDate->format( 'Y-m-d' ), 'end' => $endDate->format( 'Y-m-d' )],
        ];
    }

    protected function getTitle(): string
    {
        return 'Security Compliance Report';
    }

    protected function renderHtmlContent( array $data ): string
    {
        $html = '<h2>Summary</h2>';
        $html .= $this->renderStatCards( $data['summary'] );
        $html .= '<h2>Controls</h2>';
        $html .= $this->renderTable(
            collect( $data['controls'] )->map( fn ( $c, $name ) => array_merge( ['control' => $name], $c ) )->values()->toArray(),
        );

        return $html;
    }

    protected function getCsvRows( array $data ): array
    {
        return collect( $data['controls'] )->map( fn ( $c, $name ) => array_merge( ['control' => $name], $c))->values()->toArray();
    }
}
