<?php

declare( strict_types=1 );

namespace ArtisanPackUI\SecurityAnalytics\Analytics\Reports;

use ArtisanPackUI\SecurityAnalytics\Models\SecurityIncident;
use Carbon\Carbon;
use DateTimeInterface;
use Exception;
use InvalidArgumentException;

class IncidentReport extends AbstractReport
{
    public function generate(): array
    {
        $startDate = $this->parseDate( $this->options['start_date'] ?? null, 'start_date' );
        $endDate   = $this->parseDate( $this->options['end_date'] ?? null, 'end_date' );

        $incidents = SecurityIncident::whereBetween( 'opened_at', [$startDate, $endDate] )->get();

        return [
            'summary' => [
                'total'         => $incidents->count(),
                'open'          => $incidents->where( 'status', SecurityIncident::STATUS_OPEN )->count(),
                'investigating' => $incidents->where( 'status', SecurityIncident::STATUS_INVESTIGATING )->count(),
                'contained'     => $incidents->where( 'status', SecurityIncident::STATUS_CONTAINED )->count(),
                'resolved'      => $incidents->where( 'status', SecurityIncident::STATUS_RESOLVED )->count(),
                'closed'        => $incidents->where( 'status', SecurityIncident::STATUS_CLOSED )->count(),
            ],
            'incidents' => $incidents->map( fn ( $i ) => [
                'incident_number' => $i->incident_number,
                'title'           => $i->title,
                'severity'        => $i->severity,
                'status'          => $i->status,
                'category'        => $i->category,
                'opened_at'       => $i->opened_at?->format( 'Y-m-d H:i:s' ),
                'resolved_at'     => $i->resolved_at?->format( 'Y-m-d H:i:s' ),
                'time_to_resolve' => $i->getTimeToResolve(),
            ] )->toArray(),
            'period' => ['start' => $startDate->format( 'Y-m-d' ), 'end' => $endDate->format( 'Y-m-d' )],
        ];
    }

    protected function getTitle(): string
    {
        return 'Security Incident Report';
    }

    protected function renderHtmlContent( array $data ): string
    {
        $html = '<h2>Summary</h2>';
        $html .= $this->renderStatCards( $data['summary'] );
        $html .= '<h2>Incidents</h2>';
        $html .= $this->renderTable( $data['incidents'] );

        return $html;
    }

    protected function getCsvRows( array $data ): array
    {
        return $data['incidents'];
    }

    /**
     * Parse and validate a date option.
     *
     * @throws InvalidArgumentException
     */
    protected function parseDate( mixed $value, string $fieldName ): Carbon
    {
        if ( null === $value || '' === $value ) {
            throw new InvalidArgumentException( "The '{$fieldName}' option is required" );
        }

        // Already a DateTime/Carbon instance
        if ( $value instanceof DateTimeInterface ) {
            return Carbon::instance( $value );
        }

        // Already a Carbon instance
        if ( $value instanceof Carbon ) {
            return $value;
        }

        // Try to parse string value
        if ( is_string( $value ) ) {
            try {
                return Carbon::parse( $value );
            } catch ( Exception $e ) {
                throw new InvalidArgumentException(
                    "Invalid date format for '{$fieldName}': {$value}. Please provide a valid date string or DateTime instance.",
                );
            }
        }

        throw new InvalidArgumentException(
            "Invalid type for '{$fieldName}': expected DateTime, Carbon, or date string, got " . gettype( $value),
        );
    }
}
