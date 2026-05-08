<?php

declare( strict_types=1 );

namespace ArtisanPackUI\SecurityAnalytics\Livewire;

use ArtisanPackUI\SecurityAnalytics\Models\SecurityEvent;
use Livewire\Attributes\Url;
use Livewire\Component;
use Livewire\WithPagination;

class SecurityEventList extends Component
{
    use WithPagination;

    #[Url]
    public string $filterType = '';

    #[Url]
    public string $filterSeverity = '';

    #[Url]
    public string $filterFromDate = '';

    #[Url]
    public string $filterToDate = '';

    #[Url]
    public string $search = '';

    public string $sortBy = 'created_at';

    public string $sortDirection = 'desc';

    public int $perPage = 25;

    public ?SecurityEvent $selectedEvent = null;

    public array $headers = [
        ['key' => 'id', 'label' => 'ID', 'sortable' => true],
        ['key' => 'event_type', 'label' => 'Type', 'sortable' => true],
        ['key' => 'event_name', 'label' => 'Event', 'sortable' => true],
        ['key' => 'severity', 'label' => 'Severity', 'sortable' => true],
        ['key' => 'user_id', 'label' => 'User', 'sortable' => true],
        ['key' => 'ip_address', 'label' => 'IP', 'sortable' => true],
        ['key' => 'created_at', 'label' => 'Time', 'sortable' => true],
    ];

    public array $eventTypes = [
        ''                                     => 'All Types',
        SecurityEvent::TYPE_AUTHENTICATION     => 'Authentication',
        SecurityEvent::TYPE_AUTHORIZATION      => 'Authorization',
        SecurityEvent::TYPE_API_ACCESS         => 'API Access',
        SecurityEvent::TYPE_SECURITY_VIOLATION => 'Security Violation',
        SecurityEvent::TYPE_ROLE_CHANGE        => 'Role Change',
        SecurityEvent::TYPE_PERMISSION_CHANGE  => 'Permission Change',
        SecurityEvent::TYPE_TOKEN_MANAGEMENT   => 'Token Management',
    ];

    public array $severities = [
        ''                               => 'All Severities',
        SecurityEvent::SEVERITY_DEBUG    => 'Debug',
        SecurityEvent::SEVERITY_INFO     => 'Info',
        SecurityEvent::SEVERITY_WARNING  => 'Warning',
        SecurityEvent::SEVERITY_ERROR    => 'Error',
        SecurityEvent::SEVERITY_CRITICAL => 'Critical',
    ];

    /**
     * Allowed columns for sorting to prevent SQL injection.
     */
    protected array $sortableColumns = [
        'id',
        'event_type',
        'event_name',
        'severity',
        'user_id',
        'ip_address',
        'created_at',
    ];

    public function updatingSearch(): void
    {
        $this->resetPage();
    }

    public function updatingFilterType(): void
    {
        $this->resetPage();
    }

    public function updatingFilterSeverity(): void
    {
        $this->resetPage();
    }

    public function sort( string $column ): void
    {
        if ( ! in_array( $column, $this->sortableColumns, true ) ) {
            return;
        }

        if ( $this->sortBy === $column ) {
            $this->sortDirection = 'asc' === $this->sortDirection ? 'desc' : 'asc';
        } else {
            $this->sortBy        = $column;
            $this->sortDirection = 'asc';
        }
    }

    public function showEvent( int $id ): void
    {
        $event = SecurityEvent::with( 'user' )->findOrFail( $id );

        if ( ! auth()->user()?->can( 'view-security-events' ) ) {
            abort( 403, 'Unauthorized to view security event details.' );
        }

        $this->selectedEvent = $event;
        $this->dispatch( 'open-modal', id: 'eventDetailModal' );
    }

    public function export( string $format ): \Symfony\Component\HttpFoundation\StreamedResponse
    {
        if ( !auth()->user()?->can( 'export-security-events' ) ) {
            abort( 403, 'Unauthorized to export security events.' );
        }

        $events = $this->getFilteredQuery()->get();

        $filename = 'security-events-' . now()->format( 'Y-m-d-His' ) . '.' . $format;

        if ( 'json' === $format ) {
            return response()->streamDownload( function () use ( $events ): void {
                echo json_encode( $events->toArray(), JSON_PRETTY_PRINT );
            }, $filename, ['Content-Type' => 'application/json'] );
        }

        return response()->streamDownload( function () use ( $events ): void {
            $handle = fopen( 'php://output', 'w' );
            fputcsv( $handle, ['ID', 'Type', 'Name', 'Severity', 'User ID', 'IP', 'User Agent', 'URL', 'Method', 'Details', 'Created At'] );

            foreach ( $events as $event ) {
                fputcsv( $handle, [
                    $event->id,
                    $event->event_type,
                    $event->event_name,
                    $event->severity,
                    $event->user_id ?? '',
                    $event->ip_address,
                    $event->user_agent ?? '',
                    $event->url ?? '',
                    $event->method ?? '',
                    json_encode( $event->details ?? [] ),
                    $event->created_at->toIso8601String(),
                ] );
            }

            fclose( $handle );
        }, $filename, ['Content-Type' => 'text/csv'] );
    }

    public function render()
    {
        return view( 'security::livewire.security-event-list', [
            'events' => $this->getFilteredQuery()
                ->orderBy( $this->sortBy, $this->sortDirection )
                ->paginate( $this->perPage ),
        ] );
    }

    protected function getFilteredQuery()
    {
        $query = SecurityEvent::query()->with( 'user' );

        if ( $this->filterType ) {
            $query->byType( $this->filterType );
        }

        if ( $this->filterSeverity ) {
            $query->bySeverity( $this->filterSeverity );
        }

        if ( $this->filterFromDate ) {
            $query->where( 'created_at', '>=', $this->filterFromDate );
        }

        if ( $this->filterToDate ) {
            $query->where( 'created_at', '<=', $this->filterToDate . ' 23:59:59' );
        }

        if ( $this->search ) {
            $query->where( function ( $q ): void {
                $q->where( 'event_name', 'like', "%{$this->search}%" )
                    ->orWhere( 'ip_address', 'like', "%{$this->search}%" )
                    ->orWhere( 'url', 'like', "%{$this->search}%" );
            } );
        }

        return $query;
    }
}
