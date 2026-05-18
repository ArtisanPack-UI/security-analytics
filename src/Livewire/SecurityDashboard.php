<?php

/**
 * SecurityDashboard Livewire component.
 *
 * @package    ArtisanPack_UI
 * @subpackage SecurityAnalytics
 *
 * @author     Jacob Martella <support@artisanpackui.dev>
 *
 * @since      1.0.0
 */

declare( strict_types=1 );

namespace ArtisanPackUI\SecurityAnalytics\Livewire;

use ArtisanPackUI\SecurityAnalytics\Contracts\SecurityEventLoggerInterface;
use ArtisanPackUI\SecurityAnalytics\Models\SecurityEvent;
use Livewire\Component;

class SecurityDashboard extends Component
{
    public int $eventsToday = 0;

    public int $eventsTodayChange = 0;

    public int $failedLogins = 0;

    public int $authFailures = 0;

    public int $apiErrors = 0;

    public array $eventsByTypeChart = [];

    public array $eventsBySeverityChart = [];

    public array $suspiciousEvents = [];

    public function mount( SecurityEventLoggerInterface $logger ): void
    {
        if ( !auth()->user()?->can( 'view-security-dashboard' ) ) {
            abort( 403, 'Unauthorized to view security dashboard.' );
        }

        $stats          = $logger->getEventStats( 1 );
        $yesterdayStats = $this->getYesterdayStats();

        $this->eventsToday       = $stats['total'];
        $this->eventsTodayChange = $yesterdayStats > 0
            ? (int) round( ( ( $stats['total'] - $yesterdayStats ) / $yesterdayStats ) * 100 )
            : 0;

        $this->failedLogins = $stats['failedLogins'];
        $this->authFailures = $stats['authorizationFailures'];
        $this->apiErrors    = ( $stats['byType'][SecurityEvent::TYPE_API_ACCESS] ?? 0 );

        $this->eventsByTypeChart     = $this->buildEventsByTypeChart( $stats['byType'] );
        $this->eventsBySeverityChart = $this->buildEventsBySeverityChart( $stats['bySeverity'] );

        $this->suspiciousEvents = SecurityEvent::suspicious()
            ->recent( 24 )
            ->latest( 'created_at' )
            ->limit( 5 )
            ->get()
            ->map( fn ( $event ) => [
                'event_name'       => $event->event_name,
                'event_type'       => $event->event_type,
                'created_at_human' => $event->created_at->diffForHumans(),
            ] )
            ->toArray();
    }

    public function render()
    {
        return view( 'security-analytics::livewire.security-dashboard' );
    }

    protected function getYesterdayStats(): int
    {
        return SecurityEvent::whereBetween( 'created_at', [
            now()->subDays( 2 )->startOfDay(),
            now()->subDay()->endOfDay(),
        ] )->count();
    }

    protected function buildEventsByTypeChart( array $byType ): array
    {
        return [
            'type' => 'pie',
            'data' => [
                'labels'   => array_keys( $byType ),
                'datasets' => [
                    [
                        'data'            => array_values( $byType ),
                        'backgroundColor' => [
                            'rgba(59, 130, 246, 0.5)',
                            'rgba(245, 158, 11, 0.5)',
                            'rgba(16, 185, 129, 0.5)',
                            'rgba(239, 68, 68, 0.5)',
                            'rgba(139, 92, 246, 0.5)',
                            'rgba(236, 72, 153, 0.5)',
                        ],
                    ],
                ],
            ],
        ];
    }

    protected function buildEventsBySeverityChart( array $bySeverity ): array
    {
        $colors = [
            'debug'    => 'rgba(156, 163, 175, 0.5)',
            'info'     => 'rgba(59, 130, 246, 0.5)',
            'warning'  => 'rgba(245, 158, 11, 0.5)',
            'error'    => 'rgba(239, 68, 68, 0.5)',
            'critical' => 'rgba(220, 38, 38, 0.8)',
        ];

        return [
            'type' => 'bar',
            'data' => [
                'labels'   => array_keys( $bySeverity ),
                'datasets' => [
                    [
                        'label'           => 'Events',
                        'data'            => array_values( $bySeverity ),
                        'backgroundColor' => array_map(
                            fn ( $severity ) => $colors[ $severity ] ?? 'rgba(156, 163, 175, 0.5)',
                            array_keys( $bySeverity ),
                        ),
                    ],
                ],
            ],
        ];
    }
}
