<?php

declare( strict_types=1 );

namespace ArtisanPackUI\SecurityAnalytics\Livewire;

use ArtisanPackUI\SecurityAnalytics\Contracts\SecurityEventLoggerInterface;
use ArtisanPackUI\SecurityAnalytics\Models\SecurityEvent;
use Livewire\Component;

class SecurityStats extends Component
{
    public int $days = 7;

    public array $topIps = [];

    public array $topUsers = [];

    public array $eventFrequencyChart = [];

    public array $ipHeaders = [
        ['key' => 'ip_address', 'label' => 'IP Address'],
        ['key' => 'count', 'label' => 'Events'],
    ];

    public array $userHeaders = [
        ['key' => 'user_id', 'label' => 'User ID'],
        ['key' => 'email', 'label' => 'Email'],
        ['key' => 'count', 'label' => 'Events'],
    ];

    public function mount( SecurityEventLoggerInterface $logger ): void
    {
        $this->loadStats( $logger );
    }

    public function updatedDays( SecurityEventLoggerInterface $logger ): void
    {
        $this->loadStats( $logger );
    }

    public function render()
    {
        return view( 'security::livewire.security-stats' );
    }

    protected function loadStats( SecurityEventLoggerInterface $logger ): void
    {
        $stats = $logger->getEventStats( $this->days );

        $this->topIps = collect( $stats['topIps'] )
            ->map( fn ( $count, $ip ) => ['ip_address' => $ip, 'count' => $count] )
            ->values()
            ->toArray();

        $userModel       = config( 'auth.providers.users.model' );
        $canResolveUsers = is_string( $userModel )
            && class_exists( $userModel )
            && is_subclass_of( $userModel, \Illuminate\Database\Eloquent\Model::class );

        $this->topUsers = collect( $stats['topUsers'] )
            ->map( function ( $count, $userId ) use ( $userModel, $canResolveUsers ) {
                $user = $canResolveUsers ? $userModel::find( $userId ) : null;

                return [
                    'user_id' => $userId,
                    'email'   => $user?->email ?? 'Unknown',
                    'count'   => $count,
                ];
            } )
            ->values()
            ->toArray();

        $this->eventFrequencyChart = $this->buildFrequencyChart();
    }

    protected function buildFrequencyChart(): array
    {
        $startDate = now()->subDays( $this->days );

        $dailyCounts = SecurityEvent::where( 'created_at', '>=', $startDate )
            ->selectRaw( 'CAST(created_at AS DATE) as date, COUNT(*) as count' )
            ->groupBy( 'date' )
            ->orderBy( 'date' )
            ->pluck( 'count', 'date' )
            ->toArray();

        $labels = [];
        $data   = [];

        for ( $i = $this->days - 1; $i >= 0; $i-- ) {
            $date     = now()->subDays( $i )->format( 'Y-m-d' );
            $labels[] = now()->subDays( $i )->format( 'M j' );
            $data[]   = $dailyCounts[ $date ] ?? 0;
        }

        return [
            'type' => 'line',
            'data' => [
                'labels'   => $labels,
                'datasets' => [
                    [
                        'label'           => 'Events',
                        'data'            => $data,
                        'borderColor'     => 'rgba(59, 130, 246, 1)',
                        'backgroundColor' => 'rgba(59, 130, 246, 0.1)',
                        'fill'            => true,
                        'tension'         => 0.3,
                    ],
                ],
            ],
            'options' => [
                'responsive'          => true,
                'maintainAspectRatio' => false,
            ],
        ];
    }
}
