<?php

declare( strict_types=1 );

namespace ArtisanPackUI\SecurityAnalytics\Livewire;

use ArtisanPackUI\SecurityAnalytics\Models\SuspiciousActivity;
use Illuminate\Support\Facades\Auth;
use Livewire\Component;
use Livewire\WithPagination;

class SuspiciousActivityList extends Component
{
    use WithPagination;

    public string $filterSeverity = '';

    public string $filterType = '';

    public int $perPage = 10;

    public function mount(): void
    {
        // Check authorization
        if ( ! Auth::check() ) {
            abort( 403 );
        }
    }

    public function updatingFilterSeverity(): void
    {
        $this->resetPage();
    }

    public function updatingFilterType(): void
    {
        $this->resetPage();
    }

    public function getActivitiesProperty()
    {
        $user    = Auth::user();
        $isAdmin = $user->can( 'view-all-suspicious-activity' );

        $query = SuspiciousActivity::query()
            ->when( ! $isAdmin, fn ( $q ) => $q->where( 'user_id', $user->id ) )
            ->when( $this->filterSeverity, fn ( $q ) => $q->where( 'severity', $this->filterSeverity ) )
            ->when( $this->filterType, fn ( $q ) => $q->where( 'type', $this->filterType ) )
            ->orderBy( 'created_at', 'desc' );

        return $query->paginate( $this->perPage );
    }

    public function getSeverityOptionsProperty(): array
    {
        return [
            ''                                    => 'All Severities',
            SuspiciousActivity::SEVERITY_LOW      => 'Low',
            SuspiciousActivity::SEVERITY_MEDIUM   => 'Medium',
            SuspiciousActivity::SEVERITY_HIGH     => 'High',
            SuspiciousActivity::SEVERITY_CRITICAL => 'Critical',
        ];
    }

    public function getTypeOptionsProperty(): array
    {
        return [
            ''                                           => 'All Types',
            SuspiciousActivity::TYPE_IMPOSSIBLE_TRAVEL   => 'Impossible Travel',
            SuspiciousActivity::TYPE_BRUTE_FORCE         => 'Brute Force',
            SuspiciousActivity::TYPE_CREDENTIAL_STUFFING => 'Credential Stuffing',
            SuspiciousActivity::TYPE_UNUSUAL_LOCATION    => 'Unusual Location',
            SuspiciousActivity::TYPE_UNUSUAL_DEVICE      => 'Unusual Device',
            SuspiciousActivity::TYPE_UNUSUAL_TIME        => 'Unusual Time',
            SuspiciousActivity::TYPE_RAPID_REQUESTS      => 'Rapid Requests',
            SuspiciousActivity::TYPE_BOT_BEHAVIOR        => 'Bot Behavior',
            SuspiciousActivity::TYPE_SESSION_ANOMALY     => 'Session Anomaly',
            SuspiciousActivity::TYPE_ACCOUNT_ENUMERATION => 'Account Enumeration',
        ];
    }

    public function getSeverityClass( string $severity ): string
    {
        return match ( $severity ) {
            SuspiciousActivity::SEVERITY_LOW      => 'bg-gray-100 text-gray-800',
            SuspiciousActivity::SEVERITY_MEDIUM   => 'bg-yellow-100 text-yellow-800',
            SuspiciousActivity::SEVERITY_HIGH     => 'bg-orange-100 text-orange-800',
            SuspiciousActivity::SEVERITY_CRITICAL => 'bg-red-100 text-red-800',
            default                               => 'bg-gray-100 text-gray-800',
        };
    }

    public function render()
    {
        return view( 'security::livewire.suspicious-activity-list', [
            'activities' => $this->activities,
        ]);
    }
}
