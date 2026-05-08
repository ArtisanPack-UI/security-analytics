<div>
    <h1 class="text-2xl font-bold mb-6">Security Dashboard</h1>

    {{-- Statistics Cards --}}
    <div class="grid grid-cols-1 md:grid-cols-4 gap-4 mb-6">
        <x-artisanpack-stat
            title="Events (24h)"
            :value="number_format($eventsToday)"
            :description="$eventsTodayChange . '% from yesterday'"
            icon="heroicon-o-shield-check"
            color="text-primary"
        />
        <x-artisanpack-stat
            title="Failed Logins"
            :value="number_format($failedLogins)"
            icon="heroicon-o-x-circle"
            color="text-error"
        />
        <x-artisanpack-stat
            title="Auth Failures"
            :value="number_format($authFailures)"
            icon="heroicon-o-lock-closed"
            color="text-warning"
        />
        <x-artisanpack-stat
            title="API Errors"
            :value="number_format($apiErrors)"
            icon="heroicon-o-server"
            color="text-info"
        />
    </div>

    {{-- Charts --}}
    <div class="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-6">
        <x-artisanpack-card>
            <x-slot:header>
                <h3 class="text-lg font-bold">Events by Type</h3>
            </x-slot:header>
            <x-artisanpack-chart wire:model="eventsByTypeChart" class="h-64" />
        </x-artisanpack-card>

        <x-artisanpack-card>
            <x-slot:header>
                <h3 class="text-lg font-bold">Events by Severity</h3>
            </x-slot:header>
            <x-artisanpack-chart wire:model="eventsBySeverityChart" class="h-64" />
        </x-artisanpack-card>
    </div>

    {{-- Recent Suspicious Activity --}}
    <x-artisanpack-card>
        <x-slot:header>
            <h3 class="text-lg font-bold">Recent Suspicious Activity</h3>
        </x-slot:header>
        @forelse($suspiciousEvents as $event)
            <div class="flex items-center gap-4 p-2 border-b last:border-b-0">
                <x-artisanpack-icon name="heroicon-o-exclamation-triangle" class="w-5 h-5 text-warning" />
                <div class="flex-1">
                    <span class="font-medium">{{ $event['event_name'] }}</span>
                    <span class="text-gray-500 text-sm ml-2">{{ $event['event_type'] }}</span>
                </div>
                <span class="text-sm text-gray-500">{{ $event['created_at_human'] }}</span>
            </div>
        @empty
            <p class="text-gray-500 p-4">No suspicious activity detected.</p>
        @endforelse
    </x-artisanpack-card>

    {{-- Quick Navigation --}}
    <div class="flex gap-4 mt-6">
        <x-artisanpack-button href="{{ route('security.events') }}" color="primary">
            View All Events
        </x-artisanpack-button>
        <x-artisanpack-button href="{{ route('security.stats') }}" color="primary" outline>
            View Statistics
        </x-artisanpack-button>
    </div>
</div>
