{{--
    Security Dashboard.

    Plain HTML + Tailwind by design — this package does not depend on
    artisanpack-ui/livewire-ui-components. Override this view in your app
    if you want richer chart / card / icon components.
--}}
<div>
    <h1 class="text-2xl font-bold mb-6">{{ __( 'Security Dashboard' ) }}</h1>

    {{-- Statistics cards --}}
    <div class="grid grid-cols-1 md:grid-cols-4 gap-4 mb-6">
        <div class="bg-white shadow rounded-lg p-4">
            <div class="text-sm font-medium text-gray-500">{{ __( 'Events (24h)' ) }}</div>
            <div class="text-2xl font-bold mt-1">{{ number_format( $eventsToday ) }}</div>
            <div class="text-xs text-gray-500 mt-1">{{ $eventsTodayChange }}% {{ __( 'from yesterday' ) }}</div>
        </div>
        <div class="bg-white shadow rounded-lg p-4">
            <div class="text-sm font-medium text-gray-500">{{ __( 'Failed Logins' ) }}</div>
            <div class="text-2xl font-bold mt-1 text-red-600">{{ number_format( $failedLogins ) }}</div>
        </div>
        <div class="bg-white shadow rounded-lg p-4">
            <div class="text-sm font-medium text-gray-500">{{ __( 'Auth Failures' ) }}</div>
            <div class="text-2xl font-bold mt-1 text-yellow-600">{{ number_format( $authFailures ) }}</div>
        </div>
        <div class="bg-white shadow rounded-lg p-4">
            <div class="text-sm font-medium text-gray-500">{{ __( 'API Errors' ) }}</div>
            <div class="text-2xl font-bold mt-1 text-blue-600">{{ number_format( $apiErrors ) }}</div>
        </div>
    </div>

    {{-- Charts placeholder --}}
    {{--
        Chart rendering is left to the consumer — the component exposes
        $eventsByTypeChart and $eventsBySeverityChart data on the public
        properties. Wire them up to your charting library of choice (Chart.js,
        ApexCharts, etc.) in a published override of this view.
    --}}
    <div class="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-6">
        <div class="bg-white shadow rounded-lg p-4">
            <h3 class="text-lg font-bold mb-3">{{ __( 'Events by Type' ) }}</h3>
            <div class="h-64 flex items-center justify-center text-sm text-gray-400">
                {{ __( 'Chart data available on $eventsByTypeChart — override this view to render.' ) }}
            </div>
        </div>
        <div class="bg-white shadow rounded-lg p-4">
            <h3 class="text-lg font-bold mb-3">{{ __( 'Events by Severity' ) }}</h3>
            <div class="h-64 flex items-center justify-center text-sm text-gray-400">
                {{ __( 'Chart data available on $eventsBySeverityChart — override this view to render.' ) }}
            </div>
        </div>
    </div>

    {{-- Recent suspicious activity --}}
    <div class="bg-white shadow rounded-lg p-4">
        <h3 class="text-lg font-bold mb-3">{{ __( 'Recent Suspicious Activity' ) }}</h3>
        @forelse ( $suspiciousEvents as $event )
            <div wire:key="dashboard-suspicious-{{ $loop->index }}" class="flex items-center gap-4 p-2 border-b last:border-b-0">
                <span class="inline-block w-2 h-2 rounded-full bg-yellow-500"></span>
                <div class="flex-1">
                    <span class="font-medium">{{ $event['event_name'] }}</span>
                    <span class="text-gray-500 text-sm ml-2">{{ $event['event_type'] }}</span>
                </div>
                <span class="text-sm text-gray-500">{{ $event['created_at_human'] }}</span>
            </div>
        @empty
            <p class="text-gray-500 p-4">{{ __( 'No suspicious activity detected.' ) }}</p>
        @endforelse
    </div>

    {{-- Quick navigation --}}
    <div class="flex gap-4 mt-6">
        <a href="{{ route( 'security.events' ) }}" class="inline-flex items-center px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white text-sm font-medium rounded-md">
            {{ __( 'View All Events' ) }}
        </a>
        <a href="{{ route( 'security.stats' ) }}" class="inline-flex items-center px-4 py-2 bg-white hover:bg-gray-50 text-blue-600 border border-blue-600 text-sm font-medium rounded-md">
            {{ __( 'View Statistics' ) }}
        </a>
    </div>
</div>
