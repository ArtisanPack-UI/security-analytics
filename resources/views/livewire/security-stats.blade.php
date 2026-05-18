{{--
    Security Statistics.

    Plain HTML + Tailwind by design — this package does not depend on
    artisanpack-ui/livewire-ui-components.
--}}
<div>
    <div class="flex justify-between items-center mb-6">
        <h1 class="text-2xl font-bold">{{ __( 'Security Statistics' ) }}</h1>
        <div>
            <label for="stats-days" class="sr-only">{{ __( 'Time range' ) }}</label>
            <select id="stats-days" wire:model.live="days" class="rounded-md border-gray-300 shadow-sm focus:border-blue-500 focus:ring-blue-500 sm:text-sm">
                <option value="7">{{ __( 'Last 7 days' ) }}</option>
                <option value="14">{{ __( 'Last 14 days' ) }}</option>
                <option value="30">{{ __( 'Last 30 days' ) }}</option>
                <option value="90">{{ __( 'Last 90 days' ) }}</option>
            </select>
        </div>
    </div>

    <div class="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-6">
        {{-- Top IPs --}}
        <div class="bg-white shadow rounded-lg p-4">
            <h3 class="text-lg font-bold mb-3">{{ __( 'Top IPs by Event Count' ) }}</h3>
            @if ( count( $topIps ) > 0 )
                <table class="w-full">
                    <thead>
                        <tr class="border-b">
                            @foreach ( $ipHeaders as $key => $label )
                                <th class="text-left px-3 py-2 text-sm font-semibold text-gray-700">{{ $label }}</th>
                            @endforeach
                        </tr>
                    </thead>
                    <tbody>
                        @foreach ( $topIps as $row )
                            <tr class="border-b">
                                @foreach ( $ipHeaders as $key => $label )
                                    <td class="px-3 py-2 text-sm {{ $key === 'ip_address' ? 'font-mono' : '' }}">{{ $row[ $key ] ?? '' }}</td>
                                @endforeach
                            </tr>
                        @endforeach
                    </tbody>
                </table>
            @else
                <p class="text-gray-500 p-4 text-center">{{ __( 'No data available.' ) }}</p>
            @endif
        </div>

        {{-- Top Users --}}
        <div class="bg-white shadow rounded-lg p-4">
            <h3 class="text-lg font-bold mb-3">{{ __( 'Top Users by Event Count' ) }}</h3>
            @if ( count( $topUsers ) > 0 )
                <table class="w-full">
                    <thead>
                        <tr class="border-b">
                            @foreach ( $userHeaders as $key => $label )
                                <th class="text-left px-3 py-2 text-sm font-semibold text-gray-700">{{ $label }}</th>
                            @endforeach
                        </tr>
                    </thead>
                    <tbody>
                        @foreach ( $topUsers as $row )
                            <tr class="border-b">
                                @foreach ( $userHeaders as $key => $label )
                                    <td class="px-3 py-2 text-sm">{{ $row[ $key ] ?? '' }}</td>
                                @endforeach
                            </tr>
                        @endforeach
                    </tbody>
                </table>
            @else
                <p class="text-gray-500 p-4 text-center">{{ __( 'No data available.' ) }}</p>
            @endif
        </div>
    </div>

    {{-- Event Frequency Chart placeholder --}}
    <div class="bg-white shadow rounded-lg p-4">
        <h3 class="text-lg font-bold mb-3">{{ __( 'Event Frequency Over Time' ) }}</h3>
        <div class="h-64 flex items-center justify-center text-sm text-gray-400">
            {{ __( 'Chart data available on $eventFrequencyChart — override this view to render with your charting library.' ) }}
        </div>
    </div>

    {{-- Back to Dashboard --}}
    <div class="mt-6">
        <a href="{{ route( 'security.dashboard' ) }}" class="inline-flex items-center px-4 py-2 bg-white hover:bg-gray-50 text-blue-600 border border-blue-600 text-sm font-medium rounded-md">
            {{ __( 'Back to Dashboard' ) }}
        </a>
    </div>
</div>
