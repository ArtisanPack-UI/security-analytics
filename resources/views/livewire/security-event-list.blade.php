{{--
    Security Event list.

    Plain HTML + Tailwind by design — this package does not depend on
    artisanpack-ui/livewire-ui-components. Override this view in your app
    to swap in richer table / modal / datepicker components.
--}}
<div>
    <div class="flex justify-between items-center mb-6">
        <h1 class="text-2xl font-bold">{{ __( 'Security Events' ) }}</h1>
        <div class="flex gap-2">
            <button
                type="button"
                wire:click="export('csv')"
                class="inline-flex items-center px-3 py-1.5 bg-white hover:bg-gray-50 text-blue-600 border border-blue-600 text-sm font-medium rounded-md"
            >
                {{ __( 'Export CSV' ) }}
            </button>
            <button
                type="button"
                wire:click="export('json')"
                class="inline-flex items-center px-3 py-1.5 bg-white hover:bg-gray-50 text-blue-600 border border-blue-600 text-sm font-medium rounded-md"
            >
                {{ __( 'Export JSON' ) }}
            </button>
        </div>
    </div>

    {{-- Filters --}}
    <div class="bg-white shadow rounded-lg p-4 mb-6">
        <div class="grid grid-cols-1 md:grid-cols-5 gap-4">
            <div>
                <label for="filter-event-type" class="block text-sm font-medium text-gray-700 mb-1">{{ __( 'Event Type' ) }}</label>
                <select id="filter-event-type" wire:model.live="filterType" class="block w-full rounded-md border-gray-300 shadow-sm focus:border-blue-500 focus:ring-blue-500 sm:text-sm">
                    <option value="">{{ __( 'All Types' ) }}</option>
                    @foreach ( $eventTypes as $value => $label )
                        <option value="{{ $value }}">{{ $label }}</option>
                    @endforeach
                </select>
            </div>
            <div>
                <label for="filter-severity" class="block text-sm font-medium text-gray-700 mb-1">{{ __( 'Severity' ) }}</label>
                <select id="filter-severity" wire:model.live="filterSeverity" class="block w-full rounded-md border-gray-300 shadow-sm focus:border-blue-500 focus:ring-blue-500 sm:text-sm">
                    <option value="">{{ __( 'All Severities' ) }}</option>
                    @foreach ( $severities as $value => $label )
                        <option value="{{ $value }}">{{ $label }}</option>
                    @endforeach
                </select>
            </div>
            <div>
                <label for="filter-from-date" class="block text-sm font-medium text-gray-700 mb-1">{{ __( 'From Date' ) }}</label>
                <input id="filter-from-date" type="date" wire:model.live="filterFromDate" class="block w-full rounded-md border-gray-300 shadow-sm focus:border-blue-500 focus:ring-blue-500 sm:text-sm" />
            </div>
            <div>
                <label for="filter-to-date" class="block text-sm font-medium text-gray-700 mb-1">{{ __( 'To Date' ) }}</label>
                <input id="filter-to-date" type="date" wire:model.live="filterToDate" class="block w-full rounded-md border-gray-300 shadow-sm focus:border-blue-500 focus:ring-blue-500 sm:text-sm" />
            </div>
            <div>
                <label for="filter-search" class="block text-sm font-medium text-gray-700 mb-1">{{ __( 'Search' ) }}</label>
                <input id="filter-search" type="text" wire:model.live.debounce.300ms="search" placeholder="{{ __( 'Search events...' ) }}" class="block w-full rounded-md border-gray-300 shadow-sm focus:border-blue-500 focus:ring-blue-500 sm:text-sm" />
            </div>
        </div>
    </div>

    {{-- Events table --}}
    <div class="bg-white shadow rounded-lg p-4">
        @if ( $events->isEmpty() )
            <div class="text-center py-12 text-gray-500">
                <p class="text-lg font-medium">{{ __( 'No security events found.' ) }}</p>
            </div>
        @else
            <div class="overflow-x-auto">
                <table class="w-full">
                    <thead>
                        <tr class="border-b">
                            <th class="text-left px-4 py-3 font-semibold text-sm text-gray-700">{{ __( 'When' ) }}</th>
                            <th class="text-left px-4 py-3 font-semibold text-sm text-gray-700">{{ __( 'Event' ) }}</th>
                            <th class="text-left px-4 py-3 font-semibold text-sm text-gray-700">{{ __( 'Severity' ) }}</th>
                            <th class="text-left px-4 py-3 font-semibold text-sm text-gray-700">{{ __( 'User' ) }}</th>
                            <th class="text-left px-4 py-3 font-semibold text-sm text-gray-700">{{ __( 'IP' ) }}</th>
                            <th class="text-right px-4 py-3 font-semibold text-sm text-gray-700">{{ __( 'Actions' ) }}</th>
                        </tr>
                    </thead>
                    <tbody>
                        @foreach ( $events as $event )
                            <tr wire:key="security-event-{{ $event->id }}" class="border-b hover:bg-gray-50">
                                <td class="px-4 py-3 text-sm whitespace-nowrap" title="{{ $event->created_at }}">
                                    {{ $event->created_at->diffForHumans() }}
                                </td>
                                <td class="px-4 py-3 text-sm">
                                    <div class="font-medium">{{ $event->event_name }}</div>
                                    <div class="text-xs text-gray-500">{{ $event->event_type }}</div>
                                </td>
                                <td class="px-4 py-3 text-sm">
                                    <span class="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium {{ match( $event->severity ) {
                                        'critical' => 'bg-red-100 text-red-800',
                                        'error'    => 'bg-red-50 text-red-700',
                                        'warning'  => 'bg-yellow-100 text-yellow-800',
                                        'info'     => 'bg-blue-100 text-blue-800',
                                        default    => 'bg-gray-100 text-gray-800',
                                    } }}">
                                        {{ $event->severity }}
                                    </span>
                                </td>
                                <td class="px-4 py-3 text-sm">
                                    @if ( $event->user )
                                        {{ $event->user->email ?? $event->user_id }}
                                    @else
                                        <span class="text-gray-400">{{ __( 'Guest' ) }}</span>
                                    @endif
                                </td>
                                <td class="px-4 py-3 text-sm font-mono">
                                    {{ $event->ip_address ?? __( '—' ) }}
                                </td>
                                <td class="px-4 py-3 text-sm text-right">
                                    <button
                                        type="button"
                                        wire:click="showEvent({{ $event->id }})"
                                        class="text-blue-600 hover:text-blue-800 text-sm font-medium"
                                    >
                                        {{ __( 'View' ) }}
                                    </button>
                                </td>
                            </tr>
                        @endforeach
                    </tbody>
                </table>
            </div>

            {{-- Pagination --}}
            <div class="mt-4">
                {{ $events->links() }}
            </div>
        @endif
    </div>

    {{-- Event detail panel (inline rather than modal — keeps the view dependency-free) --}}
    @if ( $selectedEvent )
        <div class="bg-white shadow rounded-lg p-6 mt-6">
            <div class="flex justify-between items-center mb-4">
                <h2 class="text-xl font-bold">{{ __( 'Event Details' ) }}</h2>
                <button
                    type="button"
                    wire:click="$set('selectedEvent', null)"
                    class="text-gray-400 hover:text-gray-600"
                    aria-label="{{ __( 'Close' ) }}"
                >
                    &times;
                </button>
            </div>
            <div class="grid grid-cols-2 gap-4">
                <div>
                    <span class="text-gray-500 text-sm">{{ __( 'Event Type' ) }}:</span>
                    <p class="font-semibold">{{ $selectedEvent->event_type }}</p>
                </div>
                <div>
                    <span class="text-gray-500 text-sm">{{ __( 'Event Name' ) }}:</span>
                    <p class="font-semibold">{{ $selectedEvent->event_name }}</p>
                </div>
                <div>
                    <span class="text-gray-500 text-sm">{{ __( 'Severity' ) }}:</span>
                    <p class="font-semibold">{{ $selectedEvent->severity }}</p>
                </div>
                <div>
                    <span class="text-gray-500 text-sm">{{ __( 'Timestamp' ) }}:</span>
                    <p class="font-semibold">{{ $selectedEvent->created_at }}</p>
                </div>
                <div>
                    <span class="text-gray-500 text-sm">{{ __( 'IP Address' ) }}:</span>
                    <p class="font-semibold font-mono">{{ $selectedEvent->ip_address }}</p>
                </div>
                <div>
                    <span class="text-gray-500 text-sm">{{ __( 'User' ) }}:</span>
                    <p class="font-semibold">{{ $selectedEvent->user?->email ?? __( 'N/A' ) }}</p>
                </div>
                <div class="col-span-2">
                    <span class="text-gray-500 text-sm">{{ __( 'URL' ) }}:</span>
                    <p class="font-semibold break-all">{{ $selectedEvent->url ?? __( 'N/A' ) }}</p>
                </div>
                <div class="col-span-2">
                    <span class="text-gray-500 text-sm">{{ __( 'User Agent' ) }}:</span>
                    <p class="font-semibold break-all text-sm">{{ $selectedEvent->user_agent ?? __( 'N/A' ) }}</p>
                </div>
            </div>
            @if ( $selectedEvent->details )
                <div class="mt-4">
                    <span class="text-gray-500 text-sm">{{ __( 'Details' ) }}:</span>
                    <pre class="mt-2 p-4 bg-gray-50 rounded text-sm overflow-x-auto">{{ json_encode( $selectedEvent->details, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES ) }}</pre>
                </div>
            @endif
        </div>
    @endif
</div>
