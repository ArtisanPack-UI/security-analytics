<div>
    <div class="flex justify-between items-center mb-6">
        <h1 class="text-2xl font-bold">Security Events</h1>
        <div class="flex gap-2">
            <x-artisanpack-button wire:click="export('csv')" color="primary" outline size="sm">
                Export CSV
            </x-artisanpack-button>
            <x-artisanpack-button wire:click="export('json')" color="primary" outline size="sm">
                Export JSON
            </x-artisanpack-button>
        </div>
    </div>

    {{-- Filters --}}
    <x-artisanpack-card class="mb-6">
        <div class="grid grid-cols-1 md:grid-cols-5 gap-4">
            <x-artisanpack-select
                label="Event Type"
                :options="$eventTypes"
                wire:model.live="filterType"
                placeholder="All Types"
            />
            <x-artisanpack-select
                label="Severity"
                :options="$severities"
                wire:model.live="filterSeverity"
                placeholder="All Severities"
            />
            <x-artisanpack-datepicker
                label="From Date"
                wire:model.live="filterFromDate"
            />
            <x-artisanpack-datepicker
                label="To Date"
                wire:model.live="filterToDate"
            />
            <x-artisanpack-input
                label="Search"
                wire:model.live.debounce.300ms="search"
                placeholder="Search events..."
            />
        </div>
    </x-artisanpack-card>

    {{-- Events Table --}}
    <x-artisanpack-card>
        <x-artisanpack-table
            :headers="$headers"
            :rows="$events"
            :sort-by="$sortBy"
            wire:model="sortBy"
            with-pagination
            :per-page="$perPage"
            :per-page-values="[10, 25, 50, 100]"
            striped
        >
            @scope('cell_severity', $event)
                <x-artisanpack-badge
                    :value="$event->severity"
                    class="{{ match($event->severity) {
                        'critical' => 'badge-error',
                        'error' => 'badge-error badge-outline',
                        'warning' => 'badge-warning',
                        'info' => 'badge-info',
                        default => 'badge-ghost'
                    } }}"
                />
            @endscope

            @scope('cell_user_id', $event)
                @if($event->user)
                    {{ $event->user->email ?? $event->user_id }}
                @else
                    <span class="text-gray-400">Guest</span>
                @endif
            @endscope

            @scope('cell_created_at', $event)
                <span title="{{ $event->created_at }}">
                    {{ $event->created_at->diffForHumans() }}
                </span>
            @endscope

            @scope('actions', $event)
                <x-artisanpack-button
                    size="sm"
                    ghost
                    wire:click="showEvent({{ $event->id }})"
                >
                    <x-artisanpack-icon name="heroicon-o-eye" class="w-4 h-4" />
                </x-artisanpack-button>
            @endscope
        </x-artisanpack-table>
    </x-artisanpack-card>

    {{-- Event Detail Modal --}}
    <x-artisanpack-modal title="Event Details" id="eventDetailModal" width="max-w-2xl">
        @if($selectedEvent)
            <div class="space-y-4">
                <div class="grid grid-cols-2 gap-4">
                    <div>
                        <span class="text-gray-500 text-sm">Event Type:</span>
                        <p class="font-semibold">{{ $selectedEvent->event_type }}</p>
                    </div>
                    <div>
                        <span class="text-gray-500 text-sm">Event Name:</span>
                        <p class="font-semibold">{{ $selectedEvent->event_name }}</p>
                    </div>
                    <div>
                        <span class="text-gray-500 text-sm">Severity:</span>
                        <p class="font-semibold">{{ $selectedEvent->severity }}</p>
                    </div>
                    <div>
                        <span class="text-gray-500 text-sm">Timestamp:</span>
                        <p class="font-semibold">{{ $selectedEvent->created_at }}</p>
                    </div>
                    <div>
                        <span class="text-gray-500 text-sm">IP Address:</span>
                        <p class="font-semibold">{{ $selectedEvent->ip_address }}</p>
                    </div>
                    <div>
                        <span class="text-gray-500 text-sm">User:</span>
                        <p class="font-semibold">{{ $selectedEvent->user?->email ?? 'N/A' }}</p>
                    </div>
                    <div class="col-span-2">
                        <span class="text-gray-500 text-sm">URL:</span>
                        <p class="font-semibold break-all">{{ $selectedEvent->url ?? 'N/A' }}</p>
                    </div>
                    <div class="col-span-2">
                        <span class="text-gray-500 text-sm">User Agent:</span>
                        <p class="font-semibold break-all text-sm">{{ $selectedEvent->user_agent ?? 'N/A' }}</p>
                    </div>
                </div>
                @if($selectedEvent->details)
                    <div>
                        <span class="text-gray-500 text-sm">Details:</span>
                        <pre class="mt-2 p-4 bg-base-200 rounded text-sm overflow-x-auto">{{ json_encode($selectedEvent->details, JSON_PRETTY_PRINT) }}</pre>
                    </div>
                @endif
            </div>
        @endif
        <x-slot:footer>
            <x-artisanpack-button @click="$refs.eventDetailModal.close()">Close</x-artisanpack-button>
        </x-slot:footer>
    </x-artisanpack-modal>
</div>
