{{--
    Suspicious Activity list.

    Plain HTML + Tailwind by design — this package does not depend on
    artisanpack-ui/livewire-ui-components. Override this view in your app
    if you want to swap in a richer UI library.
--}}
<div>
    <div class="flex justify-between items-center mb-6">
        <h1 class="text-2xl font-bold">{{ __( 'Suspicious Activity' ) }}</h1>
    </div>

    {{-- Filters --}}
    <div class="bg-white shadow rounded-lg p-4 mb-6">
        <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div>
                <label for="filter-severity" class="block text-sm font-medium text-gray-700 mb-1">
                    {{ __( 'Severity' ) }}
                </label>
                <select
                    id="filter-severity"
                    wire:model.live="filterSeverity"
                    class="block w-full rounded-md border-gray-300 shadow-sm focus:border-blue-500 focus:ring-blue-500 sm:text-sm"
                >
                    @foreach ( $this->severityOptions as $value => $label )
                        <option value="{{ $value }}">{{ $label }}</option>
                    @endforeach
                </select>
            </div>
            <div>
                <label for="filter-type" class="block text-sm font-medium text-gray-700 mb-1">
                    {{ __( 'Type' ) }}
                </label>
                <select
                    id="filter-type"
                    wire:model.live="filterType"
                    class="block w-full rounded-md border-gray-300 shadow-sm focus:border-blue-500 focus:ring-blue-500 sm:text-sm"
                >
                    @foreach ( $this->typeOptions as $value => $label )
                        <option value="{{ $value }}">{{ $label }}</option>
                    @endforeach
                </select>
            </div>
        </div>
    </div>

    {{-- Activities table --}}
    <div class="bg-white shadow rounded-lg p-4">
        @if ( $activities->isEmpty() )
            <div class="text-center py-12 text-gray-500">
                <p class="text-lg font-medium">{{ __( 'No suspicious activity found.' ) }}</p>
                <p class="text-sm mt-2">{{ __( 'Try adjusting the filters above or check back later.' ) }}</p>
            </div>
        @else
            <div class="overflow-x-auto">
                <table class="w-full">
                    <thead>
                        <tr class="border-b">
                            <th class="text-left px-4 py-3 font-semibold text-sm text-gray-700">{{ __( 'When' ) }}</th>
                            <th class="text-left px-4 py-3 font-semibold text-sm text-gray-700">{{ __( 'Type' ) }}</th>
                            <th class="text-left px-4 py-3 font-semibold text-sm text-gray-700">{{ __( 'Severity' ) }}</th>
                            <th class="text-left px-4 py-3 font-semibold text-sm text-gray-700">{{ __( 'User' ) }}</th>
                            <th class="text-left px-4 py-3 font-semibold text-sm text-gray-700">{{ __( 'IP address' ) }}</th>
                            <th class="text-left px-4 py-3 font-semibold text-sm text-gray-700">{{ __( 'Details' ) }}</th>
                        </tr>
                    </thead>
                    <tbody>
                        @foreach ( $activities as $activity )
                            <tr wire:key="suspicious-activity-{{ $activity->id }}" class="border-b hover:bg-gray-50">
                                <td class="px-4 py-3 text-sm whitespace-nowrap">
                                    {{ $activity->created_at?->diffForHumans() }}
                                </td>
                                <td class="px-4 py-3 text-sm">
                                    {{ $this->typeOptions[ $activity->type ] ?? $activity->type }}
                                </td>
                                <td class="px-4 py-3 text-sm">
                                    <span class="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium {{ $this->getSeverityClass( $activity->severity ) }}">
                                        {{ $this->severityOptions[ $activity->severity ] ?? $activity->severity }}
                                    </span>
                                </td>
                                <td class="px-4 py-3 text-sm">
                                    {{ optional( $activity->user )->name ?? __( '—' ) }}
                                </td>
                                <td class="px-4 py-3 text-sm font-mono">
                                    {{ $activity->ip_address ?? __( '—' ) }}
                                </td>
                                <td class="px-4 py-3 text-sm">
                                    @if ( $activity->details )
                                        <details>
                                            <summary class="cursor-pointer text-blue-600 hover:text-blue-800">
                                                {{ __( 'View details' ) }}
                                            </summary>
                                            <pre class="mt-2 p-3 bg-gray-50 rounded text-xs overflow-auto max-w-md">{{ json_encode( $activity->details, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES ) }}</pre>
                                        </details>
                                    @else
                                        <span class="text-gray-400">{{ __( '—' ) }}</span>
                                    @endif
                                </td>
                            </tr>
                        @endforeach
                    </tbody>
                </table>
            </div>

            {{-- Pagination --}}
            <div class="mt-4">
                {{ $activities->links() }}
            </div>
        @endif
    </div>
</div>
