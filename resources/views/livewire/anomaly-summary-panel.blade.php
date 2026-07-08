{{--
    Anomaly Summary Panel.

    Plain HTML + Tailwind by design. Override this view in your app
    (resources/views/vendor/security-analytics/livewire/anomaly-summary-panel.blade.php)
    to change the styling.
--}}
<div class="bg-white shadow rounded-lg p-4">
    <div class="flex items-start justify-between gap-4 mb-3">
        <div>
            <h3 class="text-lg font-bold">{{ __( 'Anomaly summary' ) }}</h3>
            <p class="text-sm text-gray-500">
                {{ __( 'AI-generated digest of unusual security activity over the last :hours hours.', [ 'hours' => $windowHours ] ) }}
            </p>
        </div>

        <div class="flex items-center gap-2 shrink-0">
            <label class="text-sm text-gray-600" for="anomaly-summary-window">{{ __( 'Window (hours)' ) }}</label>
            <input
                type="number"
                id="anomaly-summary-window"
                min="1"
                max="720"
                wire:model="windowHours"
                class="w-20 px-2 py-1 text-sm border border-gray-300 rounded-md"
            />

            @if ( $available )
                <button
                    type="button"
                    wire:click="generate"
                    wire:loading.attr="disabled"
                    class="inline-flex items-center px-3 py-1.5 bg-blue-600 hover:bg-blue-700 disabled:opacity-50 text-white text-sm font-medium rounded-md"
                >
                    <span wire:loading.remove wire:target="generate">{{ __( 'Generate' ) }}</span>
                    <span wire:loading wire:target="generate">{{ __( 'Generating…' ) }}</span>
                </button>
            @elseif ( ! $toggleOn )
                <span class="inline-flex items-center px-3 py-1.5 bg-gray-100 text-gray-500 text-sm font-medium rounded-md">
                    {{ __( 'Disabled' ) }}
                </span>
            @else
                <span class="inline-flex items-center px-3 py-1.5 bg-yellow-100 text-yellow-800 text-sm font-medium rounded-md">
                    {{ __( 'Credentials required' ) }}
                </span>
            @endif
        </div>
    </div>

    @if ( $error )
        <div class="rounded-md bg-red-50 p-3 text-sm text-red-800 mb-3">
            {{ $error }}
        </div>
    @endif

    @if ( $result )
        <div class="border-t pt-3 space-y-3">
            <h4 class="text-base font-semibold text-gray-900">{{ $result['headline'] ?? '' }}</h4>
            <p class="text-sm text-gray-800 leading-relaxed">{{ $result['body'] ?? '' }}</p>

            <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
                @if ( ! empty( $result['top_severities'] ) )
                    <div>
                        <div class="text-xs uppercase tracking-wide text-gray-500 mb-1">{{ __( 'Top severities' ) }}</div>
                        <ul class="space-y-1 text-sm">
                            @foreach ( $result['top_severities'] as $index => $bucket )
                                <li wire:key="summary-severity-{{ $index }}" class="flex justify-between">
                                    <span class="text-gray-800">{{ $bucket['severity'] ?? '' }}</span>
                                    <span class="text-gray-500">{{ $bucket['count'] ?? 0 }}</span>
                                </li>
                            @endforeach
                        </ul>
                    </div>
                @endif

                @if ( ! empty( $result['top_detectors'] ) )
                    <div>
                        <div class="text-xs uppercase tracking-wide text-gray-500 mb-1">{{ __( 'Top detectors' ) }}</div>
                        <ul class="space-y-1 text-sm">
                            @foreach ( $result['top_detectors'] as $index => $bucket )
                                <li wire:key="summary-detector-{{ $index }}" class="flex justify-between">
                                    <span class="text-gray-800">{{ $bucket['detector'] ?? '' }}</span>
                                    <span class="text-gray-500">{{ $bucket['count'] ?? 0 }}</span>
                                </li>
                            @endforeach
                        </ul>
                    </div>
                @endif
            </div>

            @if ( ! empty( $result['recommended_followups'] ) )
                <div>
                    <div class="text-xs uppercase tracking-wide text-gray-500 mb-1">{{ __( 'Recommended follow-ups' ) }}</div>
                    <ul class="list-disc pl-5 space-y-1 text-sm text-gray-800">
                        @foreach ( $result['recommended_followups'] as $index => $followup )
                            <li wire:key="summary-followup-{{ $index }}">{{ $followup }}</li>
                        @endforeach
                    </ul>
                </div>
            @endif
        </div>
    @endif
</div>
