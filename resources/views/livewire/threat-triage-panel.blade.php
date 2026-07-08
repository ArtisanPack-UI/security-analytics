{{--
    Threat Triage Panel.

    Plain HTML + Tailwind by design. Override this view in your app
    (resources/views/vendor/security-analytics/livewire/threat-triage-panel.blade.php)
    to change the styling.
--}}
<div class="bg-white shadow rounded-lg p-4">
    <div class="flex items-start justify-between mb-3">
        <div>
            <h3 class="text-lg font-bold">{{ __( 'Threat triage' ) }}</h3>
            <p class="text-sm text-gray-500">
                {{ __( 'AI-assisted severity and recommended actions for this security event.' ) }}
            </p>
        </div>

        @if ( $available )
            <button
                type="button"
                wire:click="triage"
                wire:loading.attr="disabled"
                class="inline-flex items-center px-3 py-1.5 bg-blue-600 hover:bg-blue-700 disabled:opacity-50 text-white text-sm font-medium rounded-md"
            >
                <span wire:loading.remove wire:target="triage">{{ __( 'Run triage' ) }}</span>
                <span wire:loading wire:target="triage">{{ __( 'Analyzing…' ) }}</span>
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

    @if ( $error )
        <div class="rounded-md bg-red-50 p-3 text-sm text-red-800 mb-3">
            {{ $error }}
        </div>
    @endif

    @if ( $result )
        <div class="border-t pt-3 space-y-3">
            <div class="flex items-center gap-2">
                <span class="text-xs uppercase tracking-wide text-gray-500">{{ __( 'Severity' ) }}</span>
                <span
                    @class( [
                        'inline-flex items-center px-2 py-0.5 rounded text-xs font-semibold',
                        'bg-gray-100 text-gray-700'   => 'info' === ( $result['severity'] ?? 'info' ),
                        'bg-blue-100 text-blue-800'   => 'low' === ( $result['severity'] ?? '' ),
                        'bg-yellow-100 text-yellow-800' => 'medium' === ( $result['severity'] ?? '' ),
                        'bg-orange-100 text-orange-800' => 'high' === ( $result['severity'] ?? '' ),
                        'bg-red-100 text-red-800'     => 'critical' === ( $result['severity'] ?? '' ),
                    ] )
                >
                    {{ $result['severity'] ?? 'info' }}
                </span>
            </div>

            <div>
                <div class="text-xs uppercase tracking-wide text-gray-500 mb-1">{{ __( 'Summary' ) }}</div>
                <p class="text-sm text-gray-800">{{ $result['summary'] ?? '' }}</p>
            </div>

            @if ( ! empty( $result['recommended_actions'] ) )
                <div>
                    <div class="text-xs uppercase tracking-wide text-gray-500 mb-2">{{ __( 'Recommended actions' ) }}</div>
                    <ol class="space-y-1">
                        @foreach ( $result['recommended_actions'] as $index => $action )
                            <li wire:key="triage-action-{{ $index }}" class="flex items-start gap-2 text-sm">
                                <span class="mt-0.5 shrink-0 inline-block w-5 h-5 rounded-full bg-gray-100 text-gray-700 text-xs flex items-center justify-center">
                                    {{ $index + 1 }}
                                </span>
                                <span class="flex-1">
                                    <span class="text-gray-800">{{ $action['step'] ?? '' }}</span>
                                    <span class="ml-2 text-xs text-gray-500">({{ $action['urgency'] ?? '' }})</span>
                                </span>
                            </li>
                        @endforeach
                    </ol>
                </div>
            @endif

            @if ( ! empty( $result['related_events'] ) )
                <div>
                    <div class="text-xs uppercase tracking-wide text-gray-500 mb-1">{{ __( 'Related events' ) }}</div>
                    <p class="text-sm text-gray-600">
                        {{ implode( ', ', array_map( fn ( $id ) => '#' . $id, $result['related_events'] ) ) }}
                    </p>
                </div>
            @endif
        </div>
    @endif
</div>
