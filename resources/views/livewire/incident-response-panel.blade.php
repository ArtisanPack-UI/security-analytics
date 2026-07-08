{{--
    Incident Response Panel.

    Plain HTML + Tailwind by design. Suggestion-only — this component never
    triggers an action. Override this view in your app
    (resources/views/vendor/security-analytics/livewire/incident-response-panel.blade.php)
    to change the styling.
--}}
<div class="bg-white shadow rounded-lg p-4">
    <div class="flex items-start justify-between mb-3">
        <div>
            <h3 class="text-lg font-bold">{{ __( 'Incident response suggestions' ) }}</h3>
            <p class="text-sm text-gray-500">
                {{ __( 'AI-suggested next steps for this incident. Advisory only — nothing runs automatically.' ) }}
            </p>
        </div>

        @if ( $available )
            <button
                type="button"
                wire:click="suggest"
                wire:loading.attr="disabled"
                class="inline-flex items-center px-3 py-1.5 bg-blue-600 hover:bg-blue-700 disabled:opacity-50 text-white text-sm font-medium rounded-md"
            >
                <span wire:loading.remove wire:target="suggest">{{ __( 'Suggest next steps' ) }}</span>
                <span wire:loading wire:target="suggest">{{ __( 'Thinking…' ) }}</span>
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
        <div class="border-t pt-3">
            @if ( empty( $result['suggested_next_actions'] ) )
                <p class="text-sm text-gray-500">{{ __( 'No suggestions returned.' ) }}</p>
            @else
                <ol class="space-y-3">
                    @foreach ( $result['suggested_next_actions'] as $index => $action )
                        <li wire:key="incident-suggestion-{{ $index }}" class="border rounded-md p-3">
                            <div class="flex items-start justify-between gap-2">
                                <span class="font-medium text-gray-900">
                                    {{ $index + 1 }}. {{ $action['step'] ?? '' }}
                                </span>
                                <span
                                    @class( [
                                        'inline-flex items-center px-2 py-0.5 rounded text-xs font-semibold',
                                        'bg-green-100 text-green-800'  => 'low' === ( $action['risk'] ?? '' ),
                                        'bg-yellow-100 text-yellow-800' => 'medium' === ( $action['risk'] ?? '' ),
                                        'bg-red-100 text-red-800'      => 'high' === ( $action['risk'] ?? '' ),
                                    ] )
                                >
                                    {{ __( 'Risk: :risk', [ 'risk' => $action['risk'] ?? 'unknown' ] ) }}
                                </span>
                            </div>
                            <p class="text-sm text-gray-600 mt-1">{{ $action['rationale'] ?? '' }}</p>
                        </li>
                    @endforeach
                </ol>
            @endif
        </div>
    @endif
</div>
