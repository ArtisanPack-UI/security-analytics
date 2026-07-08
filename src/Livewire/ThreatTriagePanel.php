<?php

/**
 * ThreatTriagePanel Livewire component.
 *
 * @package    ArtisanPack_UI
 * @subpackage SecurityAnalytics
 *
 * @author     Jacob Martella <support@artisanpackui.dev>
 *
 * @since      1.1.0
 */

declare( strict_types=1 );

namespace ArtisanPackUI\SecurityAnalytics\Livewire;

use ArtisanPackUI\Ai\Contracts\FeatureRegistry;
use ArtisanPackUI\Ai\Exceptions\FeatureDisabledException;
use ArtisanPackUI\Ai\Exceptions\MissingCredentialsException;
use ArtisanPackUI\SecurityAnalytics\AI\Agents\ThreatTriageAgent;
use ArtisanPackUI\SecurityAnalytics\Models\SecurityEvent;
use Illuminate\Contracts\View\View;
use Illuminate\Support\Facades\Log;
use Livewire\Attributes\Locked;
use Livewire\Component;
use Throwable;

/**
 * Trigger surface for the {@see ThreatTriageAgent}.
 *
 * Rendered inline on the security-event detail surface. When the
 * `security.threat_triage` feature is disabled or unavailable the component
 * renders a disabled state; no agent call happens and no cost is incurred.
 *
 * @package    ArtisanPack_UI
 * @subpackage SecurityAnalytics
 *
 * @since      1.1.0
 */
class ThreatTriagePanel extends Component
{
    /**
     * ID of the {@see SecurityEvent} to triage. `#[Locked]` because
     * Livewire 3 hydrates public properties from the client on every
     * request; without this, a user with the coarse
     * `view-security-events` capability could rewire the target to any
     * event id via the wire protocol.
     */
    #[Locked]
    public ?int $eventId = null;

    /**
     * Whether the underlying feature is available (toggle on and credentials
     * resolvable).
     */
    public bool $available = false;

    /**
     * Whether the toggle is on (independent of credentials).
     */
    public bool $toggleOn = false;

    /**
     * The last triage result, or null before triage has run.
     *
     * @var array<string, mixed>|null
     */
    public ?array $result = null;

    /**
     * Human-readable error message when the last triage failed.
     */
    public ?string $error = null;

    /**
     * Mount the component and probe the feature-registry state.
     *
     * @since 1.1.0
     */
    public function mount( ?int $eventId = null ): void
    {
        if ( ! auth()->user()?->can( 'view-security-events' ) ) {
            abort( 403, __( 'Unauthorized to view threat triage.' ) );
        }

        $this->eventId = $eventId;

        $registry = app( FeatureRegistry::class );

        $this->toggleOn  = $registry->isToggleOn( 'security.threat_triage' );
        $this->available = $registry->isEnabled( 'security.threat_triage' );
    }

    /**
     * Run the triage agent against `$this->eventId`.
     *
     * @since 1.1.0
     */
    public function triage(): void
    {
        if ( ! auth()->user()?->can( 'view-security-events' ) ) {
            abort( 403, __( 'Unauthorized to trigger threat triage.' ) );
        }

        $this->result = null;
        $this->error  = null;

        if ( null === $this->eventId ) {
            $this->error = __( 'Select a security event to triage.' );

            return;
        }

        try {
            $this->result = ThreatTriageAgent::for( $this->eventId )->run();
        } catch ( FeatureDisabledException $e ) {
            $this->available = false;
            $this->toggleOn  = false;
            $this->error     = __( 'Threat triage is turned off for this environment.' );
        } catch ( MissingCredentialsException $e ) {
            $this->available = false;
            $this->error     = __( 'AI credentials are not configured for threat triage.' );
        } catch ( Throwable $e ) {
            // Log the raw exception (which may contain the upstream URL or
            // even API-key headers) server-side; surface a redacted generic
            // message in the browser DOM.
            Log::error( 'ThreatTriageAgent invocation failed', [
                'event_id' => $this->eventId,
                'error'    => $e->getMessage(),
                'class'    => $e::class,
            ] );

            $this->error = __( 'Threat triage failed. Check the server logs for details.' );
        }
    }

    /**
     * Render the panel view.
     *
     * @since 1.1.0
     */
    public function render(): View
    {
        return view( 'security-analytics::livewire.threat-triage-panel' );
    }
}
