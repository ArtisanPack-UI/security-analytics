<?php

/**
 * IncidentResponsePanel Livewire component.
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
use ArtisanPackUI\SecurityAnalytics\AI\Agents\IncidentResponseAgent;
use ArtisanPackUI\SecurityAnalytics\Models\SecurityIncident;
use Illuminate\Contracts\View\View;
use Illuminate\Support\Facades\Log;
use Livewire\Attributes\Locked;
use Livewire\Component;
use Throwable;

/**
 * Trigger surface for the {@see IncidentResponseAgent}.
 *
 * Rendered on the incident detail page. Suggestion-only — never triggers
 * an action; the responder decides. Disabled state when the
 * `security.incident_response` feature is off or credentials are missing.
 *
 * @package    ArtisanPack_UI
 * @subpackage SecurityAnalytics
 *
 * @since      1.1.0
 */
class IncidentResponsePanel extends Component
{
    /**
     * ID of the {@see SecurityIncident} to advise on. `#[Locked]` because
     * Livewire 3 hydrates public properties from the client on every
     * request; without this, a user with the coarse
     * `view-security-events` capability could rewire the target to any
     * incident id via the wire protocol.
     */
    #[Locked]
    public ?int $incidentId = null;

    /**
     * Whether the underlying feature is available.
     */
    public bool $available = false;

    /**
     * Whether the toggle is on (independent of credentials).
     */
    public bool $toggleOn = false;

    /**
     * The last suggestion result, or null before it has run.
     *
     * @var array<string, mixed>|null
     */
    public ?array $result = null;

    /**
     * Human-readable error message when the last suggestion failed.
     */
    public ?string $error = null;

    /**
     * Mount the panel and probe the feature-registry state.
     *
     * @since 1.1.0
     */
    public function mount( ?int $incidentId = null ): void
    {
        if ( ! auth()->user()?->can( 'view-security-events' ) ) {
            abort( 403, __( 'Unauthorized to view incident response suggestions.' ) );
        }

        $this->incidentId = $incidentId;

        $registry = app( FeatureRegistry::class );

        $this->toggleOn  = $registry->isToggleOn( 'security.incident_response' );
        $this->available = $registry->isEnabled( 'security.incident_response' );
    }

    /**
     * Run the incident-response agent against `$this->incidentId`.
     *
     * @since 1.1.0
     */
    public function suggest(): void
    {
        if ( ! auth()->user()?->can( 'view-security-events' ) ) {
            abort( 403, __( 'Unauthorized to trigger incident response suggestions.' ) );
        }

        $this->result = null;
        $this->error  = null;

        if ( null === $this->incidentId ) {
            $this->error = __( 'Select an incident to advise on.' );

            return;
        }

        try {
            $this->result = IncidentResponseAgent::for( $this->incidentId )->run();
        } catch ( FeatureDisabledException $e ) {
            $this->available = false;
            $this->toggleOn  = false;
            $this->error     = __( 'Incident response suggestions are turned off for this environment.' );
        } catch ( MissingCredentialsException $e ) {
            $this->available = false;
            $this->error     = __( 'AI credentials are not configured for incident response.' );
        } catch ( Throwable $e ) {
            // Log the raw exception (which may contain the upstream URL or
            // even API-key headers) server-side; surface a redacted generic
            // message in the browser DOM.
            Log::error( 'IncidentResponseAgent invocation failed', [
                'incident_id' => $this->incidentId,
                'error'       => $e->getMessage(),
                'class'       => $e::class,
            ] );

            $this->error = __( 'Incident response suggestions failed. Check the server logs for details.' );
        }
    }

    /**
     * Render the panel view.
     *
     * @since 1.1.0
     */
    public function render(): View
    {
        return view( 'security-analytics::livewire.incident-response-panel' );
    }
}
