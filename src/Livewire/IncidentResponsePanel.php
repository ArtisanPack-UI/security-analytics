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
     * ID of the {@see SecurityIncident} to advise on.
     */
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

    public function mount( ?int $incidentId = null ): void
    {
        if ( ! auth()->user()?->can( 'view-security-events' ) ) {
            abort( 403, 'Unauthorized to view incident response suggestions.' );
        }

        $this->incidentId = $incidentId;

        $registry = app( FeatureRegistry::class );

        $this->toggleOn  = $registry->isToggleOn( 'security.incident_response' );
        $this->available = $registry->isEnabled( 'security.incident_response' );
    }

    public function suggest(): void
    {
        if ( ! auth()->user()?->can( 'view-security-events' ) ) {
            abort( 403, 'Unauthorized to trigger incident response suggestions.' );
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
            $this->error = __( 'Incident response suggestions failed: :message', [ 'message' => $e->getMessage() ] );
        }
    }

    public function render()
    {
        return view( 'security-analytics::livewire.incident-response-panel' );
    }
}
