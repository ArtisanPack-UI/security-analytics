<?php

/**
 * AnomalySummaryPanel Livewire component.
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
use ArtisanPackUI\SecurityAnalytics\AI\Agents\AnomalySummaryAgent;
use Livewire\Component;
use Throwable;

/**
 * Trigger surface for the {@see AnomalySummaryAgent}.
 *
 * Rendered on the security dashboard. The user picks a window (in hours),
 * clicks generate, and gets back a scannable digest. Disabled when the
 * `security.anomaly_summary` feature is off or credentials are missing.
 *
 * @package    ArtisanPack_UI
 * @subpackage SecurityAnalytics
 *
 * @since      1.1.0
 */
class AnomalySummaryPanel extends Component
{
    /**
     * Window in hours the digest covers.
     */
    public int $windowHours = 24;

    /**
     * Whether the underlying feature is available.
     */
    public bool $available = false;

    /**
     * Whether the toggle is on (independent of credentials).
     */
    public bool $toggleOn = false;

    /**
     * The last summary result, or null before it has run.
     *
     * @var array<string, mixed>|null
     */
    public ?array $result = null;

    /**
     * Human-readable error message when the last summary failed.
     */
    public ?string $error = null;

    public function mount(): void
    {
        if ( ! auth()->user()?->can( 'view-security-dashboard' ) ) {
            abort( 403, 'Unauthorized to view anomaly summary.' );
        }

        $registry = app( FeatureRegistry::class );

        $this->toggleOn  = $registry->isToggleOn( 'security.anomaly_summary' );
        $this->available = $registry->isEnabled( 'security.anomaly_summary' );
    }

    public function generate(): void
    {
        if ( ! auth()->user()?->can( 'view-security-dashboard' ) ) {
            abort( 403, 'Unauthorized to generate anomaly summary.' );
        }

        $this->result = null;
        $this->error  = null;

        if ( $this->windowHours < 1 || $this->windowHours > 720 ) {
            $this->error = __( 'Window must be between 1 and 720 hours.' );

            return;
        }

        try {
            $this->result = AnomalySummaryAgent::for( $this->windowHours )->run();
        } catch ( FeatureDisabledException $e ) {
            $this->available = false;
            $this->toggleOn  = false;
            $this->error     = __( 'Anomaly summary is turned off for this environment.' );
        } catch ( MissingCredentialsException $e ) {
            $this->available = false;
            $this->error     = __( 'AI credentials are not configured for anomaly summary.' );
        } catch ( Throwable $e ) {
            $this->error = __( 'Anomaly summary failed: :message', [ 'message' => $e->getMessage() ] );
        }
    }

    public function render()
    {
        return view( 'security-analytics::livewire.anomaly-summary-panel' );
    }
}
