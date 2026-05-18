<?php

/**
 * ResponseActionInterface contract.
 *
 * @package    ArtisanPack_UI
 * @subpackage SecurityAnalytics
 *
 * @author     Jacob Martella <support@artisanpackui.dev>
 *
 * @since      1.0.0
 */

declare( strict_types=1 );

namespace ArtisanPackUI\SecurityAnalytics\Analytics\IncidentResponse\Contracts;

use ArtisanPackUI\SecurityAnalytics\Models\Anomaly;
use ArtisanPackUI\SecurityAnalytics\Models\SecurityIncident;

interface ResponseActionInterface
{
    /**
     * Get the action name.
     */
    public function getName(): string;

    /**
     * Execute the action.
     *
     * @param  array<string, mixed>  $config
     *
     * @return array<string, mixed>
     */
    public function execute( Anomaly $anomaly, ?SecurityIncident $incident = null, array $config = [] ): array;

    /**
     * Check if the action requires approval.
     */
    public function requiresApproval(): bool;

    /**
     * Validate the action configuration.
     *
     * @param  array<string, mixed>  $config
     *
     * @return array<int, string>
     */
    public function validate( array $config = [] ): array;
}
