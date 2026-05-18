<?php

/**
 * DetectorInterface contract.
 *
 * @package    ArtisanPack_UI
 * @subpackage SecurityAnalytics
 *
 * @author     Jacob Martella <support@artisanpackui.dev>
 *
 * @since      1.0.0
 */

declare( strict_types=1 );

namespace ArtisanPackUI\SecurityAnalytics\Analytics\AnomalyDetection\Contracts;

use ArtisanPackUI\SecurityAnalytics\Models\Anomaly;
use Illuminate\Support\Collection;

interface DetectorInterface
{
    /**
     * Get the detector name.
     */
    public function getName(): string;

    /**
     * Check if the detector is enabled.
     */
    public function isEnabled(): bool;

    /**
     * Analyze data and detect anomalies.
     *
     * @param  array<string, mixed>  $data
     *
     * @return Collection<int, Anomaly>
     */
    public function detect( array $data ): Collection;

    /**
     * Get the detector's configuration.
     *
     * @return array<string, mixed>
     */
    public function getConfig(): array;
}
