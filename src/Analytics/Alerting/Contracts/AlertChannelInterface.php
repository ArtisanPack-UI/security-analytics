<?php

/**
 * AlertChannelInterface contract.
 *
 * @package    ArtisanPack_UI
 * @subpackage SecurityAnalytics
 *
 * @author     Jacob Martella <support@artisanpackui.dev>
 *
 * @since      1.0.0
 */

declare( strict_types=1 );

namespace ArtisanPackUI\SecurityAnalytics\Analytics\Alerting\Contracts;

use ArtisanPackUI\SecurityAnalytics\Models\AlertRule;
use ArtisanPackUI\SecurityAnalytics\Models\Anomaly;

interface AlertChannelInterface
{
    /**
     * Get the channel name.
     */
    public function getName(): string;

    /**
     * Check if the channel is enabled.
     */
    public function isEnabled(): bool;

    /**
     * Send an alert through this channel.
     *
     * @param  array<int, string>  $recipients
     *
     * @return array<string, mixed>
     */
    public function send( Anomaly $anomaly, AlertRule $rule, array $recipients ): array;

    /**
     * Get the channel's configuration.
     *
     * @return array<string, mixed>
     */
    public function getConfig(): array;
}
