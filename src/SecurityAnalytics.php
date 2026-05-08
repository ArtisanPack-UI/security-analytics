<?php

/**
 * Main SecurityAnalytics class.
 *
 * Resolved from the container as `security-analytics` and via the
 * {@see security_analytics()} helper. Most public functionality is exposed via
 * the `SecurityEventLogger`, anomaly-detection services, SIEM exporters, and
 * incident-response automation surfaces within this package.
 *
 * @package    ArtisanPack_UI
 * @subpackage SecurityAnalytics
 *
 * @since      1.0.0
 */

declare( strict_types=1 );

namespace ArtisanPackUI\SecurityAnalytics;

class SecurityAnalytics
{
    public function version(): string
    {
        return '0.1.0';
    }
}
