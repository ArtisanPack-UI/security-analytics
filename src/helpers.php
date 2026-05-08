<?php

/**
 * SecurityAnalytics helper functions.
 *
 * @package    ArtisanPack_UI
 * @subpackage SecurityAnalytics
 *
 * @since      1.0.0
 */

use ArtisanPackUI\SecurityAnalytics\SecurityAnalytics;

if ( ! function_exists( 'security_analytics' ) ) {
    /**
     * Get the SecurityAnalytics instance.
     *
     * @since 1.0.0
     *
     * @return SecurityAnalytics
     */
    function security_analytics(): SecurityAnalytics
    {
        return app( 'security-analytics' );
    }
}
