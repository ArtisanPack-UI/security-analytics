<?php

/**
 * AccessControlMetricsListener metrics listener.
 *
 * @package    ArtisanPack_UI
 * @subpackage SecurityAnalytics
 *
 * @author     Jacob Martella <support@artisanpackui.dev>
 *
 * @since      1.0.0
 */

declare( strict_types=1 );

namespace ArtisanPackUI\SecurityAnalytics\Analytics\Listeners;

use ArtisanPackUI\SecurityAnalytics\Analytics\MetricsCollector;
use Illuminate\Auth\Access\Events\GateEvaluated;

class AccessControlMetricsListener
{
    public function __construct(
        protected MetricsCollector $collector,
    ) {
    }

    /**
     * Handle gate evaluation events.
     */
    public function handleGateEvaluated( GateEvaluated $event ): void
    {
        $allowed = true === $event->result || ( null !== $event->result && false !== $event->result );

        $this->collector->recordAccessEvent(
            $event->ability,
            'check',
            $allowed,
            [
                'user_id' => $event->user?->getAuthIdentifier(),
            ],
        );

        if ( ! $allowed ) {
            $this->collector->increment(
                'access.denied',
                1,
                tags: ['ability' => $event->ability],
            );
        }
    }

    /**
     * Subscribe to access control events.
     *
     * @param  \Illuminate\Events\Dispatcher  $events
     */
    public function subscribe( $events ): void
    {
        $events->listen( GateEvaluated::class, [self::class, 'handleGateEvaluated'] );
    }
}
