<?php

declare( strict_types=1 );

namespace ArtisanPackUI\SecurityAnalytics\Events;

use ArtisanPackUI\SecurityAnalytics\Models\Anomaly;
use Illuminate\Broadcasting\InteractsWithSockets;
use Illuminate\Foundation\Events\Dispatchable;
use Illuminate\Queue\SerializesModels;

class AnomalyDetected
{
    use Dispatchable;
    use InteractsWithSockets;
    use SerializesModels;

    /**
     * Create a new event instance.
     */
    public function __construct(
        public readonly Anomaly $anomaly,
    ) {
    }
}
