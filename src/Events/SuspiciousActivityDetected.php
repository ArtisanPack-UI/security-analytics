<?php

declare( strict_types=1 );

namespace ArtisanPackUI\SecurityAnalytics\Events;

use ArtisanPackUI\SecurityAnalytics\Models\SuspiciousActivity;
use Illuminate\Broadcasting\InteractsWithSockets;
use Illuminate\Foundation\Events\Dispatchable;
use Illuminate\Http\Request;
use Illuminate\Queue\SerializesModels;

class SuspiciousActivityDetected
{
    use Dispatchable;
    use InteractsWithSockets;
    use SerializesModels;

    /**
     * Create a new event instance.
     */
    public function __construct(
        public SuspiciousActivity $activity,
        public Request $request,
        public mixed $user = null,
    ) {
    }

    /**
     * Get the severity level.
     */
    public function getSeverity(): string
    {
        return $this->activity->severity;
    }

    /**
     * Get the risk score.
     */
    public function getRiskScore(): int
    {
        return $this->activity->risk_score;
    }

    /**
     * Check if this is a high severity event.
     */
    public function isHighSeverity(): bool
    {
        return in_array( $this->activity->severity, [
            SuspiciousActivity::SEVERITY_HIGH,
            SuspiciousActivity::SEVERITY_CRITICAL,
        ] );
    }
}
