<?php

/**
 * LogEventAction incident response action.
 *
 * @package    ArtisanPack_UI
 * @subpackage SecurityAnalytics
 *
 * @author     Jacob Martella <support@artisanpackui.dev>
 *
 * @since      1.0.0
 */

declare( strict_types=1 );

namespace ArtisanPackUI\SecurityAnalytics\Analytics\IncidentResponse\Actions;

use ArtisanPackUI\SecurityAnalytics\Models\Anomaly;
use ArtisanPackUI\SecurityAnalytics\Models\SecurityIncident;
use Illuminate\Support\Facades\Log;

class LogEventAction extends AbstractAction
{
    /**
     * {@inheritdoc}
     */
    public function getName(): string
    {
        return 'log_event';
    }

    /**
     * {@inheritdoc}
     */
    public function execute( Anomaly $anomaly, ?SecurityIncident $incident = null, array $config = [] ): array
    {
        $channel = $config['channel'] ?? 'security';
        $level   = $config['level'] ?? $this->getLogLevelFromSeverity( $anomaly->severity );

        $context = [
            'anomaly_id'  => $anomaly->id,
            'category'    => $anomaly->category,
            'severity'    => $anomaly->severity,
            'score'       => $anomaly->score,
            'detector'    => $anomaly->detector,
            'metadata'    => $anomaly->metadata,
            'detected_at' => $anomaly->detected_at?->toIso8601String(),
        ];

        if ( $incident ) {
            $context['incident_id']     = $incident->id;
            $context['incident_number'] = $incident->incident_number;
        }

        if ( $anomaly->user_id ) {
            $context['user_id'] = $anomaly->user_id;
        }

        $message = $config['message'] ?? "Security anomaly detected: {$anomaly->description}";

        Log::channel( $channel )->log( $level, $message, $context );

        if ( $incident ) {
            $this->logToIncident( $incident, [
                'channel' => $channel,
                'level'   => $level,
            ] );
        }

        return $this->success( "Event logged to {$channel} channel", [
            'channel' => $channel,
            'level'   => $level,
        ] );
    }

    /**
     * Get log level from anomaly severity.
     */
    protected function getLogLevelFromSeverity( string $severity ): string
    {
        return match ( $severity ) {
            'critical' => 'critical',
            'high'     => 'error',
            'medium'   => 'warning',
            'low'      => 'notice',
            default    => 'info',
        };
    }
}
