<?php

/**
 * DatabaseChannel alert channel.
 *
 * @package    ArtisanPack_UI
 * @subpackage SecurityAnalytics
 *
 * @author     Jacob Martella <support@artisanpackui.dev>
 *
 * @since      1.0.0
 */

declare( strict_types=1 );

namespace ArtisanPackUI\SecurityAnalytics\Analytics\Alerting\Channels;

use ArtisanPackUI\SecurityAnalytics\Analytics\Alerting\Contracts\AlertChannelInterface;
use ArtisanPackUI\SecurityAnalytics\Models\AlertHistory;
use ArtisanPackUI\SecurityAnalytics\Models\AlertRule;
use ArtisanPackUI\SecurityAnalytics\Models\Anomaly;
use Exception;

class DatabaseChannel implements AlertChannelInterface
{
    /**
     * @var array<string, mixed>
     */
    protected array $config;

    /**
     * @param  array<string, mixed>  $config
     */
    public function __construct( array $config = [] )
    {
        $this->config = array_merge( [
            'enabled'        => true, // Database channel is always available
            'store_metadata' => true,
        ], $config );
    }

    /**
     * {@inheritdoc}
     */
    public function getName(): string
    {
        return 'database';
    }

    /**
     * {@inheritdoc}
     */
    public function isEnabled(): bool
    {
        return $this->config['enabled'] ?? true;
    }

    /**
     * {@inheritdoc}
     */
    public function getConfig(): array
    {
        return $this->config;
    }

    /**
     * {@inheritdoc}
     */
    public function send( Anomaly $anomaly, AlertRule $rule, array $recipients ): array
    {
        try {
            $alertHistory = AlertHistory::create( [
                'rule_id'     => $rule->id,
                'anomaly_id'  => $anomaly->id,
                'incident_id' => $anomaly->incident_id ?? null,
                'severity'    => $anomaly->severity,
                'channel'     => $this->getName(),
                'recipient'   => ! empty( $recipients ) ? implode( ', ', $recipients ) : null,
                'status'      => AlertHistory::STATUS_SENT,
                'message'     => $this->buildMessage( $anomaly, $rule ),
                'sent_at'     => now(),
            ] );

            return [
                'success'          => true,
                'alert_history_id' => $alertHistory->id,
                'recipients'       => $recipients,
            ];
        } catch ( Exception $e ) {
            return [
                'success' => false,
                'error'   => $e->getMessage(),
            ];
        }
    }

    /**
     * Build the alert message.
     */
    protected function buildMessage( Anomaly $anomaly, AlertRule $rule ): string
    {
        $message = "Security Alert: {$rule->name}\n\n";
        $message .= "Description: {$anomaly->description}\n";
        $message .= "Severity: {$anomaly->severity}\n";
        $message .= "Category: {$anomaly->category}\n";
        $message .= "Detector: {$anomaly->detector}\n";
        $message .= "Score: {$anomaly->score}\n";
        $detectedAt = $anomaly->detected_at?->format( 'Y-m-d H:i:s T' ) ?? 'Unknown';
        $message .= "Detected At: {$detectedAt}\n";

        if ( $anomaly->user_id ) {
            $message .= "User ID: {$anomaly->user_id}\n";
        }

        if ( isset( $anomaly->metadata['ip'] ) ) {
            $message .= "IP Address: {$anomaly->metadata['ip']}\n";
        }

        return $message;
    }
}
