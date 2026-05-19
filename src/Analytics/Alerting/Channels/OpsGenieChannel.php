<?php

/**
 * OpsGenieChannel alert channel.
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
use ArtisanPackUI\SecurityAnalytics\Models\AlertRule;
use ArtisanPackUI\SecurityAnalytics\Models\Anomaly;
use Exception;
use Illuminate\Support\Facades\Http;

class OpsGenieChannel implements AlertChannelInterface
{
    /**
     * @var array<string, mixed>
     */
    protected array $config;

    protected string $apiUrl = 'https://api.opsgenie.com/v2/alerts';

    /**
     * @param  array<string, mixed>  $config
     */
    public function __construct( array $config = [] )
    {
        $this->config = array_merge( [
            'enabled'          => false,
            'api_key'          => null,
            'team'             => null,
            'priority_mapping' => [
                'critical' => 'P1',
                'high'     => 'P2',
                'medium'   => 'P3',
                'low'      => 'P4',
                'info'     => 'P5',
            ],
        ], $config );
    }

    /**
     * {@inheritdoc}
     */
    public function getName(): string
    {
        return 'opsgenie';
    }

    /**
     * {@inheritdoc}
     */
    public function isEnabled(): bool
    {
        return ( $this->config['enabled'] ?? false ) && ! empty( $this->config['api_key'] );
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
        if ( ! $this->isEnabled() ) {
            return [
                'success' => false,
                'error'   => 'OpsGenie channel is not configured',
            ];
        }

        $payload = $this->buildPayload( $anomaly, $rule, $recipients );

        try {
            $response = Http::withHeaders( [
                'Authorization' => 'GenieKey ' . $this->config['api_key'],
                'Content-Type'  => 'application/json',
            ] )->post( $this->apiUrl, $payload );

            if ( $response->successful() ) {
                $data = $response->json();

                return [
                    'success'    => true,
                    'alert_id'   => $data['requestId'] ?? null,
                    'recipients' => $recipients,
                ];
            }

            return [
                'success'  => false,
                'error'    => 'OpsGenie API returned error',
                'status'   => $response->status(),
                'response' => $response->json(),
            ];
        } catch ( Exception $e ) {
            return [
                'success' => false,
                'error'   => $e->getMessage(),
            ];
        }
    }

    /**
     * Build the OpsGenie payload.
     *
     * @param  array<int, string>  $recipients
     *
     * @return array<string, mixed>
     */
    protected function buildPayload( Anomaly $anomaly, AlertRule $rule, array $recipients ): array
    {
        $payload = [
            'message'     => "Security Alert: {$rule->name}",
            'alias'       => "security-anomaly-{$anomaly->id}",
            'description' => $this->buildDescription( $anomaly ),
            'priority'    => $this->mapSeverityToPriority( $anomaly->severity ),
            'source'      => config( 'app.name', 'Laravel Security' ),
            'tags'        => [
                'security',
                $anomaly->category,
                $anomaly->severity,
                $anomaly->detector,
            ],
            'details' => $this->buildDetails( $anomaly ),
        ];

        // Add responders
        if ( ! empty( $recipients ) ) {
            $payload['responders'] = array_map( fn ( $r ) => [
                'type'     => 'user',
                'username' => $r,
            ], $recipients );
        }

        // Add team if configured
        if ( ! empty( $this->config['team'] ) ) {
            if ( ! isset( $payload['responders'] ) ) {
                $payload['responders'] = [];
            }
            $payload['responders'][] = [
                'type' => 'team',
                'name' => $this->config['team'],
            ];
        }

        return $payload;
    }

    /**
     * Build description text.
     */
    protected function buildDescription( Anomaly $anomaly ): string
    {
        $lines = [
            $anomaly->description,
            '',
            "**Category:** {$anomaly->category}",
            "**Severity:** {$anomaly->severity}",
            "**Score:** {$anomaly->score}",
            "**Detector:** {$anomaly->detector}",
            "**Detected At:** {$anomaly->detected_at->format( 'Y-m-d H:i:s T' )}",
        ];

        if ( $anomaly->user_id ) {
            $lines[] = "**User ID:** {$anomaly->user_id}";
        }

        if ( isset( $anomaly->metadata['ip'] ) ) {
            $lines[] = "**IP Address:** {$anomaly->metadata['ip']}";
        }

        return implode( "\n", $lines );
    }

    /**
     * Build details array.
     *
     * @return array<string, string>
     */
    protected function buildDetails( Anomaly $anomaly ): array
    {
        $details = [
            'anomaly_id'  => (string) $anomaly->id,
            'category'    => $anomaly->category,
            'severity'    => $anomaly->severity,
            'score'       => (string) $anomaly->score,
            'detector'    => $anomaly->detector,
            'detected_at' => $anomaly->detected_at->toIso8601String(),
        ];

        if ( $anomaly->user_id ) {
            $details['user_id'] = (string) $anomaly->user_id;
        }

        if ( isset( $anomaly->metadata['ip'] ) ) {
            $details['ip_address'] = $anomaly->metadata['ip'];
        }

        return $details;
    }

    /**
     * Map severity to OpsGenie priority.
     */
    protected function mapSeverityToPriority( string $severity ): string
    {
        $mapping = $this->config['priority_mapping'] ?? [];

        return $mapping[ $severity ] ?? 'P3';
    }
}
