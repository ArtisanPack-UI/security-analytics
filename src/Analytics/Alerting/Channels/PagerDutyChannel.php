<?php

declare( strict_types=1 );

namespace ArtisanPackUI\SecurityAnalytics\Analytics\Alerting\Channels;

use ArtisanPackUI\SecurityAnalytics\Analytics\Alerting\Contracts\AlertChannelInterface;
use ArtisanPackUI\SecurityAnalytics\Models\AlertRule;
use ArtisanPackUI\SecurityAnalytics\Models\Anomaly;
use Exception;
use Illuminate\Support\Facades\Http;

class PagerDutyChannel implements AlertChannelInterface
{
    protected const API_URL = 'https://events.pagerduty.com/v2/enqueue';

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
            'enabled'          => false,
            'routing_key'      => null,
            'severity_mapping' => [
                'info'     => 'info',
                'low'      => 'warning',
                'medium'   => 'error',
                'high'     => 'error',
                'critical' => 'critical',
            ],
        ], $config );
    }

    /**
     * {@inheritdoc}
     */
    public function getName(): string
    {
        return 'pagerduty';
    }

    /**
     * {@inheritdoc}
     */
    public function isEnabled(): bool
    {
        return ( $this->config['enabled'] ?? false ) && ! empty( $this->config['routing_key'] );
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
                'error'   => 'PagerDuty channel is not configured',
            ];
        }

        $payload = $this->buildPayload( $anomaly, $rule );

        try {
            $response = Http::post( self::API_URL, $payload );

            if ( $response->successful() ) {
                $data = $response->json();

                return [
                    'success'   => true,
                    'dedup_key' => $data['dedup_key'] ?? null,
                    'status'    => $data['status'] ?? 'success',
                ];
            }

            return [
                'success'  => false,
                'error'    => 'PagerDuty API returned error',
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
     * Resolve a PagerDuty incident.
     *
     * @return array<string, mixed>
     */
    public function resolve( string $dedupKey ): array
    {
        if ( ! $this->isEnabled() ) {
            return ['success' => false, 'error' => 'Not configured'];
        }

        $payload = [
            'routing_key'  => $this->config['routing_key'],
            'event_action' => 'resolve',
            'dedup_key'    => $dedupKey,
        ];

        try {
            $response = Http::post( self::API_URL, $payload );

            return [
                'success' => $response->successful(),
                'status'  => $response->status(),
            ];
        } catch ( Exception $e ) {
            return ['success' => false, 'error' => $e->getMessage()];
        }
    }

    /**
     * Acknowledge a PagerDuty incident.
     *
     * @return array<string, mixed>
     */
    public function acknowledge( string $dedupKey ): array
    {
        if ( ! $this->isEnabled() ) {
            return ['success' => false, 'error' => 'Not configured'];
        }

        $payload = [
            'routing_key'  => $this->config['routing_key'],
            'event_action' => 'acknowledge',
            'dedup_key'    => $dedupKey,
        ];

        try {
            $response = Http::post( self::API_URL, $payload );

            return [
                'success' => $response->successful(),
                'status'  => $response->status(),
            ];
        } catch ( Exception $e ) {
            return ['success' => false, 'error' => $e->getMessage()];
        }
    }

    /**
     * Build the PagerDuty payload.
     *
     * @return array<string, mixed>
     */
    protected function buildPayload( Anomaly $anomaly, AlertRule $rule ): array
    {
        $severityMapping = $this->config['severity_mapping'];
        $pdSeverity      = $severityMapping[ $anomaly->severity ] ?? 'error';

        return [
            'routing_key'  => $this->config['routing_key'],
            'event_action' => 'trigger',
            'dedup_key'    => "security-{$anomaly->id}",
            'payload'      => [
                'summary'        => "[{$anomaly->severity}] {$rule->name}: {$anomaly->description}",
                'source'         => config( 'app.name', 'Security System' ),
                'severity'       => $pdSeverity,
                'timestamp'      => $anomaly->detected_at->toIso8601String(),
                'component'      => 'security',
                'group'          => $anomaly->category,
                'class'          => $anomaly->detector,
                'custom_details' => [
                    'anomaly_id' => $anomaly->id,
                    'category'   => $anomaly->category,
                    'score'      => $anomaly->score,
                    'detector'   => $anomaly->detector,
                    'user_id'    => $anomaly->user_id,
                    'metadata'   => $anomaly->metadata,
                    'rule_name'  => $rule->name,
                    'rule_id'    => $rule->id,
                ],
            ],
            'links' => [
                [
                    'href' => url( '/admin/security/anomalies/' . $anomaly->id ),
                    'text' => 'View Anomaly Details',
                ],
            ],
        ];
    }
}
