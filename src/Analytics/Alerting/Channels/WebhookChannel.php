<?php

declare( strict_types=1 );

namespace ArtisanPackUI\SecurityAnalytics\Analytics\Alerting\Channels;

use ArtisanPackUI\SecurityAnalytics\Analytics\Alerting\Contracts\AlertChannelInterface;
use ArtisanPackUI\SecurityAnalytics\Models\AlertRule;
use ArtisanPackUI\SecurityAnalytics\Models\Anomaly;
use Exception;
use Illuminate\Support\Facades\Http;

class WebhookChannel implements AlertChannelInterface
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
            'enabled' => false,
            'url'     => null,
            'secret'  => null,
            'method'  => 'POST',
            'headers' => [],
            'timeout' => 30,
            'retry'   => 3,
        ], $config );
    }

    /**
     * {@inheritdoc}
     */
    public function getName(): string
    {
        return 'webhook';
    }

    /**
     * {@inheritdoc}
     */
    public function isEnabled(): bool
    {
        return ( $this->config['enabled'] ?? false ) && ! empty( $this->config['url'] );
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
                'error'   => 'Webhook channel is not configured',
            ];
        }

        $payload = $this->buildPayload( $anomaly, $rule, $recipients );
        $headers = $this->buildHeaders( $payload );

        try {
            $http = Http::withHeaders( $headers )
                ->timeout( $this->config['timeout'] )
                ->retry( $this->config['retry'], 1000 );

            $response = match ( strtoupper( $this->config['method'] ) ) {
                'GET'   => $http->get( $this->config['url'], $payload ),
                'PUT'   => $http->put( $this->config['url'], $payload ),
                'PATCH' => $http->patch( $this->config['url'], $payload ),
                default => $http->post( $this->config['url'], $payload ),
            };

            if ( $response->successful() ) {
                return [
                    'success'  => true,
                    'url'      => $this->config['url'],
                    'status'   => $response->status(),
                    'response' => $response->json(),
                ];
            }

            return [
                'success'  => false,
                'error'    => 'Webhook returned non-success status',
                'status'   => $response->status(),
                'response' => $response->body(),
            ];
        } catch ( Exception $e ) {
            return [
                'success' => false,
                'error'   => $e->getMessage(),
            ];
        }
    }

    /**
     * Build the webhook payload.
     *
     * @param  array<int, string>  $recipients
     *
     * @return array<string, mixed>
     */
    protected function buildPayload( Anomaly $anomaly, AlertRule $rule, array $recipients ): array
    {
        return [
            'event'     => 'security.alert',
            'timestamp' => now()->toIso8601String(),
            'alert'     => [
                'rule_id'   => $rule->id,
                'rule_name' => $rule->name,
                'severity'  => $rule->severity,
            ],
            'anomaly' => [
                'id'          => $anomaly->id,
                'detector'    => $anomaly->detector,
                'category'    => $anomaly->category,
                'severity'    => $anomaly->severity,
                'score'       => $anomaly->score,
                'description' => $anomaly->description,
                'detected_at' => $anomaly->detected_at->toIso8601String(),
                'user_id'     => $anomaly->user_id,
                'ip_address'  => $anomaly->ip_address,
                'metadata'    => $anomaly->metadata,
                'resolved'    => null !== $anomaly->resolved_at,
            ],
            'recipients' => $recipients,
            'source'     => [
                'application' => config( 'app.name', 'Laravel' ),
                'environment' => config( 'app.env' ),
                'url'         => config( 'app.url' ),
            ],
        ];
    }

    /**
     * Build request headers.
     *
     * @param  array<string, mixed>  $payload
     *
     * @return array<string, string>
     */
    protected function buildHeaders( array $payload ): array
    {
        $headers = array_merge( [
            'Content-Type' => 'application/json',
            'Accept'       => 'application/json',
            'User-Agent'   => 'ArtisanPack-Security/1.0',
        ], $this->config['headers'] ?? [] );

        // Add signature if secret is configured
        if ( ! empty( $this->config['secret'] ) ) {
            $payloadJson                        = json_encode( $payload, JSON_THROW_ON_ERROR );
            $signature                          = hash_hmac( 'sha256', $payloadJson, $this->config['secret'] );
            $headers['X-Webhook-Signature']     = $signature;
            $headers['X-Webhook-Signature-256'] = 'sha256=' . $signature;
        }

        return $headers;
    }
}
