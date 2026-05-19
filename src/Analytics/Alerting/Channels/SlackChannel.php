<?php

/**
 * SlackChannel alert channel.
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

class SlackChannel implements AlertChannelInterface
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
            'enabled'     => false,
            'webhook_url' => null,
            'channel'     => '#security-alerts',
            'username'    => 'Security Bot',
            'icon_emoji'  => ':shield:',
        ], $config );
    }

    /**
     * {@inheritdoc}
     */
    public function getName(): string
    {
        return 'slack';
    }

    /**
     * {@inheritdoc}
     */
    public function isEnabled(): bool
    {
        return ( $this->config['enabled'] ?? false ) && ! empty( $this->config['webhook_url'] );
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
                'error'   => 'Slack channel is not configured',
            ];
        }

        $payload = $this->buildPayload( $anomaly, $rule, $recipients );

        try {
            $response = Http::post( $this->config['webhook_url'], $payload );

            if ( $response->successful() ) {
                return [
                    'success'  => true,
                    'channel'  => $this->config['channel'],
                    'mentions' => $recipients,
                ];
            }

            return [
                'success' => false,
                'error'   => 'Slack API returned error',
                'status'  => $response->status(),
            ];
        } catch ( Exception $e ) {
            return [
                'success' => false,
                'error'   => $e->getMessage(),
            ];
        }
    }

    /**
     * Build the Slack payload.
     *
     * @param  array<int, string>  $recipients
     *
     * @return array<string, mixed>
     */
    protected function buildPayload( Anomaly $anomaly, AlertRule $rule, array $recipients ): array
    {
        $mentions = ! empty( $recipients ) ? implode( ' ', array_map( fn ( $r ) => "<@{$r}>", $recipients ) ) : '';

        return [
            'channel'     => $this->config['channel'],
            'username'    => $this->config['username'],
            'icon_emoji'  => $this->config['icon_emoji'],
            'text'        => $this->buildHeaderText( $anomaly, $rule, $mentions ),
            'attachments' => [
                [
                    'color'  => $this->getSeverityColor( $anomaly->severity ),
                    'blocks' => $this->buildBlocks( $anomaly, $rule ),
                ],
            ],
        ];
    }

    /**
     * Build header text.
     */
    protected function buildHeaderText( Anomaly $anomaly, AlertRule $rule, string $mentions ): string
    {
        $emoji = $this->getSeverityEmoji( $anomaly->severity );
        $text  = "{$emoji} *Security Alert: {$rule->name}*";

        if ( $mentions ) {
            $text .= "\n{$mentions}";
        }

        return $text;
    }

    /**
     * Build Slack blocks.
     *
     * @return array<int, array<string, mixed>>
     */
    protected function buildBlocks( Anomaly $anomaly, AlertRule $rule ): array
    {
        $blocks = [
            [
                'type' => 'section',
                'text' => [
                    'type' => 'mrkdwn',
                    'text' => "*Description:*\n{$anomaly->description}",
                ],
            ],
            [
                'type'   => 'section',
                'fields' => [
                    [
                        'type' => 'mrkdwn',
                        'text' => "*Severity:*\n{$anomaly->severity}",
                    ],
                    [
                        'type' => 'mrkdwn',
                        'text' => "*Category:*\n{$anomaly->category}",
                    ],
                    [
                        'type' => 'mrkdwn',
                        'text' => "*Score:*\n{$anomaly->score}",
                    ],
                    [
                        'type' => 'mrkdwn',
                        'text' => "*Detector:*\n{$anomaly->detector}",
                    ],
                ],
            ],
            [
                'type'     => 'context',
                'elements' => [
                    [
                        'type' => 'mrkdwn',
                        'text' => "Detected at: {$anomaly->detected_at->format( 'Y-m-d H:i:s T' )}",
                    ],
                ],
            ],
        ];

        // Add user info if available
        if ( $anomaly->user_id ) {
            $blocks[1]['fields'][] = [
                'type' => 'mrkdwn',
                'text' => "*User ID:*\n{$anomaly->user_id}",
            ];
        }

        // Add IP info if available
        if ( $anomaly->ip_address ) {
            $blocks[1]['fields'][] = [
                'type' => 'mrkdwn',
                'text' => "*IP Address:*\n{$anomaly->ip_address}",
            ];
        }

        return $blocks;
    }

    /**
     * Get color for severity.
     */
    protected function getSeverityColor( string $severity ): string
    {
        return match ( $severity ) {
            'critical' => '#dc3545',
            'high'     => '#fd7e14',
            'medium'   => '#ffc107',
            'low'      => '#17a2b8',
            default    => '#6c757d',
        };
    }

    /**
     * Get emoji for severity.
     */
    protected function getSeverityEmoji( string $severity ): string
    {
        return match ( $severity ) {
            'critical' => ':rotating_light:',
            'high'     => ':warning:',
            'medium'   => ':large_orange_diamond:',
            'low'      => ':information_source:',
            default    => ':grey_question:',
        };
    }
}
