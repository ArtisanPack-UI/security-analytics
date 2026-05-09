<?php

declare( strict_types=1 );

namespace ArtisanPackUI\SecurityAnalytics\Analytics\Alerting\Channels;

use ArtisanPackUI\SecurityAnalytics\Analytics\Alerting\Contracts\AlertChannelInterface;
use ArtisanPackUI\SecurityAnalytics\Models\AlertRule;
use ArtisanPackUI\SecurityAnalytics\Models\Anomaly;
use Exception;
use Illuminate\Support\Facades\Http;

class TeamsChannel implements AlertChannelInterface
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
        ], $config );
    }

    /**
     * {@inheritdoc}
     */
    public function getName(): string
    {
        return 'teams';
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
                'error'   => 'Teams channel is not configured',
            ];
        }

        $payload = $this->buildPayload( $anomaly, $rule, $recipients );

        try {
            $response = Http::post( $this->config['webhook_url'], $payload );

            if ( $response->successful() ) {
                return [
                    'success'  => true,
                    'mentions' => $recipients,
                ];
            }

            return [
                'success' => false,
                'error'   => 'Teams webhook returned error',
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
     * Build the Teams Adaptive Card payload.
     *
     * @param  array<int, string>  $recipients
     *
     * @return array<string, mixed>
     */
    protected function buildPayload( Anomaly $anomaly, AlertRule $rule, array $recipients ): array
    {
        $mentionText     = '';
        $mentionEntities = [];

        if ( ! empty( $recipients ) ) {
            foreach ( $recipients as $index => $recipient ) {
                $mentionEntities[] = [
                    'type'      => 'mention',
                    'text'      => "<at>{$recipient}</at>",
                    'mentioned' => [
                        'id'   => $recipient,
                        'name' => $recipient,
                    ],
                ];
            }
            $mentionText = implode( ', ', array_map( fn ( $r ) => "<at>{$r}</at>", $recipients ) );
        }

        $adaptiveCard = [
            'type'    => 'AdaptiveCard',
            '$schema' => 'http://adaptivecards.io/schemas/adaptive-card.json',
            'version' => '1.4',
            'body'    => [
                [
                    'type'    => 'ColumnSet',
                    'columns' => [
                        [
                            'type'  => 'Column',
                            'width' => 'auto',
                            'items' => [
                                [
                                    'type'  => 'Image',
                                    'url'   => $this->getSeverityImage( $anomaly->severity ),
                                    'size'  => 'Small',
                                    'style' => 'Person',
                                ],
                            ],
                        ],
                        [
                            'type'  => 'Column',
                            'width' => 'stretch',
                            'items' => [
                                [
                                    'type'   => 'TextBlock',
                                    'text'   => "Security Alert: {$rule->name}",
                                    'weight' => 'Bolder',
                                    'size'   => 'Medium',
                                    'color'  => $this->getSeverityAdaptiveColor( $anomaly->severity ),
                                ],
                                [
                                    'type'     => 'TextBlock',
                                    'text'     => $anomaly->detected_at->format( 'Y-m-d H:i:s T' ),
                                    'size'     => 'Small',
                                    'isSubtle' => true,
                                    'spacing'  => 'None',
                                ],
                            ],
                        ],
                    ],
                ],
                [
                    'type'    => 'TextBlock',
                    'text'    => $anomaly->description,
                    'wrap'    => true,
                    'spacing' => 'Medium',
                ],
                [
                    'type'    => 'FactSet',
                    'facts'   => $this->buildFacts( $anomaly ),
                    'spacing' => 'Medium',
                ],
            ],
            'actions' => $this->buildActions( $anomaly ),
            'msteams' => [
                'width' => 'Full',
            ],
        ];

        if ( ! empty( $mentionText ) ) {
            $adaptiveCard['body'][] = [
                'type'    => 'TextBlock',
                'text'    => $mentionText,
                'wrap'    => true,
                'spacing' => 'Medium',
            ];
            $adaptiveCard['msteams']['entities'] = $mentionEntities;
        }

        return [
            'type'        => 'message',
            'attachments' => [
                [
                    'contentType' => 'application/vnd.microsoft.card.adaptive',
                    'contentUrl'  => null,
                    'content'     => $adaptiveCard,
                ],
            ],
        ];
    }

    /**
     * Build facts for the card.
     *
     * @return array<int, array<string, string>>
     */
    protected function buildFacts( Anomaly $anomaly ): array
    {
        $facts = [
            ['title' => 'Severity', 'value' => ucfirst( $anomaly->severity )],
            ['title' => 'Category', 'value' => ucfirst( $anomaly->category )],
            ['title' => 'Score', 'value' => (string) $anomaly->score],
            ['title' => 'Detector', 'value' => $anomaly->detector],
        ];

        if ( $anomaly->user_id ) {
            $facts[] = ['title' => 'User ID', 'value' => (string) $anomaly->user_id];
        }

        if ( isset( $anomaly->metadata['ip'] ) ) {
            $facts[] = ['title' => 'IP Address', 'value' => $anomaly->metadata['ip']];
        }

        return $facts;
    }

    /**
     * Build Adaptive Card actions.
     *
     * @return array<int, array<string, mixed>>
     */
    protected function buildActions( Anomaly $anomaly ): array
    {
        $dashboardUrl = config( 'app.url' ) . '/security/dashboard';

        return [
            [
                'type'  => 'Action.OpenUrl',
                'title' => 'View in Dashboard',
                'url'   => $dashboardUrl,
            ],
        ];
    }

    /**
     * Get hex color for severity.
     */
    protected function getSeverityColor( string $severity ): string
    {
        return match ( $severity ) {
            'critical' => 'dc3545',
            'high'     => 'fd7e14',
            'medium'   => 'ffc107',
            'low'      => '17a2b8',
            default    => '6c757d',
        };
    }

    /**
     * Get Adaptive Card color for severity.
     */
    protected function getSeverityAdaptiveColor( string $severity ): string
    {
        return match ( $severity ) {
            'critical' => 'Attention',
            'high'     => 'Warning',
            'medium'   => 'Warning',
            'low'      => 'Accent',
            default    => 'Default',
        };
    }

    /**
     * Get image URL for severity.
     */
    protected function getSeverityImage( string $severity ): string
    {
        return match ( $severity ) {
            'critical' => 'https://img.icons8.com/color/48/000000/high-priority.png',
            'high'     => 'https://img.icons8.com/color/48/000000/warning-shield.png',
            'medium'   => 'https://img.icons8.com/color/48/000000/medium-priority.png',
            'low'      => 'https://img.icons8.com/color/48/000000/info.png',
            default    => 'https://img.icons8.com/color/48/000000/security-checked.png',
        };
    }
}
