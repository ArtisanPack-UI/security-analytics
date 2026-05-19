<?php

/**
 * SmsChannel alert channel.
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

class SmsChannel implements AlertChannelInterface
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
            'driver'  => 'twilio', // twilio, vonage, aws_sns
            'twilio'  => [
                'account_sid' => null,
                'auth_token'  => null,
                'from'        => null,
            ],
            'vonage' => [
                'api_key'    => null,
                'api_secret' => null,
                'from'       => null,
            ],
            'aws_sns' => [
                'region'    => 'us-east-1',
                'topic_arn' => null,
            ],
        ], $config );
    }

    /**
     * {@inheritdoc}
     */
    public function getName(): string
    {
        return 'sms';
    }

    /**
     * {@inheritdoc}
     */
    public function isEnabled(): bool
    {
        if ( ! ( $this->config['enabled'] ?? false ) ) {
            return false;
        }

        return match ( $this->config['driver'] ) {
            'twilio' => ! empty( $this->config['twilio']['account_sid'] )
                && ! empty( $this->config['twilio']['auth_token'] )
                && ! empty( $this->config['twilio']['from'] ),
            'vonage' => ! empty( $this->config['vonage']['api_key'] )
                && ! empty( $this->config['vonage']['api_secret'] ),
            'aws_sns' => ! empty( $this->config['aws_sns']['topic_arn'] ),
            default   => false,
        };
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
                'error'   => 'SMS channel is not configured',
            ];
        }

        if ( empty( $recipients ) ) {
            return [
                'success' => false,
                'error'   => 'No recipients specified',
            ];
        }

        $message    = $this->buildMessage( $anomaly, $rule );
        $results    = [];
        $allSuccess = true;

        foreach ( $recipients as $recipient ) {
            $result                = $this->sendSms( $recipient, $message );
            $results[ $recipient ] = $result;

            if ( ! $result['success'] ) {
                $allSuccess = false;
            }
        }

        return [
            'success' => $allSuccess,
            'results' => $results,
        ];
    }

    /**
     * Build the SMS message.
     */
    protected function buildMessage( Anomaly $anomaly, AlertRule $rule ): string
    {
        $severityEmoji = match ( $anomaly->severity ) {
            'critical' => '!!!',
            'high'     => '!!',
            'medium'   => '!',
            default    => '',
        };

        $message = "{$severityEmoji}SECURITY ALERT{$severityEmoji}\n";
        $message .= "{$rule->name}\n";
        $message .= "Severity: {$anomaly->severity}\n";
        $message .= "Category: {$anomaly->category}\n";

        if ( $anomaly->user_id ) {
            $message .= "User: {$anomaly->user_id}\n";
        }

        // Truncate to SMS limit (160 chars for standard SMS)
        if ( strlen( $message ) > 155 ) {
            $message = substr( $message, 0, 152 ) . '...';
        }

        return $message;
    }

    /**
     * Send SMS via configured driver.
     *
     * @return array<string, mixed>
     */
    protected function sendSms( string $phoneNumber, string $message ): array
    {
        return match ( $this->config['driver'] ) {
            'twilio'  => $this->sendViaTwilio( $phoneNumber, $message ),
            'vonage'  => $this->sendViaVonage( $phoneNumber, $message ),
            'aws_sns' => $this->sendViaAwsSns( $phoneNumber, $message ),
            default   => ['success' => false, 'error' => 'Unknown SMS driver'],
        };
    }

    /**
     * Send SMS via Twilio.
     *
     * @return array<string, mixed>
     */
    protected function sendViaTwilio( string $phoneNumber, string $message ): array
    {
        $config = $this->config['twilio'];

        try {
            $response = Http::withBasicAuth( $config['account_sid'], $config['auth_token'] )
                ->asForm()
                ->post(
                    "https://api.twilio.com/2010-04-01/Accounts/{$config['account_sid']}/Messages.json",
                    [
                        'From' => $config['from'],
                        'To'   => $phoneNumber,
                        'Body' => $message,
                    ],
                );

            if ( $response->successful() ) {
                $data = $response->json();

                return [
                    'success'     => true,
                    'message_sid' => $data['sid'] ?? null,
                    'recipient'   => $phoneNumber,
                ];
            }

            return [
                'success'  => false,
                'error'    => 'Twilio API error',
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
     * Send SMS via Vonage (Nexmo).
     *
     * @return array<string, mixed>
     */
    protected function sendViaVonage( string $phoneNumber, string $message ): array
    {
        $config = $this->config['vonage'];

        try {
            $response = Http::post( 'https://rest.nexmo.com/sms/json', [
                'api_key'    => $config['api_key'],
                'api_secret' => $config['api_secret'],
                'from'       => $config['from'] ?? 'Security',
                'to'         => $phoneNumber,
                'text'       => $message,
            ] );

            if ( $response->successful() ) {
                $data     = $response->json();
                $messages = $data['messages'] ?? [];

                if ( ! empty( $messages ) && ( $messages[0]['status'] ?? '1' ) === '0' ) {
                    return [
                        'success'    => true,
                        'message_id' => $messages[0]['message-id'] ?? null,
                        'recipient'  => $phoneNumber,
                    ];
                }

                return [
                    'success' => false,
                    'error'   => $messages[0]['error-text'] ?? 'Unknown Vonage error',
                ];
            }

            return [
                'success' => false,
                'error'   => 'Vonage API error',
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
     * Send SMS via AWS SNS.
     *
     * @return array<string, mixed>
     */
    protected function sendViaAwsSns( string $phoneNumber, string $message ): array
    {
        // AWS SNS requires the AWS SDK
        if ( ! class_exists( \Aws\Sns\SnsClient::class ) ) {
            return [
                'success' => false,
                'error'   => 'AWS SDK not installed. Run: composer require aws/aws-sdk-php',
            ];
        }

        try {
            $config = $this->config['aws_sns'];

            $client = new \Aws\Sns\SnsClient( [
                'version' => 'latest',
                'region'  => $config['region'],
            ] );

            $result = $client->publish( [
                'PhoneNumber'       => $phoneNumber,
                'Message'           => $message,
                'MessageAttributes' => [
                    'AWS.SNS.SMS.SMSType' => [
                        'DataType'    => 'String',
                        'StringValue' => 'Transactional',
                    ],
                ],
            ] );

            return [
                'success'    => true,
                'message_id' => $result->get( 'MessageId' ),
                'recipient'  => $phoneNumber,
            ];
        } catch ( Exception $e ) {
            return [
                'success' => false,
                'error'   => $e->getMessage(),
            ];
        }
    }
}
