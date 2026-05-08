<?php

declare( strict_types=1 );

namespace ArtisanPackUI\SecurityAnalytics\Analytics\Alerting\Channels;

use ArtisanPackUI\SecurityAnalytics\Analytics\Alerting\Contracts\AlertChannelInterface;
use ArtisanPackUI\SecurityAnalytics\Models\AlertRule;
use ArtisanPackUI\SecurityAnalytics\Models\Anomaly;
use Exception;
use Illuminate\Support\Facades\Mail;

class EmailChannel implements AlertChannelInterface
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
            'enabled'        => true,
            'from'           => config( 'mail.from.address' ),
            'from_name'      => config( 'mail.from.name' ),
            'subject_prefix' => '[Security Alert]',
        ], $config );
    }

    /**
     * {@inheritdoc}
     */
    public function getName(): string
    {
        return 'email';
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
        if ( empty( $recipients ) ) {
            return [
                'success' => false,
                'error'   => 'No recipients specified',
            ];
        }

        $subject = $this->buildSubject( $anomaly, $rule );
        $body    = $this->buildBody( $anomaly, $rule );

        $sentTo = [];
        $failed = [];

        foreach ( $recipients as $recipient ) {
            try {
                Mail::raw( $body, function ( $message ) use ( $recipient, $subject ): void {
                    $message->to( $recipient )
                        ->subject( $subject );

                    if ( $this->config['from'] ) {
                        $message->from( $this->config['from'], $this->config['from_name'] ?? null );
                    }
                } );

                $sentTo[] = $recipient;
            } catch ( Exception $e ) {
                $failed[ $recipient ] = $e->getMessage();
            }
        }

        return [
            'success'      => count( $sentTo ) > 0,
            'sent_to'      => $sentTo,
            'failed'       => $failed,
            'total_sent'   => count( $sentTo ),
            'total_failed' => count( $failed ),
        ];
    }

    /**
     * Build the email subject.
     */
    protected function buildSubject( Anomaly $anomaly, AlertRule $rule ): string
    {
        $prefix   = $this->config['subject_prefix'];
        $severity = strtoupper( $anomaly->severity );

        return "{$prefix} [{$severity}] {$rule->name}";
    }

    /**
     * Build the email body.
     */
    protected function buildBody( Anomaly $anomaly, AlertRule $rule ): string
    {
        $lines = [
            'SECURITY ALERT',
            str_repeat( '=', 50 ),
            '',
            "Alert Rule: {$rule->name}",
            "Severity: {$anomaly->severity}",
            "Category: {$anomaly->category}",
            '',
            'ANOMALY DETAILS',
            str_repeat( '-', 50 ),
            "Description: {$anomaly->description}",
            "Score: {$anomaly->score}",
            "Detector: {$anomaly->detector}",
            "Detected At: {$anomaly->detected_at->format( 'Y-m-d H:i:s T' )}",
            '',
        ];

        if ( $anomaly->user_id ) {
            $lines[] = "User ID: {$anomaly->user_id}";
        }

        if ( ! empty( $anomaly->metadata ) ) {
            $lines[] = '';
            $lines[] = 'ADDITIONAL INFORMATION';
            $lines[] = str_repeat( '-', 50 );

            foreach ( $anomaly->metadata as $key => $value ) {
                $displayValue = is_array( $value ) ? json_encode( $value ) : (string) $value;
                $lines[]      = "{$key}: {$displayValue}";
            }
        }

        $lines[] = '';
        $lines[] = str_repeat( '=', 50 );
        $lines[] = 'This is an automated security alert from your application.';
        $lines[] = 'Please investigate this alert promptly.';

        return implode( "\n", $lines);
    }
}
