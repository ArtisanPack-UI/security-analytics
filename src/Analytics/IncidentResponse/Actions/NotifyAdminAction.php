<?php

declare( strict_types=1 );

namespace ArtisanPackUI\SecurityAnalytics\Analytics\IncidentResponse\Actions;

use ArtisanPackUI\SecurityAnalytics\Models\Anomaly;
use ArtisanPackUI\SecurityAnalytics\Models\SecurityIncident;
use Exception;
use Illuminate\Support\Facades\Mail;
use Illuminate\Support\Facades\Notification;
use RuntimeException;

class NotifyAdminAction extends AbstractAction
{
    /**
     * {@inheritdoc}
     */
    public function getName(): string
    {
        return 'notify_admin';
    }

    /**
     * {@inheritdoc}
     */
    public function execute( Anomaly $anomaly, ?SecurityIncident $incident = null, array $config = [] ): array
    {
        $channels   = $config['channels'] ?? ['email'];
        $recipients = $config['recipients'] ?? $this->getDefaultRecipients();
        $notified   = [];
        $failed     = [];

        foreach ( $channels as $channel ) {
            try {
                match ( $channel ) {
                    'email' => $this->notifyViaEmail( $anomaly, $incident, $recipients ),
                    'slack' => $this->notifyViaSlack( $anomaly, $incident, $config['slack_webhook'] ?? null ),
                    default => null,
                };
                $notified[] = $channel;
            } catch ( Exception $e ) {
                $failed[ $channel ] = $e->getMessage();
            }
        }

        if ( $incident ) {
            $this->logToIncident( $incident, [
                'channels_notified' => $notified,
                'channels_failed'   => $failed,
                'recipients'        => $recipients,
            ] );
        }

        if ( empty( $notified ) ) {
            return $this->failure( 'Failed to notify via any channel', ['errors' => $failed] );
        }

        return $this->success( 'Admin notification sent', [
            'channels_notified' => $notified,
            'channels_failed'   => $failed,
            'recipient_count'   => count( $recipients ),
        ] );
    }

    /**
     * Get default admin recipients.
     *
     * @return array<int, string>
     */
    protected function getDefaultRecipients(): array
    {
        $recipients = config( 'security-analytics.alerting.channels.email.default_recipients', [] );

        if ( empty( $recipients ) ) {
            $recipients = [config( 'mail.from.address' )];
        }

        return array_filter( $recipients );
    }

    /**
     * Send notification via email.
     *
     * @param  array<int, string>  $recipients
     */
    protected function notifyViaEmail( Anomaly $anomaly, ?SecurityIncident $incident, array $recipients ): void
    {
        if ( empty( $recipients ) ) {
            throw new RuntimeException( 'No email recipients configured' );
        }

        $subject = $this->getEmailSubject( $anomaly, $incident );
        $body    = $this->getEmailBody( $anomaly, $incident );

        foreach ( $recipients as $recipient ) {
            Mail::raw( $body, function ( $message ) use ( $recipient, $subject ): void {
                $message->to( $recipient )
                    ->subject( $subject );
            } );
        }
    }

    /**
     * Send notification via Slack.
     */
    protected function notifyViaSlack( Anomaly $anomaly, ?SecurityIncident $incident, ?string $webhookUrl ): void
    {
        $webhookUrl = $webhookUrl ?? config( 'security-analytics.alerting.channels.slack.webhook_url' );

        if ( ! $webhookUrl ) {
            throw new RuntimeException( 'Slack webhook URL not configured' );
        }

        $payload = [
            'text'        => $this->getSlackMessage( $anomaly, $incident ),
            'attachments' => [
                [
                    'color'  => $this->getSeverityColor( $anomaly->severity ),
                    'fields' => $this->getSlackFields( $anomaly, $incident ),
                ],
            ],
        ];

        $response = \Illuminate\Support\Facades\Http::timeout( 10 )->post( $webhookUrl, $payload );

        if ( ! $response->successful() ) {
            throw new RuntimeException(
                'Failed to send Slack notification: ' . $response->status() . ' - ' . $response->body(),
            );
        }
    }

    /**
     * Get email subject.
     */
    protected function getEmailSubject( Anomaly $anomaly, ?SecurityIncident $incident ): string
    {
        $severity = strtoupper( $anomaly->severity );
        $prefix   = "[{$severity}] Security Alert";

        if ( $incident ) {
            return "{$prefix}: {$incident->title}";
        }

        return "{$prefix}: {$anomaly->category}";
    }

    /**
     * Get email body.
     */
    protected function getEmailBody( Anomaly $anomaly, ?SecurityIncident $incident ): string
    {
        $lines = [
            'Security Anomaly Detected',
            '',
            "Severity: {$anomaly->severity}",
            "Category: {$anomaly->category}",
            "Description: {$anomaly->description}",
            "Score: {$anomaly->score}",
            "Detected At: {$anomaly->detected_at}",
        ];

        if ( $incident ) {
            $lines[] = '';
            $lines[] = 'Associated Incident:';
            $lines[] = "Incident #: {$incident->incident_number}";
            $lines[] = "Title: {$incident->title}";
            $lines[] = "Status: {$incident->status}";
        }

        if ( ! empty( $anomaly->metadata ) ) {
            $lines[] = '';
            $lines[] = 'Metadata:';
            foreach ( $anomaly->metadata as $key => $value ) {
                $lines[] = "  {$key}: " . ( is_array( $value ) ? json_encode( $value ) : $value );
            }
        }

        return implode( "\n", $lines );
    }

    /**
     * Get Slack message.
     */
    protected function getSlackMessage( Anomaly $anomaly, ?SecurityIncident $incident ): string
    {
        $emoji   = $this->getSeverityEmoji( $anomaly->severity );
        $message = "{$emoji} *Security Alert*: {$anomaly->description}";

        if ( $incident ) {
            $message .= " (Incident #{$incident->incident_number})";
        }

        return $message;
    }

    /**
     * Get Slack fields.
     *
     * @return array<int, array<string, mixed>>
     */
    protected function getSlackFields( Anomaly $anomaly, ?SecurityIncident $incident ): array
    {
        $fields = [
            ['title' => 'Severity', 'value' => $anomaly->severity, 'short' => true],
            ['title' => 'Category', 'value' => $anomaly->category, 'short' => true],
            ['title' => 'Score', 'value' => (string) $anomaly->score, 'short' => true],
            ['title' => 'Detected At', 'value' => $anomaly->detected_at->format( 'Y-m-d H:i:s' ), 'short' => true],
        ];

        if ( $incident ) {
            $fields[] = ['title' => 'Incident', 'value' => $incident->incident_number, 'short' => true];
            $fields[] = ['title' => 'Status', 'value' => $incident->status, 'short' => true];
        }

        return $fields;
    }

    /**
     * Get color for severity level.
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
     * Get emoji for severity level.
     */
    protected function getSeverityEmoji( string $severity ): string
    {
        return match ( $severity ) {
            'critical' => '🚨',
            'high'     => '⚠️',
            'medium'   => '⚡',
            'low'      => 'ℹ️',
            default    => '📋',
        };
    }
}
