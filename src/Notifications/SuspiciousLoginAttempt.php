<?php

/**
 * SuspiciousLoginAttempt notification.
 *
 * @package    ArtisanPack_UI
 * @subpackage SecurityAnalytics
 *
 * @author     Jacob Martella <support@artisanpackui.dev>
 *
 * @since      1.0.0
 */

declare( strict_types=1 );

namespace ArtisanPackUI\SecurityAnalytics\Notifications;

use ArtisanPackUI\SecurityAnalytics\Models\SuspiciousActivity;
use Illuminate\Bus\Queueable;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Notifications\Messages\MailMessage;
use Illuminate\Notifications\Notification;

class SuspiciousLoginAttempt extends Notification implements ShouldQueue
{
    use Queueable;

    /**
     * Create a new notification instance.
     */
    public function __construct(
        protected SuspiciousActivity $activity,
        protected ?string $ipAddress = null,
        protected ?string $userAgent = null,
        protected mixed $affectedUser = null,
    ) {
    }

    /**
     * Get the notification's delivery channels.
     *
     * @return array<int, string>
     */
    public function via( object $notifiable ): array
    {
        $channels = ['mail', 'database'];

        // Add SMS for critical alerts if configured
        if ( SuspiciousActivity::SEVERITY_CRITICAL === $this->activity->severity ) {
            if ( config( 'security.notifications.sms_for_critical', false ) ) {
                $channels[] = 'vonage'; // or 'twilio'
            }
        }

        return $channels;
    }

    /**
     * Get the mail representation of the notification.
     */
    public function toMail( object $notifiable ): MailMessage
    {
        $appName       = config( 'app.name' );
        $severityLabel = ucfirst( $this->activity->severity );

        $mail = (new MailMessage)
            ->subject( "[{$severityLabel}] Suspicious Activity Detected - {$appName}" )
            ->greeting( 'Security Alert' )
            ->line( "We detected suspicious activity on your {$appName} account." );

        // Add activity details
        $mail->line( "**Activity Type:** {$this->getActivityTypeLabel()}" )
            ->line( "**Severity:** {$severityLabel}" )
            ->line( "**Risk Score:** {$this->activity->risk_score}/100" )
            ->line( "**IP Address:** {$this->ipAddress}" )
            ->line( '**Time:** ' . now()->format( 'F j, Y \a\t g:i A T' ) );

        // Add specific details based on activity type
        if ( $details = $this->getActivityDetails() ) {
            $mail->line( '**Details:**' );
            foreach ( $details as $detail ) {
                $mail->line( "- {$detail}" );
            }
        }

        $mail->action( 'Review Account Security', url( '/settings/security' ) );

        if ( SuspiciousActivity::SEVERITY_CRITICAL === $this->activity->severity ) {
            $mail->line( '**IMPORTANT:** Your account may be compromised. We recommend:' )
                ->line( '1. Change your password immediately' )
                ->line( '2. Review recent account activity' )
                ->line( '3. Enable two-factor authentication' )
                ->line( '4. Check for unauthorized changes' );
        } else {
            $mail->line( 'If you recognize this activity, you can safely ignore this email.' );
        }

        return $mail;
    }

    /**
     * Get the array representation of the notification.
     *
     * @return array<string, mixed>
     */
    public function toArray( object $notifiable ): array
    {
        return [
            'type'          => 'suspicious_login_attempt',
            'activity_id'   => $this->activity->id,
            'activity_type' => $this->activity->type,
            'severity'      => $this->activity->severity,
            'risk_score'    => $this->activity->risk_score,
            'ip_address'    => $this->ipAddress,
            'user_agent'    => $this->userAgent,
            'details'       => $this->activity->details,
            'timestamp'     => now()->toIso8601String(),
        ];
    }

    /**
     * Get a human-readable activity type label.
     */
    protected function getActivityTypeLabel(): string
    {
        return match ( $this->activity->type ) {
            SuspiciousActivity::TYPE_IMPOSSIBLE_TRAVEL   => 'Impossible Travel Detected',
            SuspiciousActivity::TYPE_BRUTE_FORCE         => 'Brute Force Attack',
            SuspiciousActivity::TYPE_CREDENTIAL_STUFFING => 'Credential Stuffing',
            SuspiciousActivity::TYPE_UNUSUAL_LOCATION    => 'Login from Unusual Location',
            SuspiciousActivity::TYPE_UNUSUAL_DEVICE      => 'Login from Unknown Device',
            SuspiciousActivity::TYPE_UNUSUAL_TIME        => 'Login at Unusual Time',
            SuspiciousActivity::TYPE_RAPID_REQUESTS      => 'Rapid Request Pattern',
            SuspiciousActivity::TYPE_BOT_BEHAVIOR        => 'Automated Behavior Detected',
            SuspiciousActivity::TYPE_SESSION_ANOMALY     => 'Session Anomaly',
            SuspiciousActivity::TYPE_ACCOUNT_ENUMERATION => 'Account Enumeration Attempt',
            default                                      => ucwords( str_replace( '_', ' ', $this->activity->type ) ),
        };
    }

    /**
     * Get specific details about the activity.
     *
     * @return array<string>
     */
    protected function getActivityDetails(): array
    {
        $details         = [];
        $activityDetails = $this->activity->details ?? [];

        if ( SuspiciousActivity::TYPE_IMPOSSIBLE_TRAVEL === $this->activity->type ) {
            if ( isset( $activityDetails['from_location'], $activityDetails['to_location'] ) ) {
                $details[] = "Travel from {$activityDetails['from_location']} to {$activityDetails['to_location']}";
            }
            if ( isset( $activityDetails['distance_km'] ) ) {
                $details[] = "Distance: {$activityDetails['distance_km']} km";
            }
            if ( isset( $activityDetails['time_difference_minutes'] ) ) {
                $details[] = "Time difference: {$activityDetails['time_difference_minutes']} minutes";
            }
        }

        if ( SuspiciousActivity::TYPE_UNUSUAL_LOCATION === $this->activity->type ) {
            if ( isset( $activityDetails['country'] ) ) {
                $details[] = "Country: {$activityDetails['country']}";
            }
            if ( isset( $activityDetails['city'] ) ) {
                $details[] = "City: {$activityDetails['city']}";
            }
        }

        if ( SuspiciousActivity::TYPE_BRUTE_FORCE === $this->activity->type ) {
            if ( isset( $activityDetails['attempt_count'] ) ) {
                $details[] = "Failed attempts: {$activityDetails['attempt_count']}";
            }
        }

        return $details;
    }
}
