<?php

/**
 * LogAuthenticationEvents event listener.
 *
 * @package    ArtisanPack_UI
 * @subpackage SecurityAnalytics
 *
 * @author     Jacob Martella <support@artisanpackui.dev>
 *
 * @since      1.0.0
 */

declare( strict_types=1 );

namespace ArtisanPackUI\SecurityAnalytics\Listeners;

use ArtisanPackUI\SecurityAnalytics\Contracts\SecurityEventLoggerInterface;
use ArtisanPackUI\SecurityAnalytics\Models\SecurityEvent;
use Illuminate\Auth\Events\Failed;
use Illuminate\Auth\Events\Lockout;
use Illuminate\Auth\Events\Login;
use Illuminate\Auth\Events\Logout;
use Illuminate\Auth\Events\OtherDeviceLogout;
use Illuminate\Auth\Events\PasswordReset;
use Illuminate\Auth\Events\Registered;
use Illuminate\Auth\Events\Verified;
use Illuminate\Events\Dispatcher;

class LogAuthenticationEvents
{
    public function __construct(
        protected SecurityEventLoggerInterface $logger,
    ) {
    }

    /**
     * Register the listeners for the subscriber.
     */
    public function subscribe( Dispatcher $events ): void
    {
        $events->listen( Login::class, [self::class, 'handleLogin'] );
        $events->listen( Failed::class, [self::class, 'handleFailed'] );
        $events->listen( Logout::class, [self::class, 'handleLogout'] );
        $events->listen( Lockout::class, [self::class, 'handleLockout'] );
        $events->listen( PasswordReset::class, [self::class, 'handlePasswordReset'] );
        $events->listen( Registered::class, [self::class, 'handleRegistered'] );
        $events->listen( Verified::class, [self::class, 'handleVerified'] );
        $events->listen( OtherDeviceLogout::class, [self::class, 'handleOtherDeviceLogout'] );
    }

    /**
     * Handle successful login events.
     */
    public function handleLogin( Login $event ): void
    {
        if ( ! $this->isEventEnabled( 'loginSuccess' ) ) {
            return;
        }

        $this->logger->authentication( 'login_success', [
            'user_id'  => $event->user->getAuthIdentifier(),
            'guard'    => $event->guard,
            'remember' => $event->remember,
        ], SecurityEvent::SEVERITY_INFO );
    }

    /**
     * Handle failed login events.
     */
    public function handleFailed( Failed $event ): void
    {
        if ( ! $this->isEventEnabled( 'loginFailed' ) ) {
            return;
        }

        $this->logger->authentication( 'login_failed', [
            'user_id'     => $event->user?->getAuthIdentifier(),
            'guard'       => $event->guard,
            'credentials' => $this->sanitizeCredentials( $event->credentials ),
        ], SecurityEvent::SEVERITY_WARNING );
    }

    /**
     * Handle logout events.
     */
    public function handleLogout( Logout $event ): void
    {
        if ( ! $this->isEventEnabled( 'logout' ) ) {
            return;
        }

        $this->logger->authentication( 'logout', [
            'user_id' => $event->user?->getAuthIdentifier(),
            'guard'   => $event->guard,
        ], SecurityEvent::SEVERITY_INFO );
    }

    /**
     * Handle lockout events.
     */
    public function handleLockout( Lockout $event ): void
    {
        if ( ! $this->isEventEnabled( 'lockout' ) ) {
            return;
        }

        $email = $event->request->input( 'email' );

        $this->logger->authentication( 'lockout', [
            'ip_address' => $event->request->ip(),
            'email'      => $email ? $this->maskEmail( $email ) : null,
        ], SecurityEvent::SEVERITY_WARNING );
    }

    /**
     * Handle password reset events.
     */
    public function handlePasswordReset( PasswordReset $event ): void
    {
        if ( ! $this->isEventEnabled( 'passwordReset' ) ) {
            return;
        }

        $this->logger->authentication( 'password_reset', [
            'user_id' => $event->user->getAuthIdentifier(),
        ], SecurityEvent::SEVERITY_INFO );
    }

    /**
     * Handle user registered events.
     */
    public function handleRegistered( Registered $event ): void
    {
        if ( ! $this->isEventEnabled( 'registered' ) ) {
            return;
        }

        $this->logger->authentication( 'registered', [
            'user_id' => $event->user->getAuthIdentifier(),
        ], SecurityEvent::SEVERITY_INFO );
    }

    /**
     * Handle email verified events.
     */
    public function handleVerified( Verified $event ): void
    {
        if ( ! $this->isEventEnabled( 'emailVerified' ) ) {
            return;
        }

        $this->logger->authentication( 'email_verified', [
            'user_id' => $event->user->getAuthIdentifier(),
        ], SecurityEvent::SEVERITY_INFO );
    }

    /**
     * Handle other device logout events.
     */
    public function handleOtherDeviceLogout( OtherDeviceLogout $event ): void
    {
        if ( ! $this->isEventEnabled( 'otherDeviceLogout' ) ) {
            return;
        }

        $this->logger->authentication( 'other_device_logout', [
            'user_id' => $event->user->getAuthIdentifier(),
            'guard'   => $event->guard,
        ], SecurityEvent::SEVERITY_INFO );
    }

    /**
     * Check if a specific authentication event is enabled.
     */
    protected function isEventEnabled( string $event ): bool
    {
        return config( "artisanpack.security-analytics.events.authentication.events.{$event}", true );
    }

    /**
     * Sanitize credentials to remove sensitive data.
     */
    protected function sanitizeCredentials( array $credentials ): array
    {
        $sanitized = $credentials;

        // Remove password-related fields
        unset(
            $sanitized['password'],
            $sanitized['password_confirmation'],
            $sanitized['current_password'],
            $sanitized['new_password'],
        );

        // Mask email if present
        if ( isset( $sanitized['email'] ) ) {
            $sanitized['email'] = $this->maskEmail( $sanitized['email'] );
        }

        return $sanitized;
    }

    /**
     * Mask an email address for privacy.
     */
    protected function maskEmail( string $email ): string
    {
        $parts = explode( '@', $email );

        if ( 2 !== count( $parts ) ) {
            return '***';
        }

        $name   = $parts[0];
        $domain = $parts[1];

        if ( strlen( $name ) <= 2 ) {
            $maskedName = str_repeat( '*', strlen( $name ) );
        } else {
            $maskedName = substr( $name, 0, 1 ) . str_repeat( '*', strlen( $name ) - 2 ) . substr( $name, -1 );
        }

        return $maskedName . '@' . $domain;
    }
}
