<?php

/**
 * AuthenticationMetricsListener metrics listener.
 *
 * @package    ArtisanPack_UI
 * @subpackage SecurityAnalytics
 *
 * @author     Jacob Martella <support@artisanpackui.dev>
 *
 * @since      1.0.0
 */

declare( strict_types=1 );

namespace ArtisanPackUI\SecurityAnalytics\Analytics\Listeners;

use ArtisanPackUI\SecurityAnalytics\Analytics\MetricsCollector;
use Illuminate\Auth\Events\Attempting;
use Illuminate\Auth\Events\Authenticated;
use Illuminate\Auth\Events\Failed;
use Illuminate\Auth\Events\Lockout;
use Illuminate\Auth\Events\Login;
use Illuminate\Auth\Events\Logout;
use Illuminate\Auth\Events\PasswordReset;
use Illuminate\Auth\Events\Registered;
use Illuminate\Auth\Events\Verified;

class AuthenticationMetricsListener
{
    public function __construct(
        protected MetricsCollector $collector,
    ) {
    }

    /**
     * Handle login attempts.
     */
    public function handleAttempting( Attempting $event ): void
    {
        $this->collector->increment(
            'auth.attempts',
            1,
            tags: ['guard' => $event->guard],
        );
    }

    /**
     * Handle successful authentication.
     */
    public function handleAuthenticated( Authenticated $event ): void
    {
        $this->collector->recordAuthEvent( 'authenticated', true, [
            'guard'   => $event->guard,
            'user_id' => $event->user->getAuthIdentifier(),
        ] );
    }

    /**
     * Handle failed login attempts.
     */
    public function handleFailed( Failed $event ): void
    {
        $this->collector->recordAuthEvent( 'login', false, [
            'guard'       => $event->guard,
            'credentials' => array_keys( $event->credentials ),
        ] );

        $this->collector->increment(
            'auth.failed',
            1,
            tags: ['guard' => $event->guard],
        );
    }

    /**
     * Handle successful login.
     */
    public function handleLogin( Login $event ): void
    {
        $this->collector->recordAuthEvent( 'login', true, [
            'guard'    => $event->guard,
            'user_id'  => $event->user->getAuthIdentifier(),
            'remember' => $event->remember,
        ] );

        $this->collector->increment(
            'auth.success',
            1,
            tags: ['guard' => $event->guard],
        );
    }

    /**
     * Handle logout.
     */
    public function handleLogout( Logout $event ): void
    {
        $this->collector->recordAuthEvent( 'logout', true, [
            'guard'   => $event->guard,
            'user_id' => $event->user?->getAuthIdentifier(),
        ] );
    }

    /**
     * Handle account lockout.
     */
    public function handleLockout( Lockout $event ): void
    {
        $this->collector->recordAuthEvent( 'lockout', true, [
            'ip' => $event->request->ip(),
        ] );

        $this->collector->recordThreatEvent( 'account_lockout', 'medium', [
            'ip' => $event->request->ip(),
        ] );
    }

    /**
     * Handle password reset.
     */
    public function handlePasswordReset( PasswordReset $event ): void
    {
        $this->collector->recordAuthEvent( 'password_reset', true, [
            'user_id' => $event->user->getAuthIdentifier(),
        ] );
    }

    /**
     * Handle new user registration.
     */
    public function handleRegistered( Registered $event ): void
    {
        $this->collector->recordAuthEvent( 'registration', true, [
            'user_id' => $event->user->getAuthIdentifier(),
        ] );
    }

    /**
     * Handle email verification.
     */
    public function handleVerified( Verified $event ): void
    {
        $this->collector->recordAuthEvent( 'email_verified', true, [
            'user_id' => $event->user->getAuthIdentifier(),
        ] );
    }

    /**
     * Subscribe to authentication events.
     *
     * @param  \Illuminate\Events\Dispatcher  $events
     */
    public function subscribe( $events ): void
    {
        $events->listen( Attempting::class, [self::class, 'handleAttempting'] );
        $events->listen( Authenticated::class, [self::class, 'handleAuthenticated'] );
        $events->listen( Failed::class, [self::class, 'handleFailed'] );
        $events->listen( Login::class, [self::class, 'handleLogin'] );
        $events->listen( Logout::class, [self::class, 'handleLogout'] );
        $events->listen( Lockout::class, [self::class, 'handleLockout'] );
        $events->listen( PasswordReset::class, [self::class, 'handlePasswordReset'] );
        $events->listen( Registered::class, [self::class, 'handleRegistered'] );
        $events->listen( Verified::class, [self::class, 'handleVerified']);
    }
}
