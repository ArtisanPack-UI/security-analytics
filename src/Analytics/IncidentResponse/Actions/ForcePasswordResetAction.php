<?php

/**
 * ForcePasswordResetAction incident response action.
 *
 * @package    ArtisanPack_UI
 * @subpackage SecurityAnalytics
 *
 * @author     Jacob Martella <support@artisanpackui.dev>
 *
 * @since      1.0.0
 */

declare( strict_types=1 );

namespace ArtisanPackUI\SecurityAnalytics\Analytics\IncidentResponse\Actions;

use ArtisanPackUI\SecurityAnalytics\Models\Anomaly;
use ArtisanPackUI\SecurityAnalytics\Models\SecurityIncident;
use Exception;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Password;

class ForcePasswordResetAction extends AbstractAction
{
    /**
     * {@inheritdoc}
     */
    public function getName(): string
    {
        return 'force_password_reset';
    }

    /**
     * {@inheritdoc}
     */
    public function execute( Anomaly $anomaly, ?SecurityIncident $incident = null, array $config = [] ): array
    {
        $userId = $config['user_id'] ?? $anomaly->user_id;

        if ( ! $userId ) {
            return $this->failure( 'No user ID found' );
        }

        $reason    = $config['reason'] ?? $anomaly->description;
        $sendEmail = $config['send_email'] ?? true;

        // Mark user as requiring password reset
        $this->markUserForPasswordReset( $userId, $reason );

        // Optionally send password reset email
        if ( $sendEmail ) {
            $this->sendPasswordResetEmail( $userId );
        }

        // Add to incident if available
        if ( $incident ) {
            $incident->addAffectedUser( $userId );
            $this->logToIncident( $incident, [
                'user_id'    => $userId,
                'reason'     => $reason,
                'email_sent' => $sendEmail,
            ] );
        }

        return $this->success( "Password reset required for user {$userId}", [
            'user_id'    => $userId,
            'email_sent' => $sendEmail,
        ] );
    }

    /**
     * {@inheritdoc}
     */
    public function validate( array $config = [] ): array
    {
        return [];
    }

    /**
     * Check if user requires password reset.
     */
    public static function isRequired( int $userId ): bool
    {
        return Cache::has( "password_reset_required:{$userId}" );
    }

    /**
     * Clear password reset requirement.
     */
    public static function clearRequirement( int $userId ): void
    {
        Cache::forget( "password_reset_required:{$userId}" );

        $userModel = config( 'auth.providers.users.model', 'App\\Models\\User' );

        if ( class_exists( $userModel ) ) {
            try {
                $table = (new $userModel)->getTable();
                DB::table( $table )->where( 'id', $userId )->update( [
                    'password_change_required' => false,
                    'password_change_reason'   => null,
                ] );
            } catch ( Exception $e ) {
                // Ignore
            }
        }
    }

    /**
     * Mark user as requiring password reset.
     */
    protected function markUserForPasswordReset( int $userId, string $reason ): void
    {
        // Store in cache
        Cache::put( "password_reset_required:{$userId}", [
            'reason'      => $reason,
            'required_at' => now()->toIso8601String(),
        ], now()->addDays( 7 ) );

        // Update database if column exists
        $userModel = config( 'auth.providers.users.model', 'App\\Models\\User' );

        if ( ! class_exists( $userModel ) ) {
            return;
        }

        try {
            $table = (new $userModel)->getTable();

            if ( DB::getSchemaBuilder()->hasColumn( $table, 'password_change_required' ) ) {
                DB::table( $table )->where( 'id', $userId )->update( [
                    'password_change_required' => true,
                    'password_change_reason'   => $reason,
                ] );
            }
        } catch ( Exception $e ) {
            // Rely on cache
        }
    }

    /**
     * Send password reset email.
     */
    protected function sendPasswordResetEmail( int $userId ): bool
    {
        $userModel = config( 'auth.providers.users.model', 'App\\Models\\User' );

        if ( ! class_exists( $userModel ) ) {
            return false;
        }

        try {
            $user = $userModel::find( $userId );

            if ( ! $user || ! $user->email ) {
                return false;
            }

            Password::sendResetLink( ['email' => $user->email] );

            return true;
        } catch ( Exception $e ) {
            return false;
        }
    }
}
