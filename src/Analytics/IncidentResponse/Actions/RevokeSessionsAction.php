<?php

declare( strict_types=1 );

namespace ArtisanPackUI\SecurityAnalytics\Analytics\IncidentResponse\Actions;

use ArtisanPackUI\SecurityAnalytics\Models\Anomaly;
use ArtisanPackUI\SecurityAnalytics\Models\SecurityIncident;
use Exception;
use Illuminate\Support\Facades\DB;
use Log;

class RevokeSessionsAction extends AbstractAction
{
    /**
     * {@inheritdoc}
     */
    public function getName(): string
    {
        return 'revoke_sessions';
    }

    /**
     * {@inheritdoc}
     */
    public function execute( Anomaly $anomaly, ?SecurityIncident $incident = null, array $config = [] ): array
    {
        $userId = $config['user_id'] ?? $this->getUserIdFromAnomaly( $anomaly );

        if ( ! $userId ) {
            return $this->failure( 'No user ID found for session revocation' );
        }

        $revokedCount = $this->revokeSessions( $userId );

        if ( $incident ) {
            $this->logToIncident( $incident, [
                'user_id'          => $userId,
                'sessions_revoked' => $revokedCount,
            ] );
        }

        return $this->success( "Revoked {$revokedCount} sessions for user {$userId}", [
            'user_id'          => $userId,
            'sessions_revoked' => $revokedCount,
        ] );
    }

    /**
     * {@inheritdoc}
     */
    public function validate( array $config = [] ): array
    {
        $errors = [];

        if ( isset( $config['user_id'] ) && ( ! is_numeric( $config['user_id'] ) || $config['user_id'] < 1 ) ) {
            $errors[] = 'Invalid user ID';
        }

        return $errors;
    }

    /**
     * Revoke all sessions for a user.
     */
    protected function revokeSessions( int $userId ): int
    {
        $driver = config( 'session.driver' );
        $count  = 0;

        if ( 'database' === $driver ) {
            $count = DB::table( config( 'session.table', 'sessions' ) )
                ->where( 'user_id', $userId )
                ->delete();
        } elseif ( 'file' === $driver ) {
            // For file-based sessions, we can't easily revoke specific user sessions
            // without a custom mapping.
            Log::warning( 'Session revocation not supported for file driver', ['user_id' => $userId] );
            $count = 0;
        } elseif ( 'redis' === $driver || 'memcached' === $driver ) {
            // For Redis/Memcached, we would need a custom session store
            // that tracks user -> session mappings
            Log::warning( "Session revocation not fully supported for {$driver} driver", ['user_id' => $userId] );
            $count = 0;
        }

        // Also invalidate any remember tokens
        $this->invalidateRememberToken( $userId );

        return $count;
    }

    /**
     * Invalidate remember token for a user.
     */
    protected function invalidateRememberToken( int $userId ): void
    {
        $userModel = config( 'auth.providers.users.model', 'App\\Models\\User' );

        try {
            $user = $userModel::find( $userId );
            if ( $user && method_exists( $user, 'setRememberToken' ) ) {
                $user->setRememberToken( null );
                $user->save();
            }
        } catch ( Exception $e ) {
            // User model may not exist or have remember token
            Log::debug( 'Failed to invalidate remember token', [
                'user_id' => $userId,
                'error'   => $e->getMessage(),
            ] );
        }
    }
}
