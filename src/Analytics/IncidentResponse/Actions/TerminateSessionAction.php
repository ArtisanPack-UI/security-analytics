<?php

declare( strict_types=1 );

namespace ArtisanPackUI\SecurityAnalytics\Analytics\IncidentResponse\Actions;

use ArtisanPackUI\SecurityAnalytics\Models\Anomaly;
use ArtisanPackUI\SecurityAnalytics\Models\SecurityIncident;
use Exception;
use Illuminate\Support\Facades\DB;

class TerminateSessionAction extends AbstractAction
{
    /**
     * {@inheritdoc}
     */
    public function getName(): string
    {
        return 'terminate_session';
    }

    /**
     * {@inheritdoc}
     */
    public function execute( Anomaly $anomaly, ?SecurityIncident $incident = null, array $config = [] ): array
    {
        $sessionId    = $config['session_id'] ?? null;
        $userId       = $config['user_id'] ?? $anomaly->user_id;
        $ip           = $config['ip'] ?? $this->getIpFromAnomaly( $anomaly );
        $terminateAll = $config['terminate_all'] ?? false;

        $terminated = 0;

        if ( $sessionId ) {
            // Terminate specific session
            $terminated = $this->terminateSession( $sessionId );
        } elseif ( $userId && $terminateAll ) {
            // Terminate all sessions for user
            $terminated = $this->terminateUserSessions( $userId );
        } elseif ( $ip ) {
            // Terminate sessions from specific IP
            $terminated = $this->terminateIpSessions( $ip );
        } else {
            return $this->failure( 'No session identifier provided' );
        }

        // Add to incident if available
        if ( $incident ) {
            if ( $userId ) {
                $incident->addAffectedUser( $userId );
            }
            if ( $ip ) {
                $incident->addAffectedIp( $ip );
            }
            $this->logToIncident( $incident, [
                'session_id'          => $sessionId,
                'user_id'             => $userId,
                'ip'                  => $ip,
                'sessions_terminated' => $terminated,
            ] );
        }

        return $this->success( "Terminated {$terminated} session(s)", [
            'sessions_terminated' => $terminated,
            'session_id'          => $sessionId,
            'user_id'             => $userId,
            'ip'                  => $ip,
        ] );
    }

    /**
     * {@inheritdoc}
     */
    public function validate( array $config = [] ): array
    {
        $errors = [];

        if ( isset( $config['ip'] ) && ! filter_var( $config['ip'], FILTER_VALIDATE_IP ) ) {
            $errors[] = 'Invalid IP address format';
        }

        return $errors;
    }

    /**
     * Terminate sessions except current.
     */
    public static function terminateOtherSessions( int $userId, string $currentSessionId ): int
    {
        try {
            return DB::table( 'sessions' )
                ->where( 'user_id', $userId )
                ->where( 'id', '!=', $currentSessionId )
                ->delete();
        } catch ( Exception $e ) {
            return 0;
        }
    }

    /**
     * Terminate a specific session.
     */
    protected function terminateSession( string $sessionId ): int
    {
        try {
            $deleted = DB::table( 'sessions' )
                ->where( 'id', $sessionId )
                ->delete();

            return $deleted;
        } catch ( Exception $e ) {
            return 0;
        }
    }

    /**
     * Terminate all sessions for a user.
     */
    protected function terminateUserSessions( mixed $userId ): int
    {
        // Validate userId is a valid numeric value
        if ( null === $userId || ! is_numeric( $userId ) ) {
            return 0;
        }

        $validatedUserId = (int) $userId;
        if ( $validatedUserId < 1 ) {
            return 0;
        }

        try {
            $deleted = DB::table( 'sessions' )
                ->where( 'user_id', $validatedUserId )
                ->delete();

            return $deleted;
        } catch ( Exception $e ) {
            return 0;
        }
    }

    /**
     * Terminate all sessions from an IP.
     */
    protected function terminateIpSessions( string $ip ): int
    {
        try {
            $deleted = DB::table( 'sessions' )
                ->where( 'ip_address', $ip )
                ->delete();

            return $deleted;
        } catch ( Exception $e ) {
            return 0;
        }
    }
}
