<?php

declare( strict_types=1 );

namespace ArtisanPackUI\SecurityAnalytics\Analytics\IncidentResponse\Actions;

use ArtisanPackUI\SecurityAnalytics\Models\Anomaly;
use ArtisanPackUI\SecurityAnalytics\Models\SecurityIncident;
use Exception;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\DB;

class RequireTwoFactorAction extends AbstractAction
{
    /**
     * {@inheritdoc}
     */
    public function getName(): string
    {
        return 'require_2fa';
    }

    /**
     * {@inheritdoc}
     */
    public function execute( Anomaly $anomaly, ?SecurityIncident $incident = null, array $config = [] ): array
    {
        $userId = $config['user_id'] ?? $this->getUserIdFromAnomaly( $anomaly );

        if ( ! $userId ) {
            return $this->failure( 'No user ID found for 2FA requirement' );
        }

        $reason    = $config['reason'] ?? 'Security anomaly detected';
        $permanent = $config['permanent'] ?? false;

        // Set flag to require 2FA
        $cacheKey = "require_2fa:{$userId}";

        if ( $permanent ) {
            // Try to update database flag if available
            $this->setDatabaseFlag( $userId, true );
        } else {
            // Temporary requirement via cache
            $duration = $config['duration_hours'] ?? 72;
            Cache::put( $cacheKey, [
                'reason'      => $reason,
                'anomaly_id'  => $anomaly->id,
                'required_at' => now()->toIso8601String(),
            ], now()->addHours( $duration ) );
        }

        if ( $incident ) {
            $this->logToIncident( $incident, [
                'user_id'   => $userId,
                'permanent' => $permanent,
                'reason'    => $reason,
            ] );
        }

        return $this->success( "2FA requirement set for user {$userId}", [
            'user_id'   => $userId,
            'permanent' => $permanent,
            'reason'    => $reason,
        ] );
    }

    /**
     * Check if a user is required to set up 2FA.
     */
    public static function isRequired( int $userId ): bool
    {
        // Check cache first
        if ( Cache::has( "require_2fa:{$userId}" ) ) {
            return true;
        }

        // Check database flag
        $userModel = config( 'auth.providers.users.model', 'App\\Models\\User' );

        try {
            $user = $userModel::find( $userId );

            return (bool) ( $user?->requires_2fa ?? false );
        } catch ( Exception $e ) {
            return false;
        }
    }

    /**
     * Clear the 2FA requirement.
     */
    public static function clear( int $userId ): bool
    {
        Cache::forget( "require_2fa:{$userId}" );

        // Try to clear database flag
        (new self)->setDatabaseFlag( $userId, false );

        return true;
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
     * Set 2FA requirement flag in database.
     */
    protected function setDatabaseFlag( int $userId, bool $required ): void
    {
        $userModel = config( 'auth.providers.users.model', 'App\\Models\\User' );

        try {
            $tableName = (new $userModel)->getTable();
            $hasColumn = DB::getSchemaBuilder()->hasColumn( $tableName, 'requires_2fa' );

            if ( $hasColumn ) {
                DB::table( $tableName )->where( 'id', $userId )->update( ['requires_2fa' => $required] );
            }
        } catch ( Exception $e ) {
            // Column doesn't exist, rely on cache
        }
    }
}
