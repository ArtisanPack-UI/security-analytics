<?php

declare( strict_types=1 );

namespace ArtisanPackUI\SecurityAnalytics\Analytics\IncidentResponse\Actions;

use ArtisanPackUI\SecurityAnalytics\Models\Anomaly;
use ArtisanPackUI\SecurityAnalytics\Models\SecurityIncident;
use Exception;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\DB;

class BlockUserAction extends AbstractAction
{
    /**
     * {@inheritdoc}
     */
    public function getName(): string
    {
        return 'block_user';
    }

    /**
     * {@inheritdoc}
     */
    public function requiresApproval(): bool
    {
        return true; // Blocking users should require approval
    }

    /**
     * {@inheritdoc}
     */
    public function execute( Anomaly $anomaly, ?SecurityIncident $incident = null, array $config = [] ): array
    {
        $userId = $config['user_id'] ?? $this->getUserIdFromAnomaly( $anomaly );

        if ( ! $userId ) {
            return $this->failure( 'No user ID found to block' );
        }

        $duration = $config['duration_hours'] ?? 24;
        $reason   = $config['reason'] ?? $anomaly->description;

        // Block user in cache
        $cacheKey = "blocked_user:{$userId}";
        Cache::put( $cacheKey, [
            'reason'      => $reason,
            'anomaly_id'  => $anomaly->id,
            'incident_id' => $incident?->id,
            'blocked_at'  => now()->toIso8601String(),
            'expires_at'  => now()->addHours( $duration )->toIso8601String(),
        ], now()->addHours( $duration ) );

        // Optionally update user record if a flag column exists
        $this->updateUserRecord( $userId, true );

        // Add to incident if available
        if ( $incident ) {
            $incident->addAffectedUser( $userId );
            $this->logToIncident( $incident, [
                'user_id'        => $userId,
                'duration_hours' => $duration,
                'reason'         => $reason,
            ] );
        }

        return $this->success( "User {$userId} blocked for {$duration} hours", [
            'user_id'        => $userId,
            'duration_hours' => $duration,
            'expires_at'     => now()->addHours( $duration )->toIso8601String(),
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

        if ( isset( $config['duration_hours'] ) && ( ! is_numeric( $config['duration_hours'] ) || $config['duration_hours'] < 1 ) ) {
            $errors[] = 'Duration must be at least 1 hour';
        }

        return $errors;
    }

    /**
     * Check if a user is currently blocked.
     */
    public static function isBlocked( int $userId ): bool
    {
        return Cache::has( "blocked_user:{$userId}" );
    }

    /**
     * Get block info for a user.
     *
     * @return array<string, mixed>|null
     */
    public static function getBlockInfo( int $userId ): ?array
    {
        return Cache::get( "blocked_user:{$userId}" );
    }

    /**
     * Unblock a user.
     */
    public static function unblock( int $userId ): bool
    {
        // Update user record if column exists
        (new self)->updateUserRecord( $userId, false );

        return Cache::forget( "blocked_user:{$userId}" );
    }

    /**
     * Update user record with blocked status.
     */
    protected function updateUserRecord( int $userId, bool $blocked ): void
    {
        $userModel = config( 'auth.providers.users.model', 'App\\Models\\User' );

        try {
            $tableName = (new $userModel)->getTable();

            // Only update if is_blocked column exists
            $hasColumn = DB::getSchemaBuilder()->hasColumn( $tableName, 'is_blocked' );

            if ( $hasColumn ) {
                DB::table( $tableName )->where( 'id', $userId )->update( ['is_blocked' => $blocked]);
            }
        } catch ( Exception $e) {
            // Column doesn't exist, rely on cache-based blocking
        }
    }
}
