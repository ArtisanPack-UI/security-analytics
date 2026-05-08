<?php

declare( strict_types=1 );

namespace ArtisanPackUI\SecurityAnalytics\Analytics\IncidentResponse\Actions;

use ArtisanPackUI\SecurityAnalytics\Models\Anomaly;
use ArtisanPackUI\SecurityAnalytics\Models\SecurityIncident;
use Exception;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\DB;

class LockAccountAction extends AbstractAction
{
    /**
     * {@inheritdoc}
     */
    public function getName(): string
    {
        return 'lock_account';
    }

    /**
     * {@inheritdoc}
     */
    public function execute( Anomaly $anomaly, ?SecurityIncident $incident = null, array $config = [] ): array
    {
        $userId = $config['user_id'] ?? $anomaly->user_id;

        if ( ! $userId ) {
            return $this->failure( 'No user ID found to lock' );
        }

        $duration = $config['duration_hours'] ?? 24;
        $reason   = $config['reason'] ?? $anomaly->description;

        // Lock the account in cache
        $cacheKey = "locked_account:{$userId}";
        Cache::put( $cacheKey, [
            'reason'      => $reason,
            'anomaly_id'  => $anomaly->id,
            'incident_id' => $incident?->id,
            'locked_at'   => now()->toIso8601String(),
            'expires_at'  => now()->addHours( $duration )->toIso8601String(),
        ], now()->addHours( $duration ) );

        // Update user record if column exists
        $this->updateUserLockStatus( $userId, true, $reason );

        // Add to incident if available
        if ( $incident ) {
            $incident->addAffectedUser( $userId );
            $this->logToIncident( $incident, [
                'user_id'        => $userId,
                'duration_hours' => $duration,
                'reason'         => $reason,
            ] );
        }

        return $this->success( "Account {$userId} locked for {$duration} hours", [
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

        if ( isset( $config['duration_hours'] ) && ( ! is_numeric( $config['duration_hours'] ) || $config['duration_hours'] < 1 ) ) {
            $errors[] = 'Duration must be at least 1 hour';
        }

        return $errors;
    }

    /**
     * {@inheritdoc}
     */
    public function requiresApproval(): bool
    {
        return true;
    }

    /**
     * Check if an account is currently locked.
     */
    public static function isLocked( int $userId ): bool
    {
        return Cache::has( "locked_account:{$userId}" );
    }

    /**
     * Get lock info for an account.
     *
     * @return array<string, mixed>|null
     */
    public static function getLockInfo( int $userId ): ?array
    {
        return Cache::get( "locked_account:{$userId}" );
    }

    /**
     * Unlock an account.
     */
    public static function unlock( int $userId ): bool
    {
        // Clear cache
        Cache::forget( "locked_account:{$userId}" );

        // Update database
        $userModel = config( 'auth.providers.users.model', 'App\\Models\\User' );

        if ( class_exists( $userModel ) ) {
            try {
                $table = (new $userModel)->getTable();
                DB::table( $table )->where( 'id', $userId )->update( [
                    'locked_at'   => null,
                    'lock_reason' => null,
                ] );
            } catch ( Exception $e ) {
                // Ignore
            }
        }

        return true;
    }

    /**
     * Update user lock status in database.
     */
    protected function updateUserLockStatus( int $userId, bool $locked, string $reason ): void
    {
        $userModel = config( 'auth.providers.users.model', 'App\\Models\\User' );

        if ( ! class_exists( $userModel ) ) {
            return;
        }

        try {
            $table = (new $userModel)->getTable();

            // Check if locked_at column exists
            if ( DB::getSchemaBuilder()->hasColumn( $table, 'locked_at' ) ) {
                DB::table( $table )->where( 'id', $userId )->update( [
                    'locked_at'   => $locked ? now() : null,
                    'lock_reason' => $locked ? $reason : null,
                ]);
            }
        } catch ( Exception $e) {
            // Column doesn't exist or other DB error - rely on cache
        }
    }
}
