<?php

declare( strict_types=1 );

namespace ArtisanPackUI\SecurityAnalytics\Models;

use Illuminate\Database\Eloquent\Model;

class ResponsePlaybook extends Model
{
    /**
     * The table associated with the model.
     */
    protected $table = 'response_playbooks';

    /**
     * The attributes that are mass assignable.
     *
     * @var array<int, string>
     */
    protected $fillable = [
        'name',
        'description',
        'trigger_conditions',
        'actions',
        'is_active',
        'requires_approval',
        'cooldown_minutes',
    ];

    /**
     * Check if the playbook matches the given anomaly.
     */
    public function matchesAnomaly( Anomaly $anomaly ): bool
    {
        $conditions = $this->trigger_conditions ?? [];

        foreach ( $conditions as $field => $expected ) {
            $actual = $anomaly->getAttribute( $field );

            if ( is_array( $expected ) ) {
                if ( ! in_array( $actual, $expected, true ) ) {
                    return false;
                }
            } elseif ( $actual !== $expected ) {
                return false;
            }
        }

        return true;
    }

    /**
     * Get the list of action names.
     *
     * @return array<int, string>
     */
    public function getActionNames(): array
    {
        $actions = $this->actions ?? [];

        return array_map( function ( $action ) {
            return is_array( $action ) ? ( $action['name'] ?? $action['action'] ?? '' ) : $action;
        }, $actions );
    }

    /**
     * Get action configuration by name.
     *
     * @return array<string, mixed>|null
     */
    public function getActionConfig( string $actionName ): ?array
    {
        $actions = $this->actions ?? [];

        foreach ( $actions as $action ) {
            if ( is_array( $action ) ) {
                $name = $action['name'] ?? $action['action'] ?? '';
                if ( $name === $actionName ) {
                    return $action;
                }
            } elseif ( $action === $actionName ) {
                return ['action' => $actionName];
            }
        }

        return null;
    }

    /**
     * Check if the playbook is on cooldown.
     */
    public function isOnCooldown( ?string $contextKey = null ): bool
    {
        if ( $this->cooldown_minutes <= 0 ) {
            return false;
        }

        $cacheKey = 'playbook_cooldown_' . $this->id;
        if ( $contextKey ) {
            $cacheKey .= '_' . $contextKey;
        }

        return cache()->has( $cacheKey );
    }

    /**
     * Start the cooldown period.
     */
    public function startCooldown( ?string $contextKey = null ): void
    {
        if ( $this->cooldown_minutes <= 0 ) {
            return;
        }

        $cacheKey = 'playbook_cooldown_' . $this->id;
        if ( $contextKey ) {
            $cacheKey .= '_' . $contextKey;
        }

        cache()->put( $cacheKey, true, now()->addMinutes( $this->cooldown_minutes ) );
    }

    /**
     * Scope a query to active playbooks.
     *
     * @param  \Illuminate\Database\Eloquent\Builder<ResponsePlaybook>  $query
     *
     * @return \Illuminate\Database\Eloquent\Builder<ResponsePlaybook>
     */
    public function scopeActive( $query )
    {
        return $query->where( 'is_active', true );
    }

    /**
     * Scope a query to playbooks that don't require approval.
     *
     * @param  \Illuminate\Database\Eloquent\Builder<ResponsePlaybook>  $query
     *
     * @return \Illuminate\Database\Eloquent\Builder<ResponsePlaybook>
     */
    public function scopeAutomatic( $query )
    {
        return $query->where( 'requires_approval', false );
    }

    /**
     * Scope a query to playbooks that require approval.
     *
     * @param  \Illuminate\Database\Eloquent\Builder<ResponsePlaybook>  $query
     *
     * @return \Illuminate\Database\Eloquent\Builder<ResponsePlaybook>
     */
    public function scopeRequiresApproval( $query )
    {
        return $query->where( 'requires_approval', true );
    }

    /**
     * Find matching playbooks for an anomaly.
     *
     * @return \Illuminate\Database\Eloquent\Collection<int, ResponsePlaybook>
     */
    public static function findMatchingPlaybooks( Anomaly $anomaly ): \Illuminate\Database\Eloquent\Collection
    {
        return static::active()
            ->get()
            ->filter( fn ( self $playbook ) => $playbook->matchesAnomaly( $anomaly ) );
    }

    /**
     * Get the attributes that should be cast.
     *
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return [
            'trigger_conditions' => 'array',
            'actions'            => 'array',
            'is_active'          => 'boolean',
            'requires_approval'  => 'boolean',
            'cooldown_minutes'   => 'integer',
        ];
    }
}
