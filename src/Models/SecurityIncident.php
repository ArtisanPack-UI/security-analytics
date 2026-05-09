<?php

declare( strict_types=1 );

namespace ArtisanPackUI\SecurityAnalytics\Models;

use ArtisanPackUI\SecurityAnalytics\Database\Factories\SecurityIncidentFactory;
use DB;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Database\Eloquent\Relations\HasMany;

class SecurityIncident extends Model
{
    /** @use HasFactory<SecurityIncidentFactory> */
    use HasFactory;

    /**
     * Incident statuses.
     */
    public const STATUS_OPEN = 'open';

    public const STATUS_INVESTIGATING = 'investigating';

    public const STATUS_CONTAINED = 'contained';

    public const STATUS_RESOLVED = 'resolved';

    public const STATUS_CLOSED = 'closed';

    /**
     * Severity levels.
     */
    public const SEVERITY_INFO = 'info';

    public const SEVERITY_LOW = 'low';

    public const SEVERITY_MEDIUM = 'medium';

    public const SEVERITY_HIGH = 'high';

    public const SEVERITY_CRITICAL = 'critical';

    /**
     * The table associated with the model.
     */
    protected $table = 'security_incidents';

    /**
     * The attributes that are mass assignable.
     *
     * @var array<int, string>
     */
    protected $fillable = [
        'incident_number',
        'title',
        'description',
        'severity',
        'status',
        'category',
        'source_anomaly_id',
        'affected_users',
        'affected_ips',
        'actions_taken',
        'assigned_to',
        'opened_at',
        'contained_at',
        'resolved_at',
        'closed_at',
        'root_cause',
        'lessons_learned',
    ];

    /**
     * Generate a unique incident number.
     */
    public static function generateIncidentNumber(): string
    {
        $year = date( 'Y' );
        
        return DB::transaction( function () use ( $year ) {
            $lastIncident = static::whereYear( 'created_at', $year )
                ->orderByDesc( 'id' )
                ->lockForUpdate()
                ->first();

            $sequence = 1;
            if ( $lastIncident && preg_match( '/INC-\d{4}-(\d+)/', $lastIncident->incident_number, $matches ) ) {
                $sequence = (int) $matches[1] + 1;
            }

            return sprintf( 'INC-%s-%06d', $year, $sequence );
        } );
    }

    /**
     * Get the source anomaly.
     *
     * @return BelongsTo<Anomaly, SecurityIncident>
     */
    public function sourceAnomaly(): BelongsTo
    {
        return $this->belongsTo( Anomaly::class, 'source_anomaly_id' );
    }

    /**
     * Get the assigned user.
     *
     * @return BelongsTo<\Illuminate\Foundation\Auth\User, SecurityIncident>
     */
    public function assignee(): BelongsTo
    {
        $userModel = config( 'auth.providers.users.model', 'App\\Models\\User' );

        return $this->belongsTo( $userModel, 'assigned_to' );
    }

    /**
     * Get related alerts.
     *
     * @return HasMany<AlertHistory>
     */
    public function alerts(): HasMany
    {
        return $this->hasMany( AlertHistory::class, 'incident_id' );
    }

    /**
     * Check if incident is open.
     */
    public function isOpen(): bool
    {
        return self::STATUS_OPEN === $this->status;
    }

    /**
     * Check if incident is closed.
     */
    public function isClosed(): bool
    {
        return self::STATUS_CLOSED === $this->status;
    }

    /**
     * Check if incident is active (not closed).
     */
    public function isActive(): bool
    {
        return ! $this->isClosed();
    }

    /**
     * Transition to investigating status.
     */
    public function investigate(): void
    {
        $this->status = self::STATUS_INVESTIGATING;
        $this->save();
    }

    /**
     * Transition to contained status.
     */
    public function contain(): void
    {
        $this->status       = self::STATUS_CONTAINED;
        $this->contained_at = now();
        $this->save();
    }

    /**
     * Transition to resolved status.
     */
    public function resolve( ?string $rootCause = null ): void
    {
        $this->status      = self::STATUS_RESOLVED;
        $this->resolved_at = now();
        if ( null !== $rootCause ) {
            $this->root_cause = $rootCause;
        }
        $this->save();
    }

    /**
     * Close the incident.
     */
    public function close( ?string $lessonsLearned = null ): void
    {
        $this->status    = self::STATUS_CLOSED;
        $this->closed_at = now();
        if ( null !== $lessonsLearned ) {
            $this->lessons_learned = $lessonsLearned;
        }
        $this->save();
    }

    /**
     * Assign the incident to a user.
     */
    public function assignTo( int $userId ): void
    {
        $this->assigned_to = $userId;
        $this->save();
    }

    /**
     * Add an action to the incident.
     */
    public function addAction( string $action, array $details = [] ): void
    {
        $actions   = $this->actions_taken ?? [];
        $actions[] = [
            'action'    => $action,
            'details'   => $details,
            'timestamp' => now()->toIso8601String(),
        ];
        $this->actions_taken = $actions;
        $this->save();
    }

    /**
     * Add an affected user.
     */
    public function addAffectedUser( int $userId ): void
    {
        $users = $this->affected_users ?? [];
        if ( ! in_array( $userId, $users, true ) ) {
            $users[]              = $userId;
            $this->affected_users = $users;
            $this->save();
        }
    }

    /**
     * Add an affected IP.
     */
    public function addAffectedIp( string $ip ): void
    {
        $ips = $this->affected_ips ?? [];
        if ( ! in_array( $ip, $ips, true ) ) {
            $ips[]              = $ip;
            $this->affected_ips = $ips;
            $this->save();
        }
    }

    /**
     * Get the time to contain in minutes.
     */
    public function getTimeToContain(): ?int
    {
        if ( null === $this->contained_at || null === $this->opened_at ) {
            return null;
        }

        return (int) $this->opened_at->diffInMinutes( $this->contained_at );
    }

    /**
     * Get the time to resolve in minutes.
     */
    public function getTimeToResolve(): ?int
    {
        if ( null === $this->resolved_at || null === $this->opened_at ) {
            return null;
        }

        return (int) $this->opened_at->diffInMinutes( $this->resolved_at );
    }

    /**
     * Scope a query to active incidents.
     *
     * @param  \Illuminate\Database\Eloquent\Builder<SecurityIncident>  $query
     *
     * @return \Illuminate\Database\Eloquent\Builder<SecurityIncident>
     */
    public function scopeActive( $query )
    {
        return $query->where( 'status', '!=', self::STATUS_CLOSED );
    }

    /**
     * Scope a query to open incidents.
     *
     * @param  \Illuminate\Database\Eloquent\Builder<SecurityIncident>  $query
     *
     * @return \Illuminate\Database\Eloquent\Builder<SecurityIncident>
     */
    public function scopeOpen( $query )
    {
        return $query->where( 'status', self::STATUS_OPEN );
    }

    /**
     * Scope a query to a specific status.
     *
     * @param  \Illuminate\Database\Eloquent\Builder<SecurityIncident>  $query
     *
     * @return \Illuminate\Database\Eloquent\Builder<SecurityIncident>
     */
    public function scopeStatus( $query, string $status )
    {
        return $query->where( 'status', $status );
    }

    /**
     * Scope a query to a specific severity.
     *
     * @param  \Illuminate\Database\Eloquent\Builder<SecurityIncident>  $query
     *
     * @return \Illuminate\Database\Eloquent\Builder<SecurityIncident>
     */
    public function scopeSeverity( $query, string $severity )
    {
        return $query->where( 'severity', $severity );
    }

    /**
     * Scope a query to critical incidents.
     *
     * @param  \Illuminate\Database\Eloquent\Builder<SecurityIncident>  $query
     *
     * @return \Illuminate\Database\Eloquent\Builder<SecurityIncident>
     */
    public function scopeCritical( $query )
    {
        return $query->where( 'severity', self::SEVERITY_CRITICAL );
    }

    /**
     * Scope a query to assigned incidents.
     *
     * @param  \Illuminate\Database\Eloquent\Builder<SecurityIncident>  $query
     *
     * @return \Illuminate\Database\Eloquent\Builder<SecurityIncident>
     */
    public function scopeAssignedTo( $query, int $userId )
    {
        return $query->where( 'assigned_to', $userId );
    }

    /**
     * Scope a query to unassigned incidents.
     *
     * @param  \Illuminate\Database\Eloquent\Builder<SecurityIncident>  $query
     *
     * @return \Illuminate\Database\Eloquent\Builder<SecurityIncident>
     */
    public function scopeUnassigned( $query )
    {
        return $query->whereNull( 'assigned_to' );
    }

    /**
     * Create a new factory instance for the model.
     */
    protected static function newFactory(): SecurityIncidentFactory
    {
        return SecurityIncidentFactory::new();
    }

    /**
     * Get the attributes that should be cast.
     *
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return [
            'affected_users' => 'array',
            'affected_ips'   => 'array',
            'actions_taken'  => 'array',
            'opened_at'      => 'datetime',
            'contained_at'   => 'datetime',
            'resolved_at'    => 'datetime',
            'closed_at'      => 'datetime',
        ];
    }

    /**
     * Boot the model.
     */
    protected static function boot(): void
    {
        parent::boot();

        static::creating( function ( self $incident ): void {
            if ( empty( $incident->incident_number ) ) {
                $incident->incident_number = self::generateIncidentNumber();
            }
            if ( null === $incident->opened_at ) {
                $incident->opened_at = now();
            }
        });
    }
}
