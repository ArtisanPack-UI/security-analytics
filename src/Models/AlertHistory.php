<?php

declare( strict_types=1 );

namespace ArtisanPackUI\SecurityAnalytics\Models;

use ArtisanPackUI\SecurityAnalytics\Database\Factories\AlertHistoryFactory;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

class AlertHistory extends Model
{
    /** @use HasFactory<AlertHistoryFactory> */
    use HasFactory;

    /**
     * Alert statuses.
     */
    public const STATUS_PENDING = 'pending';

    public const STATUS_SENT = 'sent';

    public const STATUS_FAILED = 'failed';

    public const STATUS_ACKNOWLEDGED = 'acknowledged';

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
    protected $table = 'alert_history';

    /**
     * The attributes that are mass assignable.
     *
     * @var array<int, string>
     */
    protected $fillable = [
        'rule_id',
        'anomaly_id',
        'incident_id',
        'severity',
        'channel',
        'recipient',
        'status',
        'message',
        'sent_at',
        'acknowledged_at',
        'acknowledged_by',
        'error_message',
    ];

    /**
     * Get the alert rule.
     *
     * @return BelongsTo<AlertRule, AlertHistory>
     */
    public function rule(): BelongsTo
    {
        return $this->belongsTo( AlertRule::class, 'rule_id' );
    }

    /**
     * Get the source anomaly.
     *
     * @return BelongsTo<Anomaly, AlertHistory>
     */
    public function anomaly(): BelongsTo
    {
        return $this->belongsTo( Anomaly::class, 'anomaly_id' );
    }

    /**
     * Get the related incident.
     *
     * @return BelongsTo<SecurityIncident, AlertHistory>
     */
    public function incident(): BelongsTo
    {
        return $this->belongsTo( SecurityIncident::class, 'incident_id' );
    }

    /**
     * Get the user who acknowledged this alert.
     *
     * @return BelongsTo<\Illuminate\Foundation\Auth\User, AlertHistory>
     */
    public function acknowledgedByUser(): BelongsTo
    {
        $userModel = config( 'auth.providers.users.model', 'App\\Models\\User' );

        return $this->belongsTo( $userModel, 'acknowledged_by' );
    }

    /**
     * Check if the alert is pending.
     */
    public function isPending(): bool
    {
        return self::STATUS_PENDING === $this->status;
    }

    /**
     * Check if the alert was sent.
     */
    public function isSent(): bool
    {
        return self::STATUS_SENT === $this->status;
    }

    /**
     * Check if the alert failed.
     */
    public function isFailed(): bool
    {
        return self::STATUS_FAILED === $this->status;
    }

    /**
     * Check if the alert was acknowledged.
     */
    public function isAcknowledged(): bool
    {
        return self::STATUS_ACKNOWLEDGED === $this->status;
    }

    /**
     * Mark the alert as sent.
     */
    public function markAsSent(): void
    {
        $this->status  = self::STATUS_SENT;
        $this->sent_at = now();
        $this->save();
    }

    /**
     * Mark the alert as failed.
     */
    public function markAsFailed( string $error ): void
    {
        $this->status        = self::STATUS_FAILED;
        $this->error_message = $error;
        $this->save();
    }

    /**
     * Acknowledge the alert.
     */
    public function acknowledge( ?int $userId = null ): void
    {
        $this->status          = self::STATUS_ACKNOWLEDGED;
        $this->acknowledged_at = now();
        $this->acknowledged_by = $userId;
        $this->save();
    }

    /**
     * Scope a query to a specific status.
     *
     * @param  \Illuminate\Database\Eloquent\Builder<AlertHistory>  $query
     *
     * @return \Illuminate\Database\Eloquent\Builder<AlertHistory>
     */
    public function scopeStatus( $query, string $status )
    {
        return $query->where( 'status', $status );
    }

    /**
     * Scope a query to pending alerts.
     *
     * @param  \Illuminate\Database\Eloquent\Builder<AlertHistory>  $query
     *
     * @return \Illuminate\Database\Eloquent\Builder<AlertHistory>
     */
    public function scopePending( $query )
    {
        return $query->where( 'status', self::STATUS_PENDING );
    }

    /**
     * Scope a query to sent alerts.
     *
     * @param  \Illuminate\Database\Eloquent\Builder<AlertHistory>  $query
     *
     * @return \Illuminate\Database\Eloquent\Builder<AlertHistory>
     */
    public function scopeSent( $query )
    {
        return $query->where( 'status', self::STATUS_SENT );
    }

    /**
     * Scope a query to failed alerts.
     *
     * @param  \Illuminate\Database\Eloquent\Builder<AlertHistory>  $query
     *
     * @return \Illuminate\Database\Eloquent\Builder<AlertHistory>
     */
    public function scopeFailed( $query )
    {
        return $query->where( 'status', self::STATUS_FAILED );
    }

    /**
     * Scope a query to a specific channel.
     *
     * @param  \Illuminate\Database\Eloquent\Builder<AlertHistory>  $query
     *
     * @return \Illuminate\Database\Eloquent\Builder<AlertHistory>
     */
    public function scopeChannel( $query, string $channel )
    {
        return $query->where( 'channel', $channel );
    }

    /**
     * Scope a query to a specific severity.
     *
     * @param  \Illuminate\Database\Eloquent\Builder<AlertHistory>  $query
     *
     * @return \Illuminate\Database\Eloquent\Builder<AlertHistory>
     */
    public function scopeSeverity( $query, string $severity )
    {
        return $query->where( 'severity', $severity );
    }

    /**
     * Scope a query to unacknowledged alerts.
     *
     * @param  \Illuminate\Database\Eloquent\Builder<AlertHistory>  $query
     *
     * @return \Illuminate\Database\Eloquent\Builder<AlertHistory>
     */
    public function scopeUnacknowledged( $query )
    {
        return $query->whereIn( 'status', [self::STATUS_PENDING, self::STATUS_SENT] );
    }

    /**
     * Create a new factory instance for the model.
     */
    protected static function newFactory(): AlertHistoryFactory
    {
        return AlertHistoryFactory::new();
    }

    /**
     * Get the attributes that should be cast.
     *
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return [
            'sent_at'         => 'datetime',
            'acknowledged_at' => 'datetime',
        ];
    }
}
