<?php

declare( strict_types=1 );

namespace ArtisanPackUI\SecurityAnalytics\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

class SuspiciousActivity extends Model
{
    /**
     * Activity types.
     */
    public const TYPE_BRUTE_FORCE = 'brute_force';

    public const TYPE_IMPOSSIBLE_TRAVEL = 'impossible_travel';

    public const TYPE_ANOMALOUS_LOGIN = 'anomalous_login';

    public const TYPE_PROXY_DETECTED = 'proxy_detected';

    public const TYPE_TOR_DETECTED = 'tor_detected';

    public const TYPE_DATACENTER_IP = 'datacenter_ip';

    public const TYPE_MULTIPLE_FAILURES = 'multiple_failures';

    public const TYPE_DEVICE_CHANGE = 'device_change';

    public const TYPE_UNUSUAL_TIME = 'unusual_time';

    public const TYPE_SESSION_HIJACKING = 'session_hijacking';

    public const TYPE_CREDENTIAL_STUFFING = 'credential_stuffing';

    /**
     * Severity levels.
     */
    public const SEVERITY_LOW = 'low';

    public const SEVERITY_MEDIUM = 'medium';

    public const SEVERITY_HIGH = 'high';

    public const SEVERITY_CRITICAL = 'critical';

    /**
     * Actions taken.
     */
    public const ACTION_NONE = 'none';

    public const ACTION_CAPTCHA = 'captcha';

    public const ACTION_STEP_UP = 'step_up';

    public const ACTION_BLOCK = 'block';

    public const ACTION_LOCKOUT = 'lockout';

    public const ACTION_NOTIFY = 'notify';

    /**
     * Indicates if the model should be timestamped.
     */
    public $timestamps = false;

    /**
     * The table associated with the model.
     */
    protected $table = 'suspicious_activities';

    /**
     * The attributes that are mass assignable.
     *
     * @var array<int, string>
     */
    protected $fillable = [
        'user_id',
        'session_id',
        'type',
        'severity',
        'risk_score',
        'ip_address',
        'location',
        'device_fingerprint',
        'details',
        'action_taken',
        'resolved',
        'resolved_at',
        'resolved_by',
        'created_at',
    ];

    /**
     * Get the user associated with this activity.
     *
     * @return BelongsTo<\Illuminate\Foundation\Auth\User, SuspiciousActivity>
     */
    public function user(): BelongsTo
    {
        $userModel = config( 'auth.providers.users.model', 'App\\Models\\User' );

        return $this->belongsTo( $userModel );
    }

    /**
     * Get the user who resolved this activity.
     *
     * @return BelongsTo<\Illuminate\Foundation\Auth\User, SuspiciousActivity>
     */
    public function resolver(): BelongsTo
    {
        $userModel = config( 'auth.providers.users.model', 'App\\Models\\User' );

        return $this->belongsTo( $userModel, 'resolved_by' );
    }

    /**
     * Mark the activity as resolved.
     */
    public function resolve( ?int $resolvedBy = null ): void
    {
        $this->resolved    = true;
        $this->resolved_at = now();
        $this->resolved_by = $resolvedBy;
        $this->save();
    }

    /**
     * Check if this activity is critical severity.
     */
    public function isCritical(): bool
    {
        return self::SEVERITY_CRITICAL === $this->severity;
    }

    /**
     * Check if this activity is high severity.
     */
    public function isHigh(): bool
    {
        return self::SEVERITY_HIGH === $this->severity;
    }

    /**
     * Check if this activity is medium severity.
     */
    public function isMedium(): bool
    {
        return self::SEVERITY_MEDIUM === $this->severity;
    }

    /**
     * Check if this activity is low severity.
     */
    public function isLow(): bool
    {
        return self::SEVERITY_LOW === $this->severity;
    }

    /**
     * Get a human-readable type description.
     */
    public function getTypeDescription(): string
    {
        return match ( $this->type ) {
            self::TYPE_BRUTE_FORCE         => 'Brute Force Attack',
            self::TYPE_IMPOSSIBLE_TRAVEL   => 'Impossible Travel',
            self::TYPE_ANOMALOUS_LOGIN     => 'Anomalous Login',
            self::TYPE_PROXY_DETECTED      => 'Proxy/VPN Detected',
            self::TYPE_TOR_DETECTED        => 'Tor Exit Node Detected',
            self::TYPE_DATACENTER_IP       => 'Datacenter IP Detected',
            self::TYPE_MULTIPLE_FAILURES   => 'Multiple Failed Attempts',
            self::TYPE_DEVICE_CHANGE       => 'Unexpected Device Change',
            self::TYPE_UNUSUAL_TIME        => 'Unusual Login Time',
            self::TYPE_SESSION_HIJACKING   => 'Session Hijacking Attempt',
            self::TYPE_CREDENTIAL_STUFFING => 'Credential Stuffing',
            default                        => ucwords( str_replace( '_', ' ', $this->type ) ),
        };
    }

    /**
     * Get the severity badge color.
     */
    public function getSeverityColor(): string
    {
        return match ( $this->severity ) {
            self::SEVERITY_LOW      => 'gray',
            self::SEVERITY_MEDIUM   => 'yellow',
            self::SEVERITY_HIGH     => 'orange',
            self::SEVERITY_CRITICAL => 'red',
            default                 => 'gray',
        };
    }

    /**
     * Get a detail value.
     */
    public function getDetail( string $key ): mixed
    {
        return data_get( $this->details, $key );
    }

    /**
     * Scope a query to only include unresolved activities.
     *
     * @param  \Illuminate\Database\Eloquent\Builder<SuspiciousActivity>  $query
     *
     * @return \Illuminate\Database\Eloquent\Builder<SuspiciousActivity>
     */
    public function scopeUnresolved( $query )
    {
        return $query->where( 'resolved', false );
    }

    /**
     * Scope a query to only include activities of a specific type.
     *
     * @param  \Illuminate\Database\Eloquent\Builder<SuspiciousActivity>  $query
     *
     * @return \Illuminate\Database\Eloquent\Builder<SuspiciousActivity>
     */
    public function scopeOfType( $query, string $type )
    {
        return $query->where( 'type', $type );
    }

    /**
     * Scope a query to only include activities of a specific severity or higher.
     *
     * @param  \Illuminate\Database\Eloquent\Builder<SuspiciousActivity>  $query
     *
     * @return \Illuminate\Database\Eloquent\Builder<SuspiciousActivity>
     */
    public function scopeMinimumSeverity( $query, string $severity )
    {
        $severities = [
            self::SEVERITY_LOW      => 1,
            self::SEVERITY_MEDIUM   => 2,
            self::SEVERITY_HIGH     => 3,
            self::SEVERITY_CRITICAL => 4,
        ];

        $minLevel = $severities[ $severity ] ?? 1;

        $allowedSeverities = array_keys( array_filter( $severities, fn ( $level ) => $level >= $minLevel ) );

        return $query->whereIn( 'severity', $allowedSeverities );
    }

    /**
     * Scope a query to only include activities from a specific IP.
     *
     * @param  \Illuminate\Database\Eloquent\Builder<SuspiciousActivity>  $query
     *
     * @return \Illuminate\Database\Eloquent\Builder<SuspiciousActivity>
     */
    public function scopeFromIp( $query, string $ipAddress )
    {
        return $query->where( 'ip_address', $ipAddress );
    }

    /**
     * Scope a query to only include recent activities.
     *
     * @param  \Illuminate\Database\Eloquent\Builder<SuspiciousActivity>  $query
     *
     * @return \Illuminate\Database\Eloquent\Builder<SuspiciousActivity>
     */
    public function scopeRecent( $query, int $hours = 24 )
    {
        return $query->where( 'created_at', '>=', now()->subHours( $hours ) );
    }

    /**
     * Get the attributes that should be cast.
     *
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return [
            'risk_score'  => 'float',
            'location'    => 'array',
            'details'     => 'array',
            'resolved'    => 'boolean',
            'resolved_at' => 'datetime',
            'created_at'  => 'datetime',
        ];
    }

    /**
     * Boot the model.
     */
    protected static function boot(): void
    {
        parent::boot();

        static::creating( function ( $model ): void {
            if ( ! $model->created_at ) {
                $model->created_at = now();
            }
            if ( null === $model->details) {
                $model->details = [];
            }
        });
    }
}
