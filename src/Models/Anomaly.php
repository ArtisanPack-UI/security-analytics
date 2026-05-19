<?php

/**
 * Anomaly Eloquent model.
 *
 * @package    ArtisanPack_UI
 * @subpackage SecurityAnalytics
 *
 * @author     Jacob Martella <support@artisanpackui.dev>
 *
 * @since      1.0.0
 */

declare( strict_types=1 );

namespace ArtisanPackUI\SecurityAnalytics\Models;

use ArtisanPackUI\SecurityAnalytics\Database\Factories\AnomalyFactory;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

class Anomaly extends Model
{
    /** @use HasFactory<AnomalyFactory> */
    use HasFactory;

    /**
     * Anomaly categories.
     */
    public const CATEGORY_STATISTICAL = 'statistical';

    public const CATEGORY_BEHAVIORAL = 'behavioral';

    public const CATEGORY_RULE_BASED = 'rule_based';

    public const CATEGORY_AUTHENTICATION = 'authentication';

    public const CATEGORY_THREAT = 'threat';

    public const CATEGORY_ACCESS = 'access';

    public const CATEGORY_DATA = 'data';

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
    protected $table = 'anomalies';

    /**
     * The attributes that are mass assignable.
     *
     * @var array<int, string>
     */
    protected $fillable = [
        'detector',
        'category',
        'severity',
        'score',
        'description',
        'event_id',
        'user_id',
        'ip_address',
        'metadata',
        'detected_at',
        'resolved_at',
        'resolved_by',
        'resolution_notes',
    ];

    /**
     * Get the user associated with this anomaly.
     *
     * @return BelongsTo<\Illuminate\Foundation\Auth\User, Anomaly>
     */
    public function user(): BelongsTo
    {
        $userModel = config( 'auth.providers.users.model', 'App\\Models\\User' );

        return $this->belongsTo( $userModel );
    }

    /**
     * Get the user who resolved this anomaly.
     *
     * @return BelongsTo<\Illuminate\Foundation\Auth\User, Anomaly>
     */
    public function resolver(): BelongsTo
    {
        $userModel = config( 'auth.providers.users.model', 'App\\Models\\User' );

        return $this->belongsTo( $userModel, 'resolved_by' );
    }

    /**
     * Check if the anomaly is resolved.
     */
    public function isResolved(): bool
    {
        return null !== $this->resolved_at;
    }

    /**
     * Check if the anomaly is critical.
     */
    public function isCritical(): bool
    {
        return self::SEVERITY_CRITICAL === $this->severity;
    }

    /**
     * Check if the anomaly is high severity or above.
     */
    public function isHighSeverity(): bool
    {
        return in_array( $this->severity, [self::SEVERITY_HIGH, self::SEVERITY_CRITICAL], true );
    }

    /**
     * Resolve the anomaly.
     */
    public function resolve( ?int $resolvedBy = null, ?string $notes = null ): void
    {
        $this->resolved_at      = now();
        $this->resolved_by      = $resolvedBy;
        $this->resolution_notes = $notes;
        $this->save();
    }

    /**
     * Get a metadata value.
     */
    public function getMetadata( string $key, mixed $default = null ): mixed
    {
        return data_get( $this->metadata, $key, $default );
    }

    /**
     * Set a metadata value.
     */
    public function setMetadata( string $key, mixed $value ): void
    {
        $metadata = $this->metadata ?? [];
        data_set( $metadata, $key, $value );
        $this->metadata = $metadata;
    }

    /**
     * Scope a query to unresolved anomalies.
     *
     * @param  \Illuminate\Database\Eloquent\Builder<Anomaly>  $query
     *
     * @return \Illuminate\Database\Eloquent\Builder<Anomaly>
     */
    public function scopeUnresolved( $query )
    {
        return $query->whereNull( 'resolved_at' );
    }

    /**
     * Scope a query to resolved anomalies.
     *
     * @param  \Illuminate\Database\Eloquent\Builder<Anomaly>  $query
     *
     * @return \Illuminate\Database\Eloquent\Builder<Anomaly>
     */
    public function scopeResolved( $query )
    {
        return $query->whereNotNull( 'resolved_at' );
    }

    /**
     * Scope a query to a specific severity.
     *
     * @param  \Illuminate\Database\Eloquent\Builder<Anomaly>  $query
     *
     * @return \Illuminate\Database\Eloquent\Builder<Anomaly>
     */
    public function scopeSeverity( $query, string $severity )
    {
        return $query->where( 'severity', $severity );
    }

    /**
     * Scope a query to high severity or above.
     *
     * @param  \Illuminate\Database\Eloquent\Builder<Anomaly>  $query
     *
     * @return \Illuminate\Database\Eloquent\Builder<Anomaly>
     */
    public function scopeHighSeverity( $query )
    {
        return $query->whereIn( 'severity', [self::SEVERITY_HIGH, self::SEVERITY_CRITICAL] );
    }

    /**
     * Scope a query to a specific detector.
     *
     * @param  \Illuminate\Database\Eloquent\Builder<Anomaly>  $query
     *
     * @return \Illuminate\Database\Eloquent\Builder<Anomaly>
     */
    public function scopeDetector( $query, string $detector )
    {
        return $query->where( 'detector', $detector );
    }

    /**
     * Scope a query to a specific category.
     *
     * @param  \Illuminate\Database\Eloquent\Builder<Anomaly>  $query
     *
     * @return \Illuminate\Database\Eloquent\Builder<Anomaly>
     */
    public function scopeCategory( $query, string $category )
    {
        return $query->where( 'category', $category );
    }

    /**
     * Scope a query to a specific user.
     *
     * @param  \Illuminate\Database\Eloquent\Builder<Anomaly>  $query
     *
     * @return \Illuminate\Database\Eloquent\Builder<Anomaly>
     */
    public function scopeForUser( $query, int $userId )
    {
        return $query->where( 'user_id', $userId );
    }

    /**
     * Scope a query to a specific IP address.
     *
     * @param  \Illuminate\Database\Eloquent\Builder<Anomaly>  $query
     *
     * @return \Illuminate\Database\Eloquent\Builder<Anomaly>
     */
    public function scopeForIp( $query, string $ipAddress )
    {
        return $query->where( 'ip_address', $ipAddress );
    }

    /**
     * Get severity weight for sorting.
     */
    public function getSeverityWeight(): int
    {
        return match ( $this->severity ) {
            self::SEVERITY_CRITICAL => 5,
            self::SEVERITY_HIGH     => 4,
            self::SEVERITY_MEDIUM   => 3,
            self::SEVERITY_LOW      => 2,
            self::SEVERITY_INFO     => 1,
            default                 => 0,
        };
    }

    /**
     * Create a new factory instance for the model.
     */
    protected static function newFactory(): AnomalyFactory
    {
        return AnomalyFactory::new();
    }

    /**
     * Get the attributes that should be cast.
     *
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return [
            'score'       => 'float',
            'metadata'    => 'array',
            'detected_at' => 'datetime',
            'resolved_at' => 'datetime',
        ];
    }
}
