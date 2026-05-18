<?php

/**
 * SecurityEvent Eloquent model.
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

use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Support\Carbon;

/**
 * @property int $id
 * @property string $event_type
 * @property string $event_name
 * @property string $severity
 * @property int|null $user_id
 * @property string $ip_address
 * @property string|null $user_agent
 * @property string|null $url
 * @property string|null $method
 * @property int|null $status_code
 * @property array|null $details
 * @property string|null $fingerprint
 * @property Carbon $created_at
 */
class SecurityEvent extends Model
{
    public const UPDATED_AT = null;

    public const TYPE_AUTHENTICATION = 'authentication';

    public const TYPE_AUTHORIZATION = 'authorization';

    public const TYPE_API_ACCESS = 'api_access';

    public const TYPE_SECURITY_VIOLATION = 'security_violation';

    public const TYPE_ROLE_CHANGE = 'role_change';

    public const TYPE_PERMISSION_CHANGE = 'permission_change';

    public const TYPE_TOKEN_MANAGEMENT = 'token_management';

    public const SEVERITY_DEBUG = 'debug';

    public const SEVERITY_INFO = 'info';

    public const SEVERITY_WARNING = 'warning';

    public const SEVERITY_ERROR = 'error';

    public const SEVERITY_CRITICAL = 'critical';

    protected $fillable = [
        'event_type',
        'event_name',
        'severity',
        'user_id',
        'ip_address',
        'user_agent',
        'url',
        'method',
        'status_code',
        'details',
        'fingerprint',
    ];

    protected $casts = [
        'details'     => 'array',
        'status_code' => 'integer',
        'user_id'     => 'integer',
        'created_at'  => 'datetime',
    ];

    /**
     * Get the user associated with the event.
     */
    public function user(): BelongsTo
    {
        $userModel = config( 'auth.providers.users.model', 'App\\Models\\User' );

        return $this->belongsTo( $userModel );
    }

    /**
     * Scope a query to filter by event type.
     */
    public function scopeByType( Builder $query, string $type ): Builder
    {
        return $query->where( 'event_type', $type );
    }

    /**
     * Scope a query to filter by event name.
     */
    public function scopeByName( Builder $query, string $name ): Builder
    {
        return $query->where( 'event_name', $name );
    }

    /**
     * Scope a query to filter by severity.
     */
    public function scopeBySeverity( Builder $query, string $severity ): Builder
    {
        return $query->where( 'severity', $severity );
    }

    /**
     * Scope a query to filter by user.
     */
    public function scopeByUser( Builder $query, int $userId ): Builder
    {
        return $query->where( 'user_id', $userId );
    }

    /**
     * Scope a query to filter by IP address.
     */
    public function scopeByIp( Builder $query, string $ip ): Builder
    {
        return $query->where( 'ip_address', $ip );
    }

    /**
     * Scope a query to get recent events within a timeframe.
     */
    public function scopeRecent( Builder $query, int $hours = 24 ): Builder
    {
        return $query->where( 'created_at', '>=', now()->subHours( $hours ) );
    }

    /**
     * Scope a query to filter events within a date range.
     */
    public function scopeInDateRange( Builder $query, $start, $end ): Builder
    {
        return $query->whereBetween( 'created_at', [$start, $end] );
    }

    /**
     * Scope a query to get suspicious events (errors and critical severity).
     */
    public function scopeSuspicious( Builder $query ): Builder
    {
        return $query->whereIn( 'severity', [self::SEVERITY_ERROR, self::SEVERITY_CRITICAL] );
    }

    /**
     * Scope a query to get authentication events.
     */
    public function scopeAuthentication( Builder $query ): Builder
    {
        return $query->where( 'event_type', self::TYPE_AUTHENTICATION );
    }

    /**
     * Scope a query to get authorization events.
     */
    public function scopeAuthorization( Builder $query ): Builder
    {
        return $query->where( 'event_type', self::TYPE_AUTHORIZATION );
    }

    /**
     * Scope a query to get API access events.
     */
    public function scopeApiAccess( Builder $query ): Builder
    {
        return $query->where( 'event_type', self::TYPE_API_ACCESS );
    }

    /**
     * Scope a query to get security violation events.
     */
    public function scopeSecurityViolation( Builder $query ): Builder
    {
        return $query->where( 'event_type', self::TYPE_SECURITY_VIOLATION );
    }

    /**
     * Check if the event is suspicious (error or critical severity).
     */
    public function isSuspicious(): bool
    {
        return in_array( $this->severity, [self::SEVERITY_ERROR, self::SEVERITY_CRITICAL], true );
    }

    /**
     * Get formatted details for display.
     */
    public function getFormattedDetails(): string
    {
        if ( empty( $this->details ) ) {
            return '';
        }

        return json_encode( $this->details, JSON_PRETTY_PRINT ) ?: '';
    }

    /**
     * Generate a fingerprint for the event to group similar events.
     */
    public static function generateFingerprint( string $eventType, string $eventName, ?string $ipAddress = null ): string
    {
        return hash( 'sha256', implode( '|', [$eventType, $eventName, $ipAddress ?? '']));
    }
}
