<?php

/**
 * ThreatIndicator Eloquent model.
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

use ArtisanPackUI\SecurityAnalytics\Database\Factories\ThreatIndicatorFactory;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;

class ThreatIndicator extends Model
{
    /** @use HasFactory<ThreatIndicatorFactory> */
    use HasFactory;

    /**
     * Indicator types.
     */
    public const TYPE_IP = 'ip';

    public const TYPE_DOMAIN = 'domain';

    public const TYPE_URL = 'url';

    public const TYPE_HASH = 'hash';

    public const TYPE_EMAIL = 'email';

    /**
     * Threat types.
     */
    public const THREAT_MALWARE = 'malware';

    public const THREAT_PHISHING = 'phishing';

    public const THREAT_SPAM = 'spam';

    public const THREAT_BRUTEFORCE = 'bruteforce';

    public const THREAT_BOTNET = 'botnet';

    public const THREAT_PROXY = 'proxy';

    public const THREAT_TOR = 'tor';

    public const THREAT_VPN = 'vpn';

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
    protected $table = 'threat_indicators';

    /**
     * The attributes that are mass assignable.
     *
     * @var array<int, string>
     */
    protected $fillable = [
        'type',
        'value',
        'source',
        'threat_type',
        'severity',
        'confidence',
        'first_seen_at',
        'last_seen_at',
        'expires_at',
        'metadata',
    ];

    /**
     * Check if the indicator is expired.
     */
    public function isExpired(): bool
    {
        if ( null === $this->expires_at ) {
            return false;
        }

        return $this->expires_at->isPast();
    }

    /**
     * Check if the indicator is active.
     */
    public function isActive(): bool
    {
        return ! $this->isExpired();
    }

    /**
     * Update the last seen timestamp.
     */
    public function updateLastSeen(): void
    {
        $this->last_seen_at = now();
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
     * Scope a query to a specific type.
     *
     * @param  \Illuminate\Database\Eloquent\Builder<ThreatIndicator>  $query
     *
     * @return \Illuminate\Database\Eloquent\Builder<ThreatIndicator>
     */
    public function scopeOfType( $query, string $type )
    {
        return $query->where( 'type', $type );
    }

    /**
     * Scope a query to a specific threat type.
     *
     * @param  \Illuminate\Database\Eloquent\Builder<ThreatIndicator>  $query
     *
     * @return \Illuminate\Database\Eloquent\Builder<ThreatIndicator>
     */
    public function scopeThreatType( $query, string $threatType )
    {
        return $query->where( 'threat_type', $threatType );
    }

    /**
     * Scope a query to active (non-expired) indicators.
     *
     * @param  \Illuminate\Database\Eloquent\Builder<ThreatIndicator>  $query
     *
     * @return \Illuminate\Database\Eloquent\Builder<ThreatIndicator>
     */
    public function scopeActive( $query )
    {
        return $query->where( function ( $q ): void {
            $q->whereNull( 'expires_at' )
                ->orWhere( 'expires_at', '>', now() );
        } );
    }

    /**
     * Scope a query to expired indicators.
     *
     * @param  \Illuminate\Database\Eloquent\Builder<ThreatIndicator>  $query
     *
     * @return \Illuminate\Database\Eloquent\Builder<ThreatIndicator>
     */
    public function scopeExpired( $query )
    {
        return $query->whereNotNull( 'expires_at' )
            ->where( 'expires_at', '<=', now() );
    }

    /**
     * Scope a query to a specific source.
     *
     * @param  \Illuminate\Database\Eloquent\Builder<ThreatIndicator>  $query
     *
     * @return \Illuminate\Database\Eloquent\Builder<ThreatIndicator>
     */
    public function scopeFromSource( $query, string $source )
    {
        return $query->where( 'source', $source );
    }

    /**
     * Scope a query to high confidence indicators.
     *
     * @param  \Illuminate\Database\Eloquent\Builder<ThreatIndicator>  $query
     *
     * @return \Illuminate\Database\Eloquent\Builder<ThreatIndicator>
     */
    public function scopeHighConfidence( $query, int $minConfidence = 80 )
    {
        return $query->where( 'confidence', '>=', $minConfidence );
    }

    /**
     * Scope a query to find by value.
     *
     * @param  \Illuminate\Database\Eloquent\Builder<ThreatIndicator>  $query
     *
     * @return \Illuminate\Database\Eloquent\Builder<ThreatIndicator>
     */
    public function scopeByValue( $query, string $type, string $value )
    {
        return $query->where( 'type', $type )->where( 'value', $value );
    }

    /**
     * Find an active indicator by type and value.
     */
    public static function findActive( string $type, string $value ): ?self
    {
        return static::active()
            ->byValue( $type, $value )
            ->first();
    }

    /**
     * Create a new factory instance for the model.
     */
    protected static function newFactory(): ThreatIndicatorFactory
    {
        return ThreatIndicatorFactory::new();
    }

    /**
     * Boot the model.
     */
    protected static function boot(): void
    {
        parent::boot();

        static::creating( function ( ThreatIndicator $indicator ): void {
            // Set default severity based on confidence if not provided
            if ( empty( $indicator->severity ) ) {
                $indicator->severity = self::mapConfidenceToSeverity( $indicator->confidence ?? 0 );
            }

            // Set default first_seen_at if not provided
            if ( empty( $indicator->first_seen_at ) ) {
                $indicator->first_seen_at = now();
            }

            // Set default last_seen_at if not provided
            if ( empty( $indicator->last_seen_at ) ) {
                $indicator->last_seen_at = now();
            }
        } );
    }

    /**
     * Map confidence score to severity level.
     */
    protected static function mapConfidenceToSeverity( int $confidence ): string
    {
        return match ( true ) {
            $confidence >= 80 => self::SEVERITY_CRITICAL,
            $confidence >= 60 => self::SEVERITY_HIGH,
            $confidence >= 40 => self::SEVERITY_MEDIUM,
            $confidence >= 20 => self::SEVERITY_LOW,
            default           => self::SEVERITY_INFO,
        };
    }

    /**
     * Get the attributes that should be cast.
     *
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return [
            'confidence'    => 'integer',
            'first_seen_at' => 'datetime',
            'last_seen_at'  => 'datetime',
            'expires_at'    => 'datetime',
            'metadata'      => 'array',
        ];
    }
}
