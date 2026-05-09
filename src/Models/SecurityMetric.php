<?php

declare( strict_types=1 );

namespace ArtisanPackUI\SecurityAnalytics\Models;

use ArtisanPackUI\SecurityAnalytics\Database\Factories\SecurityMetricFactory;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;

class SecurityMetric extends Model
{
    /** @use HasFactory<SecurityMetricFactory> */
    use HasFactory;

    /**
     * Metric types.
     */
    public const TYPE_COUNTER = 'counter';

    public const TYPE_GAUGE = 'gauge';

    public const TYPE_TIMING = 'timing';

    public const TYPE_HISTOGRAM = 'histogram';

    /**
     * Metric categories.
     */
    public const CATEGORY_AUTHENTICATION = 'authentication';

    public const CATEGORY_AUTHORIZATION = 'authorization';

    public const CATEGORY_API = 'api';

    public const CATEGORY_APPLICATION = 'application';

    public const CATEGORY_SYSTEM = 'system';

    public const CATEGORY_THREAT = 'threat';

    public const CATEGORY_PERFORMANCE = 'performance';

    public const CATEGORY_ACCESS = 'access';

    /**
     * The table associated with the model.
     */
    protected $table = 'security_metrics';

    /**
     * The attributes that are mass assignable.
     *
     * @var array<int, string>
     */
    protected $fillable = [
        'category',
        'metric_name',
        'metric_type',
        'value',
        'tags',
        'recorded_at',
    ];

    /**
     * Get a tag value.
     */
    public function getTag( string $key, mixed $default = null ): mixed
    {
        return data_get( $this->tags, $key, $default );
    }

    /**
     * Check if metric has a specific tag.
     */
    public function hasTag( string $key ): bool
    {
        return null !== data_get( $this->tags, $key );
    }

    /**
     * Scope a query to a specific category.
     *
     * @param  \Illuminate\Database\Eloquent\Builder<SecurityMetric>  $query
     *
     * @return \Illuminate\Database\Eloquent\Builder<SecurityMetric>
     */
    public function scopeCategory( $query, string $category )
    {
        return $query->where( 'category', $category );
    }

    /**
     * Scope a query to a specific metric name.
     *
     * @param  \Illuminate\Database\Eloquent\Builder<SecurityMetric>  $query
     *
     * @return \Illuminate\Database\Eloquent\Builder<SecurityMetric>
     */
    public function scopeMetric( $query, string $metricName )
    {
        return $query->where( 'metric_name', $metricName );
    }

    /**
     * Scope a query to a specific metric name (alias for scopeMetric).
     *
     * @param  \Illuminate\Database\Eloquent\Builder<SecurityMetric>  $query
     *
     * @return \Illuminate\Database\Eloquent\Builder<SecurityMetric>
     */
    public function scopeMetricName( $query, string $metricName )
    {
        return $this->scopeMetric( $query, $metricName );
    }

    /**
     * Scope a query to a specific metric type.
     *
     * @param  \Illuminate\Database\Eloquent\Builder<SecurityMetric>  $query
     *
     * @return \Illuminate\Database\Eloquent\Builder<SecurityMetric>
     */
    public function scopeOfType( $query, string $type )
    {
        return $query->where( 'metric_type', $type );
    }

    /**
     * Scope a query to a time range.
     *
     * @param  \Illuminate\Database\Eloquent\Builder<SecurityMetric>  $query
     *
     * @return \Illuminate\Database\Eloquent\Builder<SecurityMetric>
     */
    public function scopeBetween( $query, $from, $to )
    {
        return $query->whereBetween( 'recorded_at', [$from, $to] );
    }

    /**
     * Scope a query to metrics with a specific tag.
     *
     * @param  \Illuminate\Database\Eloquent\Builder<SecurityMetric>  $query
     *
     * @return \Illuminate\Database\Eloquent\Builder<SecurityMetric>
     */
    public function scopeWithTag( $query, string $key, mixed $value = null )
    {
        if ( null === $value ) {
            return $query->whereJsonContainsKey( "tags->{$key}" );
        }

        return $query->whereJsonContains( "tags->{$key}", $value );
    }

    /**
     * Create a new factory instance for the model.
     */
    protected static function newFactory(): SecurityMetricFactory
    {
        return SecurityMetricFactory::new();
    }

    /**
     * Get the attributes that should be cast.
     *
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return [
            'value'       => 'decimal:6',
            'tags'        => 'array',
            'recorded_at' => 'datetime',
        ];
    }
}
