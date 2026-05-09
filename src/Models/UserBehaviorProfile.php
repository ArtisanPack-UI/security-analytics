<?php

declare( strict_types=1 );

namespace ArtisanPackUI\SecurityAnalytics\Models;

use ArtisanPackUI\SecurityAnalytics\Database\Factories\UserBehaviorProfileFactory;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

class UserBehaviorProfile extends Model
{
    /** @use HasFactory<UserBehaviorProfileFactory> */
    use HasFactory;

    /**
     * Profile types.
     */
    public const TYPE_LOGIN = 'login';

    public const TYPE_API_USAGE = 'api_usage';

    public const TYPE_RESOURCE_ACCESS = 'resource_access';

    public const TYPE_SESSION = 'session';

    public const TYPE_GEOGRAPHIC = 'geographic';

    public const TYPE_ACCESS_PATTERNS = 'access_patterns';

    /**
     * The table associated with the model.
     */
    protected $table = 'user_behavior_profiles';

    /**
     * The attributes that are mass assignable.
     *
     * @var array<int, string>
     */
    protected $fillable = [
        'user_id',
        'profile_type',
        'baseline_data',
        'sample_count',
        'confidence_score',
        'last_updated_at',
    ];

    /**
     * Get the user that owns this profile.
     *
     * @return BelongsTo<\Illuminate\Foundation\Auth\User, UserBehaviorProfile>
     */
    public function user(): BelongsTo
    {
        $userModel = config( 'auth.providers.users.model', 'App\\Models\\User' );

        return $this->belongsTo( $userModel );
    }

    /**
     * Get a baseline value.
     */
    public function getBaseline( string $key, mixed $default = null ): mixed
    {
        return data_get( $this->baseline_data, $key, $default );
    }

    /**
     * Set a baseline value.
     */
    public function setBaseline( string $key, mixed $value ): void
    {
        $data = $this->baseline_data ?? [];
        data_set( $data, $key, $value );
        $this->baseline_data = $data;
    }

    /**
     * Check if the profile has sufficient data.
     */
    public function hasSufficientData( int $minSamples = 10 ): bool
    {
        return $this->sample_count >= $minSamples;
    }

    /**
     * Get the confidence level as a string.
     */
    public function getConfidenceLevel(): string
    {
        return match ( true ) {
            $this->confidence_score >= 80 => 'high',
            $this->confidence_score >= 50 => 'medium',
            $this->confidence_score >= 20 => 'low',
            default                       => 'insufficient',
        };
    }

    /**
     * Update the profile with a new data point.
     *
     * @param  array<string, mixed>  $dataPoint
     */
    public function addDataPoint( array $dataPoint ): void
    {
        $this->sample_count++;
        $this->last_updated_at = now();

        // Update confidence based on sample count
        $this->confidence_score = min( 100, ( $this->sample_count / 100 ) * 100 );
    }

    /**
     * Scope a query to a specific user.
     *
     * @param  \Illuminate\Database\Eloquent\Builder<UserBehaviorProfile>  $query
     *
     * @return \Illuminate\Database\Eloquent\Builder<UserBehaviorProfile>
     */
    public function scopeForUser( $query, int $userId )
    {
        return $query->where( 'user_id', $userId );
    }

    /**
     * Scope a query to a specific profile type.
     *
     * @param  \Illuminate\Database\Eloquent\Builder<UserBehaviorProfile>  $query
     *
     * @return \Illuminate\Database\Eloquent\Builder<UserBehaviorProfile>
     */
    public function scopeOfType( $query, string $type )
    {
        return $query->where( 'profile_type', $type );
    }

    /**
     * Scope a query to profiles with sufficient data.
     *
     * @param  \Illuminate\Database\Eloquent\Builder<UserBehaviorProfile>  $query
     *
     * @return \Illuminate\Database\Eloquent\Builder<UserBehaviorProfile>
     */
    public function scopeWithSufficientData( $query, int $minSamples = 10 )
    {
        return $query->where( 'sample_count', '>=', $minSamples );
    }

    /**
     * Scope a query to profiles needing update.
     *
     * @param  \Illuminate\Database\Eloquent\Builder<UserBehaviorProfile>  $query
     *
     * @return \Illuminate\Database\Eloquent\Builder<UserBehaviorProfile>
     */
    public function scopeNeedsUpdate( $query, int $hoursOld = 24 )
    {
        return $query->where( function ( $q ) use ( $hoursOld ): void {
            $q->whereNull( 'last_updated_at' )
                ->orWhere( 'last_updated_at', '<', now()->subHours( $hoursOld ) );
        } );
    }

    /**
     * Create a new factory instance for the model.
     */
    protected static function newFactory(): UserBehaviorProfileFactory
    {
        return UserBehaviorProfileFactory::new();
    }

    /**
     * Get the attributes that should be cast.
     *
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return [
            'baseline_data'    => 'array',
            'sample_count'     => 'integer',
            'confidence_score' => 'decimal:2',
            'last_updated_at'  => 'datetime',
        ];
    }
}
