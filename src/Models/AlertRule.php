<?php

declare( strict_types=1 );

namespace ArtisanPackUI\SecurityAnalytics\Models;

use ArtisanPackUI\SecurityAnalytics\Database\Factories\AlertRuleFactory;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\HasMany;

class AlertRule extends Model
{
    /** @use HasFactory<AlertRuleFactory> */
    use HasFactory;

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
    protected $table = 'alert_rules';

    /**
     * The attributes that are mass assignable.
     *
     * @var array<int, string>
     */
    protected $fillable = [
        'name',
        'description',
        'conditions',
        'severity',
        'channels',
        'recipients',
        'is_active',
        'cooldown_minutes',
        'escalation_policy',
    ];

    /**
     * Get the alert history for this rule.
     *
     * @return HasMany<AlertHistory>
     */
    public function history(): HasMany
    {
        return $this->hasMany( AlertHistory::class, 'rule_id' );
    }

    /**
     * Check if conditions match the given data.
     *
     * @param  array<string, mixed>  $data
     */
    public function matchesConditions( array $data ): bool
    {
        $conditions = $this->conditions ?? [];

        foreach ( $conditions as $field => $condition ) {
            $value = data_get( $data, $field );

            if ( is_array( $condition ) ) {
                // Handle operator conditions: ['operator' => '>=', 'value' => 5]
                if ( isset( $condition['operator'] ) ) {
                    if ( ! $this->evaluateCondition( $value, $condition['operator'], $condition['value'] ?? null ) ) {
                        return false;
                    }
                }
                // Handle in-array check
                elseif ( ! in_array( $value, $condition, true ) ) {
                    return false;
                }
            } elseif ( $value !== $condition ) {
                return false;
            }
        }

        return true;
    }

    /**
     * Get recipients for a specific channel.
     *
     * @return array<int, string>
     */
    public function getRecipientsForChannel( string $channel ): array
    {
        $recipients = $this->recipients ?? [];

        return $recipients[ $channel ] ?? [];
    }

    /**
     * Check if the rule is on cooldown.
     */
    public function isOnCooldown( ?string $contextKey = null ): bool
    {
        if ( $this->cooldown_minutes <= 0 ) {
            return false;
        }

        $cacheKey = 'alert_rule_cooldown_' . $this->id;
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

        $cacheKey = 'alert_rule_cooldown_' . $this->id;
        if ( $contextKey ) {
            $cacheKey .= '_' . $contextKey;
        }

        cache()->put( $cacheKey, true, now()->addMinutes( $this->cooldown_minutes ) );
    }

    /**
     * Get the escalation time in minutes for a given level.
     */
    public function getEscalationTime( int $level = 1 ): ?int
    {
        $policy = $this->escalation_policy ?? [];

        if ( empty( $policy ) ) {
            return null;
        }

        // Find the escalation level
        foreach ( $policy as $escalation ) {
            if ( ( $escalation['level'] ?? 1 ) === $level ) {
                return $escalation['after_minutes'] ?? null;
            }
        }

        return null;
    }

    /**
     * Scope a query to active rules.
     *
     * @param  \Illuminate\Database\Eloquent\Builder<AlertRule>  $query
     *
     * @return \Illuminate\Database\Eloquent\Builder<AlertRule>
     */
    public function scopeActive( $query )
    {
        return $query->where( 'is_active', true );
    }

    /**
     * Scope a query to a specific severity.
     *
     * @param  \Illuminate\Database\Eloquent\Builder<AlertRule>  $query
     *
     * @return \Illuminate\Database\Eloquent\Builder<AlertRule>
     */
    public function scopeSeverity( $query, string $severity )
    {
        return $query->where( 'severity', $severity );
    }

    /**
     * Scope a query to rules with a specific channel.
     *
     * @param  \Illuminate\Database\Eloquent\Builder<AlertRule>  $query
     *
     * @return \Illuminate\Database\Eloquent\Builder<AlertRule>
     */
    public function scopeWithChannel( $query, string $channel )
    {
        return $query->whereJsonContains( 'channels', $channel );
    }

    /**
     * Create a new factory instance for the model.
     */
    protected static function newFactory(): AlertRuleFactory
    {
        return AlertRuleFactory::new();
    }

    /**
     * Get the attributes that should be cast.
     *
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return [
            'conditions'        => 'array',
            'channels'          => 'array',
            'recipients'        => 'array',
            'is_active'         => 'boolean',
            'cooldown_minutes'  => 'integer',
            'escalation_policy' => 'array',
        ];
    }

    /**
     * Evaluate a condition with an operator.
     */
    protected function evaluateCondition( mixed $value, string $operator, mixed $expected ): bool
    {
        return match ( $operator ) {
            '='           => $value === $expected,
            '!='          => $value !== $expected,
            '>'           => $value > $expected,
            '>='          => $value >= $expected,
            '<'           => $value < $expected,
            '<='          => $value <= $expected,
            'in'          => is_array( $expected ) && in_array( $value, $expected, true ),
            'not_in'      => is_array( $expected ) && ! in_array( $value, $expected, true ),
            'contains'    => is_string( $value ) && is_string( $expected ) && str_contains( $value, $expected ),
            'starts_with' => is_string( $value ) && is_string( $expected ) && str_starts_with( $value, $expected ),
            'ends_with'   => is_string( $value ) && is_string( $expected ) && str_ends_with( $value, $expected ),
            'regex'       => is_string( $value ) && is_string( $expected ) && preg_match( $expected, $value ),
            default       => false,
        };
    }
}
