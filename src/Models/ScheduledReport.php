<?php

/**
 * ScheduledReport Eloquent model.
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

use ArtisanPackUI\SecurityAnalytics\Database\Factories\ScheduledReportFactory;
use DateTime;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;

class ScheduledReport extends Model
{
    /** @use HasFactory<ScheduledReportFactory> */
    use HasFactory;

    /**
     * Report formats.
     */
    public const FORMAT_PDF = 'pdf';

    public const FORMAT_HTML = 'html';

    public const FORMAT_CSV = 'csv';

    public const FORMAT_JSON = 'json';

    /**
     * Report types.
     */
    public const TYPE_EXECUTIVE = 'executive_summary';

    public const TYPE_THREAT = 'threat_report';

    public const TYPE_COMPLIANCE = 'compliance_report';

    public const TYPE_INCIDENT = 'incident_report';

    public const TYPE_USER_ACTIVITY = 'user_activity';

    public const TYPE_TREND = 'trend_report';

    /**
     * The table associated with the model.
     */
    protected $table = 'scheduled_reports';

    /**
     * The attributes that are mass assignable.
     *
     * @var array<int, string>
     */
    protected $fillable = [
        'report_type',
        'name',
        'cron_expression',
        'recipients',
        'options',
        'format',
        'is_active',
        'last_run_at',
        'next_run_at',
    ];

    /**
     * Check if the report should run now.
     */
    public function shouldRunNow(): bool
    {
        if ( ! $this->is_active ) {
            return false;
        }

        if ( null === $this->next_run_at ) {
            return true;
        }

        return $this->next_run_at->isPast();
    }

    /**
     * Calculate the next run time based on cron expression.
     */
    public function calculateNextRun(): void
    {
        // Use a cron expression parser to calculate next run
        // This is a simplified implementation - in production use a library like dragonmantank/cron-expression
        $this->next_run_at = $this->parseNextCronRun();
    }

    /**
     * Mark the report as run.
     */
    public function markAsRun(): void
    {
        $this->last_run_at = now();
        $this->calculateNextRun();
        $this->save();
    }

    /**
     * Get an option value.
     */
    public function getOption( string $key, mixed $default = null ): mixed
    {
        return data_get( $this->options, $key, $default );
    }

    /**
     * Set an option value.
     */
    public function setOption( string $key, mixed $value ): void
    {
        $options = $this->options ?? [];
        data_set( $options, $key, $value );
        $this->options = $options;
    }

    /**
     * Get the email recipients.
     *
     * @return array<int, string>
     */
    public function getEmailRecipients(): array
    {
        $recipients = $this->recipients ?? [];

        return array_filter( $recipients, function ( $recipient ) {
            return false !== filter_var( $recipient, FILTER_VALIDATE_EMAIL );
        } );
    }

    /**
     * Scope a query to active reports.
     *
     * @param  \Illuminate\Database\Eloquent\Builder<ScheduledReport>  $query
     *
     * @return \Illuminate\Database\Eloquent\Builder<ScheduledReport>
     */
    public function scopeActive( $query )
    {
        return $query->where( 'is_active', true );
    }

    /**
     * Scope a query to due reports.
     *
     * @param  \Illuminate\Database\Eloquent\Builder<ScheduledReport>  $query
     *
     * @return \Illuminate\Database\Eloquent\Builder<ScheduledReport>
     */
    public function scopeDue( $query )
    {
        return $query->where( 'is_active', true )
            ->where( function ( $q ): void {
                $q->whereNull( 'next_run_at' )
                    ->orWhere( 'next_run_at', '<=', now() );
            } );
    }

    /**
     * Scope a query to a specific report type.
     *
     * @param  \Illuminate\Database\Eloquent\Builder<ScheduledReport>  $query
     *
     * @return \Illuminate\Database\Eloquent\Builder<ScheduledReport>
     */
    public function scopeOfType( $query, string $type )
    {
        return $query->where( 'report_type', $type );
    }

    /**
     * Scope a query to a specific format.
     *
     * @param  \Illuminate\Database\Eloquent\Builder<ScheduledReport>  $query
     *
     * @return \Illuminate\Database\Eloquent\Builder<ScheduledReport>
     */
    public function scopeFormat( $query, string $format )
    {
        return $query->where( 'format', $format );
    }

    /**
     * Create a new factory instance for the model.
     */
    protected static function newFactory(): ScheduledReportFactory
    {
        return ScheduledReportFactory::new();
    }

    /**
     * Get the attributes that should be cast.
     *
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return [
            'recipients'  => 'array',
            'options'     => 'array',
            'is_active'   => 'boolean',
            'last_run_at' => 'datetime',
            'next_run_at' => 'datetime',
        ];
    }

    /**
     * Parse the cron expression and return the next run time.
     */
    protected function parseNextCronRun(): ?DateTime
    {
        // Common shortcuts
        $shortcuts = [
            '@daily'   => now()->addDay()->startOfDay(),
            '@weekly'  => now()->addWeek()->startOfWeek(),
            '@monthly' => now()->addMonth()->startOfMonth(),
            '@hourly'  => now()->addHour()->startOfHour(),
        ];

        if ( isset( $shortcuts[ $this->cron_expression ] ) ) {
            return $shortcuts[ $this->cron_expression ];
        }

        // For full cron expressions, use a library in production
        // This is a fallback that runs daily at midnight
        return now()->addDay()->startOfDay();
    }
}
