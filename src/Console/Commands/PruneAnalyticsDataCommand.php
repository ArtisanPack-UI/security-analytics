<?php

/**
 * `PruneAnalyticsDataCommand` Artisan command.
 *
 * @package    ArtisanPack_UI
 * @subpackage SecurityAnalytics
 *
 * @author     Jacob Martella <support@artisanpackui.dev>
 *
 * @since      1.0.0
 */

declare( strict_types=1 );

namespace ArtisanPackUI\SecurityAnalytics\Console\Commands;

use ArtisanPackUI\SecurityAnalytics\Analytics\MetricsCollector;
use ArtisanPackUI\SecurityAnalytics\Analytics\ThreatIntelligence\ThreatIntelligenceService;
use ArtisanPackUI\SecurityAnalytics\Models\AlertHistory;
use ArtisanPackUI\SecurityAnalytics\Models\Anomaly;
use ArtisanPackUI\SecurityAnalytics\Models\SecurityIncident;
use ArtisanPackUI\SecurityAnalytics\Models\SecurityMetric;
use ArtisanPackUI\SecurityAnalytics\Models\UserBehaviorProfile;
use Illuminate\Console\Command;

class PruneAnalyticsDataCommand extends Command
{
    /**
     * The name and signature of the console command.
     *
     * @var string
     */
    protected $signature = 'security:analytics:prune
                            {--metrics : Prune old metrics}
                            {--anomalies : Prune old resolved anomalies}
                            {--alerts : Prune old alert history}
                            {--threats : Prune expired threat indicators}
                            {--incidents : Prune old closed incidents}
                            {--profiles : Prune stale behavior profiles}
                            {--all : Prune all data types}
                            {--days= : Override retention period (days)}
                            {--dry-run : Show what would be deleted without deleting}';

    /**
     * The console command description.
     *
     * @var string
     */
    protected $description = 'Prune old analytics data to maintain database performance';

    public function __construct(
        protected MetricsCollector $metricsCollector,
        protected ThreatIntelligenceService $threatIntel,
    ) {
        parent::__construct();
    }

    /**
     * Execute the console command.
     */
    public function handle(): int
    {
        $runAll       = $this->option( 'all' );
        $dryRun       = $this->option( 'dry-run' );
        $daysOption   = $this->option( 'days' );
        $overrideDays = null !== $daysOption ? (int) $daysOption : null;

        // A non-positive --days value would push the cutoff to now() or the
        // future, which would prune *current* records instead of stale ones.
        if ( null !== $overrideDays && $overrideDays < 1 ) {
            $this->error( "--days must be a positive integer; got '{$daysOption}'." );

            return Command::FAILURE;
        }

        // Fail fast: check if any prune option is specified
        if ( ! $runAll && ! $this->option( 'metrics' ) && ! $this->option( 'anomalies' )
            && ! $this->option( 'alerts' ) && ! $this->option( 'threats' )
            && ! $this->option( 'incidents' ) && ! $this->option( 'profiles' ) ) {
            $this->info( 'No data type specified. Use --all to prune all types or specify individual types.' );

            return Command::SUCCESS;
        }

        if ( $dryRun ) {
            $this->warn( 'DRY RUN - No data will be deleted' );
        }

        $totalDeleted = 0;

        if ( $runAll || $this->option( 'metrics' ) ) {
            $totalDeleted += $this->pruneMetrics( $dryRun, $overrideDays );
        }

        if ( $runAll || $this->option( 'anomalies' ) ) {
            $totalDeleted += $this->pruneAnomalies( $dryRun, $overrideDays );
        }

        if ( $runAll || $this->option( 'alerts' ) ) {
            $totalDeleted += $this->pruneAlerts( $dryRun, $overrideDays );
        }

        if ( $runAll || $this->option( 'threats' ) ) {
            $totalDeleted += $this->pruneThreats( $dryRun );
        }

        if ( $runAll || $this->option( 'incidents' ) ) {
            $totalDeleted += $this->pruneIncidents( $dryRun, $overrideDays );
        }

        if ( $runAll || $this->option( 'profiles' ) ) {
            $totalDeleted += $this->pruneProfiles( $dryRun, $overrideDays );
        }

        $this->newLine();
        $action = $dryRun ? 'Would delete' : 'Deleted';
        $this->info( "{$action} {$totalDeleted} total records." );

        return Command::SUCCESS;
    }

    /**
     * Prune old metrics.
     */
    protected function pruneMetrics( bool $dryRun, ?int $overrideDays ): int
    {
        $days   = $overrideDays ?? config( 'security-analytics.metrics.retention_days', 90 );
        $cutoff = now()->subDays( $days );

        $this->info( "Pruning metrics older than {$days} days..." );

        $count = SecurityMetric::where( 'recorded_at', '<', $cutoff )->count();

        if ( ! $dryRun && $count > 0 ) {
            $this->metricsCollector->cleanup( $days );
        }

        $this->info( "  {$count} metrics " . ( $dryRun ? 'would be deleted' : 'deleted' ) );

        return $count;
    }

    /**
     * Prune old resolved anomalies.
     */
    protected function pruneAnomalies( bool $dryRun, ?int $overrideDays ): int
    {
        $days   = $overrideDays ?? 180; // Default 6 months for anomalies
        $cutoff = now()->subDays( $days );

        $this->info( "Pruning resolved anomalies older than {$days} days..." );

        $query = Anomaly::whereNotNull( 'resolved_at' )
            ->where( 'resolved_at', '<', $cutoff );

        $count = $query->count();

        if ( ! $dryRun && $count > 0 ) {
            $query->delete();
        }

        $this->info( "  {$count} anomalies " . ( $dryRun ? 'would be deleted' : 'deleted' ) );

        return $count;
    }

    /**
     * Prune old alert history.
     */
    protected function pruneAlerts( bool $dryRun, ?int $overrideDays ): int
    {
        $days   = $overrideDays ?? 90; // Default 3 months for alerts
        $cutoff = now()->subDays( $days );

        $this->info( "Pruning alert history older than {$days} days..." );

        $query = AlertHistory::where( 'created_at', '<', $cutoff );

        $count = $query->count();

        if ( ! $dryRun && $count > 0 ) {
            $query->delete();
        }

        $this->info( "  {$count} alerts " . ( $dryRun ? 'would be deleted' : 'deleted' ) );

        return $count;
    }

    /**
     * Prune expired threat indicators.
     */
    protected function pruneThreats( bool $dryRun ): int
    {
        $this->info( 'Pruning expired threat indicators...' );

        $count = $this->threatIntel->getStatistics()['total_indicators']
            - $this->threatIntel->getStatistics()['active_indicators'];

        if ( ! $dryRun && $count > 0 ) {
            $this->threatIntel->cleanupExpired();
        }

        $this->info( "  {$count} indicators " . ( $dryRun ? 'would be deleted' : 'deleted' ) );

        return $count;
    }

    /**
     * Prune old closed incidents.
     */
    protected function pruneIncidents( bool $dryRun, ?int $overrideDays ): int
    {
        $days   = $overrideDays ?? 365; // Default 1 year for incidents
        $cutoff = now()->subDays( $days );

        $this->info( "Pruning closed incidents older than {$days} days..." );

        $query = SecurityIncident::where( 'status', SecurityIncident::STATUS_CLOSED )
            ->where( 'closed_at', '<', $cutoff );

        $count = $query->count();

        if ( ! $dryRun && $count > 0 ) {
            $query->delete();
        }

        $this->info( "  {$count} incidents " . ( $dryRun ? 'would be deleted' : 'deleted' ) );

        return $count;
    }

    /**
     * Prune stale behavior profiles.
     */
    protected function pruneProfiles( bool $dryRun, ?int $overrideDays ): int
    {
        $days   = $overrideDays ?? 90; // Default 3 months
        $cutoff = now()->subDays( $days );

        $this->info( "Pruning stale behavior profiles (not updated in {$days} days)..." );

        $query = UserBehaviorProfile::where( 'last_updated_at', '<', $cutoff )
            ->where( 'confidence_score', '<', 50 ); // Only prune low-confidence profiles

        $count = $query->count();

        if ( ! $dryRun && $count > 0 ) {
            $query->delete();
        }

        $this->info( "  {$count} profiles " . ( $dryRun ? 'would be deleted' : 'deleted' ) );

        return $count;
    }
}
