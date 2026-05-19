<?php

/**
 * `UpdateBehaviorBaselinesCommand` Artisan command.
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

use ArtisanPackUI\SecurityAnalytics\Analytics\AnomalyDetection\BaselineManager;
use ArtisanPackUI\SecurityAnalytics\Models\UserBehaviorProfile;
use Illuminate\Console\Command;

class UpdateBehaviorBaselinesCommand extends Command
{
    /**
     * The name and signature of the console command.
     *
     * @var string
     */
    protected $signature = 'security:baselines:update
                            {--user= : Update baseline for specific user ID}
                            {--type= : Update specific profile type (login, access, session, all)}
                            {--force : Force update even if recently updated}
                            {--prune : Prune profiles with insufficient data}
                            {--days=30 : Number of days to use for baseline calculation}';

    /**
     * The console command description.
     *
     * @var string
     */
    protected $description = 'Update user behavior baselines for anomaly detection';

    public function __construct(
        protected BaselineManager $baselineManager,
    ) {
        parent::__construct();
    }

    /**
     * Execute the console command.
     */
    public function handle(): int
    {
        $userId      = $this->option( 'user' );
        $profileType = $this->option( 'type' ) ?? 'all';
        $force       = $this->option( 'force' );
        $days        = (int) $this->option( 'days' );

        $this->info( 'Starting baseline update...' );

        if ( $userId ) {
            $this->updateUserBaseline( (int) $userId, $profileType, $days, $force );
        } else {
            $this->updateAllBaselines( $profileType, $days, $force );
        }

        if ( $this->option( 'prune' ) ) {
            $this->pruneInsufficientProfiles();
        }

        $this->info( 'Baseline update completed.' );

        return Command::SUCCESS;
    }

    /**
     * Update baseline for a specific user.
     */
    protected function updateUserBaseline( int $userId, string $profileType, int $days, bool $force ): void
    {
        $this->info( "Updating baselines for user {$userId}..." );

        $types = 'all' === $profileType
            ? [UserBehaviorProfile::TYPE_LOGIN, UserBehaviorProfile::TYPE_ACCESS, UserBehaviorProfile::TYPE_SESSION]
            : [$profileType];

        foreach ( $types as $type ) {
            $result = $this->baselineManager->updateUserBaseline( $userId, $type, $days, $force );

            if ( $result['updated'] ) {
                $this->info( "  Updated {$type} baseline: {$result['sample_count']} samples, confidence: {$result['confidence']}%" );
            } else {
                $this->warn( "  Skipped {$type}: {$result['reason']}" );
            }
        }
    }

    /**
     * Update baselines for all users.
     */
    protected function updateAllBaselines( string $profileType, int $days, bool $force ): void
    {
        $this->info( 'Updating baselines for all users...' );

        $types = 'all' === $profileType
            ? [UserBehaviorProfile::TYPE_LOGIN, UserBehaviorProfile::TYPE_ACCESS, UserBehaviorProfile::TYPE_SESSION]
            : [$profileType];

        $bar = $this->output->createProgressBar();
        $bar->setFormat( ' %current%/%max% [%bar%] %percent:3s%% %elapsed:6s%/%estimated:-6s% %memory:6s%' );

        $stats = [
            'updated' => 0,
            'skipped' => 0,
            'failed'  => 0,
        ];

        foreach ( $types as $type ) {
            $this->info( "Processing {$type} profiles..." );

            $results = $this->baselineManager->updateAllBaselines( $type, $days, $force, function ( $progress ) use ( $bar ): void {
                $bar->setProgress( $progress['current'] );
                $bar->setMaxSteps( $progress['total'] );
            } );

            $stats['updated'] += $results['updated'];
            $stats['skipped'] += $results['skipped'];
            $stats['failed'] += $results['failed'];
        }

        $bar->finish();
        $this->newLine();

        $this->table(
            ['Metric', 'Count'],
            [
                ['Updated', $stats['updated']],
                ['Skipped', $stats['skipped']],
                ['Failed', $stats['failed']],
            ],
        );
    }

    /**
     * Prune profiles with insufficient data.
     */
    protected function pruneInsufficientProfiles(): void
    {
        $this->info( 'Pruning profiles with insufficient data...' );

        $minSamples    = config( 'security-analytics.user_behavior.min_data_points', 50 );
        $minConfidence = 30;

        $deleted = UserBehaviorProfile::where( 'sample_count', '<', $minSamples )
            ->where( 'confidence_score', '<', $minConfidence )
            ->where( 'created_at', '<', now()->subDays( 7 ) )
            ->delete();

        $this->info( "Pruned {$deleted} insufficient profiles." );
    }
}
