<?php

/**
 * `ClearSecurityEvents` Artisan command.
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

use ArtisanPackUI\SecurityAnalytics\Contracts\SecurityEventLoggerInterface;
use Illuminate\Console\Command;

class ClearSecurityEvents extends Command
{
    /**
     * The name and signature of the console command.
     *
     * @var string
     */
    protected $signature = 'security:events:clear
                            {--days=90 : Delete events older than N days}
                            {--keep-critical : Keep critical severity events}
                            {--force : Skip confirmation}';

    /**
     * The console command description.
     *
     * @var string
     */
    protected $description = 'Clear old security events based on retention policy';

    /**
     * Execute the console command.
     */
    public function handle( SecurityEventLoggerInterface $logger ): int
    {
        $daysOption = $this->option( 'days' );

        if ( ! is_numeric( $daysOption ) || (int) $daysOption < 1 ) {
            $this->error( 'The --days option must be a positive integer (minimum 1).' );

            return self::FAILURE;
        }

        $days         = (int) $daysOption;
        $keepCritical = $this->option( 'keep-critical' );

        if ( ! $this->option( 'force' ) ) {
            $message = "This will delete security events older than {$days} days.";
            if ( $keepCritical ) {
                $message .= ' Critical events will be preserved.';
            }

            if ( ! $this->confirm( $message . ' Continue?' ) ) {
                $this->info( 'Operation cancelled.' );

                return self::SUCCESS;
            }
        }

        $this->info( "Clearing security events older than {$days} days..." );

        $deleted = $logger->pruneOldEvents( $days, $keepCritical );

        $this->info( "Deleted {$deleted} security event(s)." );

        return self::SUCCESS;
    }
}
