<?php

declare( strict_types=1 );

namespace ArtisanPackUI\SecurityAnalytics\Console\Commands;

use ArtisanPackUI\SecurityAnalytics\Contracts\SecurityEventLoggerInterface;
use ArtisanPackUI\SecurityAnalytics\Notifications\SuspiciousActivityNotification;
use Illuminate\Console\Command;
use Illuminate\Support\Collection;
use Illuminate\Support\Facades\Notification;

class DetectSuspiciousActivity extends Command
{
    /**
     * The name and signature of the console command.
     *
     * @var string
     */
    protected $signature = 'security:detect
                            {--notify : Send notifications for detected suspicious activity}';

    /**
     * The console command description.
     *
     * @var string
     */
    protected $description = 'Detect suspicious activity patterns';

    /**
     * Execute the console command.
     */
    public function handle( SecurityEventLoggerInterface $logger ): int
    {
        $this->info( 'Analyzing security events for suspicious activity...' );
        $this->newLine();

        $suspicious = $logger->detectSuspiciousActivity();

        if ( $suspicious->isEmpty() ) {
            $this->info( 'No suspicious activity detected.' );

            return self::SUCCESS;
        }

        $this->warn( "Detected {$suspicious->count()} suspicious pattern(s):" );
        $this->newLine();

        foreach ( $suspicious as $item ) {
            $this->displaySuspiciousItem( $item );
        }

        if ( $this->option( 'notify' ) ) {
            $this->sendNotifications( $suspicious );
        }

        return self::SUCCESS;
    }

    /**
     * Display a suspicious activity item.
     */
    protected function displaySuspiciousItem( array $item ): void
    {
        $type      = $item['type'];
        $threshold = $item['threshold'];
        $count     = $item['count'];
        $window    = $item['window_minutes'];

        switch ( $type ) {
            case 'failed_logins_per_ip':
                $this->line( "<fg=red>Failed Logins from IP:</> {$item['ip_address']}" );
                $this->line( "  Count: {$count} (threshold: {$threshold})" );
                $this->line( "  Window: {$window} minutes" );
                break;

            case 'failed_logins_per_user':
                $this->line( "<fg=red>Failed Logins for User:</> {$item['user_id']}" );
                $this->line( "  Count: {$count} (threshold: {$threshold})" );
                $this->line( "  Window: {$window} minutes" );
                break;

            case 'permission_denials_per_user':
                $this->line( "<fg=yellow>Permission Denials for User:</> {$item['user_id']}" );
                $this->line( "  Count: {$count} (threshold: {$threshold})" );
                $this->line( "  Window: {$window} minutes" );
                break;

            default:
                $this->line( "<fg=yellow>Unknown Pattern:</> {$type}" );
                $this->line( '  Details: ' . json_encode( $item ) );
        }

        $this->newLine();
    }

    /**
     * Send notifications for suspicious activity.
     */
    protected function sendNotifications( Collection $suspicious ): void
    {
        $alertingConfig = config( 'artisanpack.security-analytics.alerting', [] );

        if ( ! ( $alertingConfig['enabled'] ?? false ) ) {
            $this->warn( 'Alerting is disabled in configuration.' );

            return;
        }

        $recipients = $alertingConfig['recipients'] ?? '';

        if ( empty( $recipients ) ) {
            $this->warn( 'No alert recipients configured.' );

            return;
        }

        $this->info( 'Sending notifications...' );

        $recipientsArray = is_string( $recipients )
            ? array_filter( array_map( 'trim', explode( ',', $recipients ) ) )
            : (array) $recipients;

        Notification::route( 'mail', $recipientsArray )
            ->notify( new SuspiciousActivityNotification( $suspicious));

        $this->info( 'Notifications sent to: ' . implode( ', ', $recipientsArray));
    }
}
