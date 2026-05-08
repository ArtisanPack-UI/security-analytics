<?php

declare( strict_types=1 );

namespace ArtisanPackUI\SecurityAnalytics;

use ArtisanPackUI\SecurityAnalytics\Analytics\Alerting\AlertManager;
use ArtisanPackUI\SecurityAnalytics\Analytics\Alerting\Channels\DatabaseChannel;
use ArtisanPackUI\SecurityAnalytics\Analytics\Alerting\Channels\OpsGenieChannel;
use ArtisanPackUI\SecurityAnalytics\Analytics\Alerting\Channels\SmsChannel;
use ArtisanPackUI\SecurityAnalytics\Analytics\Alerting\Channels\TeamsChannel;
use ArtisanPackUI\SecurityAnalytics\Analytics\Alerting\Channels\WebhookChannel;
use ArtisanPackUI\SecurityAnalytics\Analytics\AnomalyDetection\AnomalyDetectionService;
use ArtisanPackUI\SecurityAnalytics\Analytics\AnomalyDetection\Detectors\AccessPatternDetector;
use ArtisanPackUI\SecurityAnalytics\Analytics\AnomalyDetection\Detectors\BruteForceDetector;
use ArtisanPackUI\SecurityAnalytics\Analytics\AnomalyDetection\Detectors\CredentialStuffingDetector;
use ArtisanPackUI\SecurityAnalytics\Analytics\AnomalyDetection\Detectors\GeoVelocityDetector;
use ArtisanPackUI\SecurityAnalytics\Analytics\AnomalyDetection\Detectors\PrivilegeEscalationDetector;
use ArtisanPackUI\SecurityAnalytics\Analytics\Dashboard\DashboardDataProvider;
use ArtisanPackUI\SecurityAnalytics\Analytics\IncidentResponse\Actions\EnableEnhancedLoggingAction;
use ArtisanPackUI\SecurityAnalytics\Analytics\IncidentResponse\Actions\ForcePasswordResetAction;
use ArtisanPackUI\SecurityAnalytics\Analytics\IncidentResponse\Actions\LockAccountAction;
use ArtisanPackUI\SecurityAnalytics\Analytics\IncidentResponse\Actions\RateLimitIpAction;
use ArtisanPackUI\SecurityAnalytics\Analytics\IncidentResponse\Actions\TerminateSessionAction;
use ArtisanPackUI\SecurityAnalytics\Analytics\IncidentResponse\IncidentResponder;
use ArtisanPackUI\SecurityAnalytics\Analytics\MetricsCollector;
use ArtisanPackUI\SecurityAnalytics\Analytics\Reports\ReportGenerator;
use ArtisanPackUI\SecurityAnalytics\Analytics\Siem\Exporters\DatadogExporter;
use ArtisanPackUI\SecurityAnalytics\Analytics\Siem\Exporters\WebhookExporter as SiemWebhookExporter;
use ArtisanPackUI\SecurityAnalytics\Analytics\Siem\SiemExportService;
use ArtisanPackUI\SecurityAnalytics\Analytics\ThreatIntelligence\Providers\CustomFeedProvider;
use ArtisanPackUI\SecurityAnalytics\Analytics\ThreatIntelligence\Providers\GoogleSafeBrowsingProvider;
use ArtisanPackUI\SecurityAnalytics\Analytics\ThreatIntelligence\Providers\IpQualityScoreProvider;
use ArtisanPackUI\SecurityAnalytics\Analytics\ThreatIntelligence\ThreatIntelligenceService;
use ArtisanPackUI\SecurityAnalytics\Authentication\Contracts\SuspiciousActivityDetectorInterface;
use ArtisanPackUI\SecurityAnalytics\Authentication\Detection\SuspiciousActivityService;
use ArtisanPackUI\SecurityAnalytics\Console\Commands\AnalyticsProcessCommand;
use ArtisanPackUI\SecurityAnalytics\Console\Commands\ClearSecurityEvents;
use ArtisanPackUI\SecurityAnalytics\Console\Commands\DetectSuspiciousActivity;
use ArtisanPackUI\SecurityAnalytics\Console\Commands\ExportSecurityEvents;
use ArtisanPackUI\SecurityAnalytics\Console\Commands\GenerateSecurityReportCommand;
use ArtisanPackUI\SecurityAnalytics\Console\Commands\ListSecurityEvents;
use ArtisanPackUI\SecurityAnalytics\Console\Commands\PruneAnalyticsDataCommand;
use ArtisanPackUI\SecurityAnalytics\Console\Commands\SecurityEventStats;
use ArtisanPackUI\SecurityAnalytics\Console\Commands\SyncThreatFeedsCommand;
use ArtisanPackUI\SecurityAnalytics\Console\Commands\TestSiemConnectionCommand;
use ArtisanPackUI\SecurityAnalytics\Console\Commands\UpdateBehaviorBaselinesCommand;
use ArtisanPackUI\SecurityAnalytics\Contracts\SecurityEventLoggerInterface;
use ArtisanPackUI\SecurityAnalytics\Services\SecurityEventLogger;
use Illuminate\Support\ServiceProvider;

/**
 * Service provider for the Security Analytics package.
 *
 * Wires the security event logger, anomaly-detection service, threat
 * intelligence service, incident responder, alert manager, dashboard
 * data provider, report generator, and SIEM export service. Loads
 * config, migrations, views, routes, and console commands.
 */
class SecurityAnalyticsServiceProvider extends ServiceProvider
{
    /**
     * Register container bindings.
     */
    public function register(): void
    {
        $this->mergeConfigFrom(
            __DIR__ . '/../config/artisanpack/security-analytics.php',
            'artisanpack.security-analytics',
        );

        $this->app->singleton( 'security-analytics', fn () => new SecurityAnalytics() );

        // Core event logger
        $this->app->singleton( SecurityEventLoggerInterface::class, fn () => new SecurityEventLogger() );
        $this->app->alias( SecurityEventLoggerInterface::class, 'security-events' );

        // Suspicious activity detector
        $this->app->singleton( SuspiciousActivityService::class, fn () => new SuspiciousActivityService() );
        $this->app->bind( SuspiciousActivityDetectorInterface::class, SuspiciousActivityService::class );

        $this->registerAnalyticsServices();
    }

    /**
     * Bootstrap package services.
     */
    public function boot(): void
    {
        $this->publishes( [
            __DIR__ . '/../config/artisanpack/security-analytics.php'
                => config_path( 'artisanpack/security-analytics.php' ),
        ], 'security-analytics-config' );

        $this->loadMigrationsFrom( __DIR__ . '/../database/migrations' );

        $this->loadViewsFrom( __DIR__ . '/../resources/views', 'artisanpack-ui-security-analytics' );

        // Dashboard routes register Livewire components — only load if both
        // the dashboard is enabled AND livewire/livewire is actually installed.
        if (
            config( 'artisanpack.security-analytics.dashboard.enabled', true )
            && class_exists( \Livewire\Component::class )
        ) {
            $this->loadRoutesFrom( __DIR__ . '/../routes/security-dashboard.php' );
        }

        if (
            config( 'artisanpack.security-analytics.dashboard.enabled', false )
            && class_exists( \Livewire\Component::class )
        ) {
            $this->loadRoutesFrom( __DIR__ . '/../routes/analytics-dashboard.php' );
        }

        if ( $this->app->runningInConsole() ) {
            $this->commands( [
                AnalyticsProcessCommand::class,
                ClearSecurityEvents::class,
                DetectSuspiciousActivity::class,
                ExportSecurityEvents::class,
                GenerateSecurityReportCommand::class,
                ListSecurityEvents::class,
                PruneAnalyticsDataCommand::class,
                SecurityEventStats::class,
                SyncThreatFeedsCommand::class,
                TestSiemConnectionCommand::class,
                UpdateBehaviorBaselinesCommand::class,
            ] );
        }
    }

    /**
     * Register analytics service singletons.
     */
    protected function registerAnalyticsServices(): void
    {
        $this->app->singleton( MetricsCollector::class, fn () => new MetricsCollector(
            config( 'artisanpack.security-analytics.metrics', [] ),
        ) );

        $this->app->singleton( AnomalyDetectionService::class, function (): AnomalyDetectionService {
            $service = new AnomalyDetectionService(
                config( 'artisanpack.security-analytics.anomaly_detection', [] ),
            );

            $this->registerAnomalyDetectors( $service );

            return $service;
        } );

        $this->app->singleton( ThreatIntelligenceService::class, function (): ThreatIntelligenceService {
            $service = new ThreatIntelligenceService(
                config( 'artisanpack.security-analytics.threat_intelligence', [] ),
            );

            $this->registerThreatIntelProviders( $service );

            return $service;
        } );

        $this->app->singleton( IncidentResponder::class, function (): IncidentResponder {
            $service = new IncidentResponder(
                config( 'artisanpack.security-analytics.incident_response', [] ),
            );

            $this->registerResponseActions( $service );

            return $service;
        } );

        $this->app->singleton( AlertManager::class, function (): AlertManager {
            $service = new AlertManager(
                config( 'artisanpack.security-analytics.alerting', [] ),
            );

            $this->registerAlertChannels( $service );

            return $service;
        } );

        $this->app->singleton( DashboardDataProvider::class, fn () => new DashboardDataProvider() );

        $this->app->singleton( ReportGenerator::class, fn () => new ReportGenerator(
            config( 'artisanpack.security-analytics.reports', [] ),
        ) );

        $this->app->singleton( SiemExportService::class, function (): SiemExportService {
            $service = new SiemExportService(
                config( 'artisanpack.security-analytics.siem', [] ),
            );

            $this->registerSiemExporters( $service );

            return $service;
        } );
    }

    /**
     * Register anomaly detectors gated on config presence.
     */
    protected function registerAnomalyDetectors( AnomalyDetectionService $service ): void
    {
        $configs = config( 'artisanpack.security-analytics.anomaly_detection.detectors', [] );

        if ( ! empty( $configs['geo_velocity'] ) ) {
            $service->registerDetector( new GeoVelocityDetector( $configs['geo_velocity'] ) );
        }

        if ( ! empty( $configs['brute_force'] ) ) {
            $service->registerDetector( new BruteForceDetector( $configs['brute_force'] ) );
        }

        if ( ! empty( $configs['credential_stuffing'] ) ) {
            $service->registerDetector( new CredentialStuffingDetector( $configs['credential_stuffing'] ) );
        }

        if ( ! empty( $configs['privilege_escalation'] ) ) {
            $service->registerDetector( new PrivilegeEscalationDetector( $configs['privilege_escalation'] ) );
        }

        if ( ! empty( $configs['access_pattern'] ) ) {
            $service->registerDetector( new AccessPatternDetector( $configs['access_pattern'] ) );
        }
    }

    /**
     * Register threat intelligence providers gated on config presence.
     */
    protected function registerThreatIntelProviders( ThreatIntelligenceService $service ): void
    {
        $configs = config( 'artisanpack.security-analytics.threat_intelligence.providers', [] );

        if ( ! empty( $configs['ipqualityscore'] ) ) {
            $service->registerProvider( new IpQualityScoreProvider( $configs['ipqualityscore'] ) );
        }

        if ( ! empty( $configs['google_safe_browsing'] ) ) {
            $service->registerProvider( new GoogleSafeBrowsingProvider( $configs['google_safe_browsing'] ) );
        }

        if ( ! empty( $configs['custom_feeds'] ) ) {
            foreach ( $configs['custom_feeds'] as $feedConfig ) {
                $service->registerProvider( new CustomFeedProvider( $feedConfig ) );
            }
        }
    }

    /**
     * Register the default incident response actions.
     */
    protected function registerResponseActions( IncidentResponder $service ): void
    {
        $service->registerAction( new LockAccountAction() );
        $service->registerAction( new ForcePasswordResetAction() );
        $service->registerAction( new RateLimitIpAction() );
        $service->registerAction( new TerminateSessionAction() );
        $service->registerAction( new EnableEnhancedLoggingAction() );
    }

    /**
     * Register alert channels gated on config presence.
     */
    protected function registerAlertChannels( AlertManager $service ): void
    {
        $configs = config( 'artisanpack.security-analytics.alerting.channels', [] );

        if ( ! empty( $configs['teams'] ) ) {
            $service->registerChannel( new TeamsChannel( $configs['teams'] ) );
        }

        if ( ! empty( $configs['opsgenie'] ) ) {
            $service->registerChannel( new OpsGenieChannel( $configs['opsgenie'] ) );
        }

        if ( ! empty( $configs['webhook'] ) ) {
            $service->registerChannel( new WebhookChannel( $configs['webhook'] ) );
        }

        if ( ! empty( $configs['sms'] ) ) {
            $service->registerChannel( new SmsChannel( $configs['sms'] ) );
        }

        if ( ! empty( $configs['database'] ) ) {
            $service->registerChannel( new DatabaseChannel( $configs['database'] ) );
        }
    }

    /**
     * Register SIEM exporters gated on config presence.
     */
    protected function registerSiemExporters( SiemExportService $service ): void
    {
        $configs = config( 'artisanpack.security-analytics.siem.providers', [] );

        if ( ! empty( $configs['datadog'] ) ) {
            $service->registerExporter( new DatadogExporter( $configs['datadog'] ) );
        }

        if ( ! empty( $configs['webhook'] ) ) {
            $service->registerExporter( new SiemWebhookExporter( $configs['webhook']));
        }
    }
}
