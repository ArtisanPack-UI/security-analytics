<?php

namespace Tests\Unit;

use ArtisanPackUI\SecurityAnalytics\Contracts\SecurityEventLoggerInterface;
use ArtisanPackUI\SecurityAnalytics\Models\SecurityEvent;
use ArtisanPackUI\SecurityAnalytics\Services\SecurityEventLogger;
use Illuminate\Support\Facades\Config;
use Orchestra\Testbench\TestCase;
use PHPUnit\Framework\Attributes\Test;

class SecurityEventLoggerTest extends TestCase
{
    public function setUp(): void
    {
        parent::setUp();
        $this->artisan( 'migrate', ['--database' => 'testbench'] )->run();
    }

    #[Test]
    public function it_can_log_a_security_event(): void
    {
        $logger = app( SecurityEventLoggerInterface::class );

        $event = $logger->log(
            SecurityEvent::TYPE_AUTHENTICATION,
            'login_success',
            ['user_id' => 1],
            SecurityEvent::SEVERITY_INFO,
        );

        $this->assertNotNull( $event );
        $this->assertDatabaseHas( 'security_events', [
            'event_type' => SecurityEvent::TYPE_AUTHENTICATION,
            'event_name' => 'login_success',
            'severity'   => SecurityEvent::SEVERITY_INFO,
        ] );
    }

    #[Test]
    public function it_can_log_authentication_events(): void
    {
        $logger = app( SecurityEventLoggerInterface::class );

        $event = $logger->authentication( 'login_failed', ['email' => 'test@example.com'] );

        $this->assertNotNull( $event );
        $this->assertEquals( SecurityEvent::TYPE_AUTHENTICATION, $event->event_type );
        $this->assertEquals( 'login_failed', $event->event_name );
    }

    #[Test]
    public function it_can_log_authorization_events(): void
    {
        $logger = app( SecurityEventLoggerInterface::class );

        $event = $logger->authorization( 'permission_denied', ['permission' => 'edit-articles'] );

        $this->assertNotNull( $event );
        $this->assertEquals( SecurityEvent::TYPE_AUTHORIZATION, $event->event_type );
        $this->assertEquals( 'permission_denied', $event->event_name );
        $this->assertEquals( SecurityEvent::SEVERITY_WARNING, $event->severity );
    }

    #[Test]
    public function it_can_log_api_access_events(): void
    {
        $logger = app( SecurityEventLoggerInterface::class );

        $event = $logger->apiAccess( 'token_created', ['token_name' => 'test-token'] );

        $this->assertNotNull( $event );
        $this->assertEquals( SecurityEvent::TYPE_API_ACCESS, $event->event_type );
    }

    #[Test]
    public function it_can_log_security_violation_events(): void
    {
        $logger = app( SecurityEventLoggerInterface::class );

        $event = $logger->securityViolation( 'csp_violation', ['directive' => 'script-src'] );

        $this->assertNotNull( $event );
        $this->assertEquals( SecurityEvent::TYPE_SECURITY_VIOLATION, $event->event_type );
        $this->assertEquals( SecurityEvent::SEVERITY_ERROR, $event->severity );
    }

    #[Test]
    public function it_can_log_role_change_events(): void
    {
        $logger = app( SecurityEventLoggerInterface::class );

        $event = $logger->roleChange( 'role_created', ['role_name' => 'admin'] );

        $this->assertNotNull( $event );
        $this->assertEquals( SecurityEvent::TYPE_ROLE_CHANGE, $event->event_type );
    }

    #[Test]
    public function it_can_log_permission_change_events(): void
    {
        $logger = app( SecurityEventLoggerInterface::class );

        $event = $logger->permissionChange( 'permission_created', ['permission_name' => 'edit-articles'] );

        $this->assertNotNull( $event );
        $this->assertEquals( SecurityEvent::TYPE_PERMISSION_CHANGE, $event->event_type );
    }

    #[Test]
    public function it_respects_enabled_config(): void
    {
        Config::set( 'artisanpack.security-analytics.enabled', false );

        $logger = new SecurityEventLogger();
        $event  = $logger->log( SecurityEvent::TYPE_AUTHENTICATION, 'test', [] );

        $this->assertNull( $event );
    }

    #[Test]
    public function it_respects_event_type_config(): void
    {
        Config::set( 'artisanpack.security-analytics.events.authentication.enabled', false );

        $logger = new SecurityEventLogger();
        $event  = $logger->authentication( 'login_success', [] );

        $this->assertNull( $event );
    }

    #[Test]
    public function it_can_get_recent_events(): void
    {
        $logger = app( SecurityEventLoggerInterface::class );

        $logger->authentication( 'login_success', [] );
        $logger->authentication( 'login_failed', [] );
        $logger->authorization( 'permission_denied', [] );

        $events = $logger->getRecentEvents( 10 );

        $this->assertCount( 3, $events );
    }

    #[Test]
    public function it_can_get_events_by_type(): void
    {
        $logger = app( SecurityEventLoggerInterface::class );

        $logger->authentication( 'login_success', [] );
        $logger->authentication( 'login_failed', [] );
        $logger->authorization( 'permission_denied', [] );

        $events = $logger->getEventsByType( SecurityEvent::TYPE_AUTHENTICATION, 10 );

        $this->assertCount( 2, $events );
    }

    #[Test]
    public function it_can_get_event_stats(): void
    {
        $logger = app( SecurityEventLoggerInterface::class );

        $logger->authentication( 'login_success', [] );
        $logger->authentication( 'login_failed', [] );
        $logger->authorization( 'permission_denied', [] );

        $stats = $logger->getEventStats( 1 );

        $this->assertEquals( 3, $stats['total'] );
        $this->assertArrayHasKey( 'byType', $stats );
        $this->assertArrayHasKey( 'bySeverity', $stats );
    }

    #[Test]
    public function it_can_prune_old_events(): void
    {
        $logger = app( SecurityEventLoggerInterface::class );

        // Create an old event - need to use DB query to set old timestamp
        $oldEventId = \Illuminate\Support\Facades\DB::table( 'security_events' )->insertGetId( [
            'event_type' => SecurityEvent::TYPE_AUTHENTICATION,
            'event_name' => 'old_event',
            'severity'   => SecurityEvent::SEVERITY_INFO,
            'ip_address' => '127.0.0.1',
            'created_at' => now()->subDays( 100 )->toDateTimeString(),
        ] );

        // Create a recent event
        $logger->authentication( 'recent_event', [] );

        $deleted = $logger->pruneOldEvents( 90 );

        $this->assertEquals( 1, $deleted );
        $this->assertDatabaseMissing( 'security_events', ['event_name' => 'old_event'] );
        $this->assertDatabaseHas( 'security_events', ['event_name' => 'recent_event'] );
    }

    #[Test]
    public function it_keeps_critical_events_when_pruning(): void
    {
        Config::set( 'artisanpack.security-analytics.retention.keepCritical', true );

        // Create an old critical event
        SecurityEvent::create( [
            'event_type' => SecurityEvent::TYPE_SECURITY_VIOLATION,
            'event_name' => 'critical_old_event',
            'severity'   => SecurityEvent::SEVERITY_CRITICAL,
            'ip_address' => '127.0.0.1',
            'created_at' => now()->subDays( 100 ),
        ] );

        $logger  = app( SecurityEventLoggerInterface::class );
        $deleted = $logger->pruneOldEvents( 90 );

        $this->assertEquals( 0, $deleted );
        $this->assertDatabaseHas( 'security_events', ['event_name' => 'critical_old_event'] );
    }

    protected function getPackageProviders( $app )
    {
        return [
            \ArtisanPackUI\SecurityAnalytics\SecurityAnalyticsServiceProvider::class,
        ];
    }

    protected function getEnvironmentSetUp( $app ): void
    {
        Config::set( 'artisanpack.security.enabled', false );
        Config::set( 'artisanpack.security-analytics.enabled', true );
        Config::set( 'artisanpack.security-analytics.storage.database', true );
        Config::set( 'database.default', 'testbench' );
        Config::set( 'database.connections.testbench', [
            'driver'   => 'sqlite',
            'database' => ':memory:',
            'prefix'   => '',
        ] );

        // Create users table for migrations that depend on it
        $app['db']->connection()->getSchemaBuilder()->create( 'users', function ( $table ): void {
            $table->increments( 'id' );
            $table->string( 'name' );
            $table->string( 'email' );
            $table->timestamps();
        } );
    }
}
