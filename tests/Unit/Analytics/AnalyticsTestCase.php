<?php

declare( strict_types=1 );

namespace Tests\Unit\Analytics;

use Illuminate\Foundation\Testing\RefreshDatabase;
use Orchestra\Testbench\TestCase;

abstract class AnalyticsTestCase extends TestCase
{
    use RefreshDatabase;

    protected function getPackageProviders( $app ): array
    {
        return [
            \ArtisanPackUI\SecurityAnalytics\SecurityAnalyticsServiceProvider::class,
        ];
    }

    protected function getEnvironmentSetUp( $app ): void
    {
        $app['config']->set( 'app.key', 'base64:' . base64_encode( random_bytes( 32 ) ) );
        $app['config']->set( 'database.default', 'testing' );
        $app['config']->set( 'database.connections.testing', [
            'driver'   => 'sqlite',
            'database' => ':memory:',
            'prefix'   => '',
        ] );
    }

    protected function defineDatabaseMigrations(): void
    {
        $this->loadMigrationsFrom( __DIR__ . '/../../../database/migrations' );
    }
}
