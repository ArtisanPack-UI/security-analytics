<?php

declare( strict_types=1 );

namespace Tests\Unit\Analytics;

use ArtisanPackUI\SecurityAnalytics\Analytics\ThreatIntelligence\Contracts\ThreatIntelProviderInterface;
use ArtisanPackUI\SecurityAnalytics\Analytics\ThreatIntelligence\ThreatIntelligenceService;
use ArtisanPackUI\SecurityAnalytics\Models\ThreatIndicator;

class ThreatIntelligenceServiceTest extends AnalyticsTestCase
{
    protected ThreatIntelligenceService $service;

    protected function setUp(): void
    {
        parent::setUp();
        $this->service = new ThreatIntelligenceService( [
            'enabled'   => true,
            'cache_ttl' => 60,
        ] );
    }

    public function test_it_registers_custom_provider(): void
    {
        $provider = $this->createMockProvider( 'test_provider' );

        $this->service->registerProvider( $provider );

        $this->assertNotNull( $this->service->getProvider( 'test_provider' ) );
    }

    public function test_it_returns_null_for_unknown_provider(): void
    {
        $this->assertNull( $this->service->getProvider( 'nonexistent' ) );
    }

    public function test_it_gets_enabled_providers(): void
    {
        $enabledProvider  = $this->createMockProvider( 'enabled', true );
        $disabledProvider = $this->createMockProvider( 'disabled', false );

        $this->service->registerProvider( $enabledProvider );
        $this->service->registerProvider( $disabledProvider );

        $enabled = $this->service->getEnabledProviders();

        $this->assertCount( 1, $enabled );
        $this->assertArrayHasKey( 'enabled', $enabled );
    }

    public function test_it_checks_local_indicator_first(): void
    {
        // Create a local threat indicator
        ThreatIndicator::create( [
            'type'          => ThreatIndicator::TYPE_IP,
            'value'         => '192.168.1.100',
            'source'        => 'internal',
            'threat_type'   => ThreatIndicator::THREAT_BRUTEFORCE,
            'confidence'    => 85,
            'first_seen_at' => now()->subDays( 5 ),
            'last_seen_at'  => now(),
            'expires_at'    => now()->addDays( 7 ),
        ] );

        $result = $this->service->checkIp( '192.168.1.100' );

        $this->assertTrue( $result['is_malicious'] );
        $this->assertEquals( 85, $result['confidence'] );
        $this->assertEquals( 'local_database', $result['source'] );
    }

    public function test_it_returns_clean_result_for_unknown_ip(): void
    {
        $result = $this->service->checkIp( '10.0.0.1' );

        $this->assertFalse( $result['is_malicious'] );
        $this->assertEquals( 0, $result['confidence'] );
        $this->assertEquals( 'none', $result['threat_level'] );
    }

    public function test_it_aggregates_results_from_multiple_providers(): void
    {
        $provider1 = $this->createMockProvider( 'provider1', true, [
            'is_malicious' => true,
            'confidence'   => 80,
            'provider'     => 'provider1',
            'categories'   => ['malware'],
        ] );

        $provider2 = $this->createMockProvider( 'provider2', true, [
            'is_malicious' => true,
            'confidence'   => 60,
            'provider'     => 'provider2',
            'categories'   => ['spam'],
        ] );

        $this->service->registerProvider( $provider1 );
        $this->service->registerProvider( $provider2 );

        // The IP will be checked against external providers
        $result = $this->service->checkIp( '203.0.113.50' );

        $this->assertArrayHasKey( 'providers', $result );
    }

    public function test_should_block_ip_respects_threshold(): void
    {
        $service = new ThreatIntelligenceService( [
            'enabled'              => true,
            'auto_block_threshold' => 70,
        ] );

        // Create a high-confidence threat indicator
        ThreatIndicator::create( [
            'type'          => ThreatIndicator::TYPE_IP,
            'value'         => '192.168.1.200',
            'source'        => 'internal',
            'threat_type'   => ThreatIndicator::THREAT_BRUTEFORCE,
            'confidence'    => 85,
            'first_seen_at' => now(),
            'last_seen_at'  => now(),
            'expires_at'    => now()->addDays( 7 ),
        ] );

        $this->assertTrue( $service->shouldBlockIp( '192.168.1.200' ) );
    }

    public function test_should_not_block_clean_ip(): void
    {
        $service = new ThreatIntelligenceService( [
            'enabled'              => true,
            'auto_block_threshold' => 70,
        ] );

        $this->assertFalse( $service->shouldBlockIp( '10.0.0.1' ) );
    }

    public function test_it_gets_ip_reputation(): void
    {
        ThreatIndicator::create( [
            'type'          => ThreatIndicator::TYPE_IP,
            'value'         => '192.168.1.150',
            'source'        => 'internal',
            'threat_type'   => ThreatIndicator::THREAT_SPAM,
            'confidence'    => 45,
            'first_seen_at' => now(),
            'last_seen_at'  => now(),
            'expires_at'    => now()->addDays( 7 ),
        ] );

        $reputation = $this->service->getIpReputation( '192.168.1.150' );

        $this->assertEquals( 45, $reputation );
    }

    public function test_it_imports_indicators(): void
    {
        $indicators = [
            ['type' => 'ip', 'value' => '1.2.3.4', 'threat_type' => 'malware', 'confidence' => 90],
            ['type' => 'domain', 'value' => 'bad-domain.com', 'threat_type' => 'phishing', 'confidence' => 85],
            ['type' => 'hash', 'value' => 'abc123def456', 'threat_type' => 'malware', 'confidence' => 95],
        ];

        $imported = $this->service->importIndicators( $indicators, 'test_feed' );

        $this->assertEquals( 3, $imported );
        $this->assertEquals( 3, ThreatIndicator::count() );
    }

    public function test_it_gets_statistics(): void
    {
        ThreatIndicator::factory()->count( 5 )->ip()->create();
        ThreatIndicator::factory()->count( 3 )->domain()->create();
        ThreatIndicator::factory()->count( 2 )->expired()->create();

        $stats = $this->service->getStatistics();

        $this->assertEquals( 10, $stats['total_indicators'] );
        $this->assertArrayHasKey( 'by_type', $stats );
        $this->assertArrayHasKey( 'by_threat_type', $stats );
        $this->assertArrayHasKey( 'by_source', $stats );
    }

    public function test_it_cleans_up_expired_indicators(): void
    {
        ThreatIndicator::factory()->count( 3 )->active()->create();
        ThreatIndicator::factory()->count( 2 )->expired()->create();

        $deleted = $this->service->cleanupExpired();

        $this->assertEquals( 2, $deleted );
        $this->assertEquals( 3, ThreatIndicator::count() );
    }

    public function test_it_determines_correct_threat_level(): void
    {
        $indicatorData = [
            ['confidence' => 85, 'expected' => 'critical'],
            ['confidence' => 65, 'expected' => 'high'],
            ['confidence' => 45, 'expected' => 'medium'],
            ['confidence' => 25, 'expected' => 'low'],
            ['confidence' => 10, 'expected' => 'none'],
        ];

        foreach ( $indicatorData as $data ) {
            ThreatIndicator::create( [
                'type'          => ThreatIndicator::TYPE_IP,
                'value'         => '10.0.0.' . $data['confidence'],
                'source'        => 'test',
                'threat_type'   => 'malware',
                'confidence'    => $data['confidence'],
                'first_seen_at' => now(),
                'last_seen_at'  => now(),
                'expires_at'    => now()->addDays( 7 ),
            ] );

            $result = $this->service->checkIp( '10.0.0.' . $data['confidence'] );
            $this->assertEquals( $data['expected'], $result['threat_level'] );
        }
    }

    protected function createMockProvider( string $name, bool $enabled = true, ?array $checkResult = null ): ThreatIntelProviderInterface
    {
        return new class( $name, $enabled, $checkResult ) implements ThreatIntelProviderInterface {
            public function __construct(
                private string $name,
                private bool $enabled,
                private ?array $checkResult,
            ) {
            }

            public function getName(): string
            {
                return $this->name;
            }

            public function isEnabled(): bool
            {
                return $this->enabled;
            }

            public function getSupportedTypes(): array
            {
                return ['ip', 'domain', 'url', 'hash'];
            }

            public function checkIp( string $ip ): ?array
            {
                return $this->checkResult;
            }

            public function checkDomain( string $domain ): ?array
            {
                return $this->checkResult;
            }

            public function checkUrl( string $url ): ?array
            {
                return $this->checkResult;
            }

            public function checkHash( string $hash): ?array
            {
                return $this->checkResult;
            }

            public function getConfig(): array
            {
                return [];
            }
        };
    }
}
