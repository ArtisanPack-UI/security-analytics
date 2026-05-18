<?php

/**
 * AbuseIPDBProvider threat intelligence provider.
 *
 * @package    ArtisanPack_UI
 * @subpackage SecurityAnalytics
 *
 * @author     Jacob Martella <support@artisanpackui.dev>
 *
 * @since      1.0.0
 */

declare( strict_types=1 );

namespace ArtisanPackUI\SecurityAnalytics\Analytics\ThreatIntelligence\Providers;

class AbuseIPDBProvider extends AbstractProvider
{
    protected const BASE_URL = 'https://api.abuseipdb.com/api/v2';

    /**
     * {@inheritdoc}
     */
    public function getName(): string
    {
        return 'abuseipdb';
    }

    /**
     * {@inheritdoc}
     */
    public function getSupportedTypes(): array
    {
        return ['ip'];
    }

    /**
     * {@inheritdoc}
     */
    public function checkIp( string $ip ): ?array
    {
        if ( ! $this->isEnabled() ) {
            return null;
        }

        $response = $this->makeRequest( self::BASE_URL . '/check', 'GET', [
            'query' => [
                'ipAddress'    => $ip,
                'maxAgeInDays' => $this->config['max_age_days'],
                'verbose'      => true,
            ],
        ] );

        if ( ! $response || ! isset( $response['data'] ) ) {
            return null;
        }

        $data = $response['data'];

        return [
            'provider'         => $this->getName(),
            'indicator'        => $ip,
            'indicator_type'   => 'ip',
            'is_malicious'     => $data['abuseConfidenceScore'] >= $this->config['min_confidence'],
            'confidence'       => $data['abuseConfidenceScore'],
            'threat_level'     => $this->determineThreatLevel( $data['abuseConfidenceScore'] ),
            'categories'       => $this->mapCategories( $data['reports'] ?? [] ),
            'country'          => $data['countryCode'] ?? null,
            'isp'              => $data['isp'] ?? null,
            'domain'           => $data['domain'] ?? null,
            'is_tor'           => $data['isTor'] ?? false,
            'total_reports'    => $data['totalReports'] ?? 0,
            'last_reported_at' => $data['lastReportedAt'] ?? null,
            'raw_data'         => $data,
        ];
    }

    /**
     * {@inheritdoc}
     */
    protected function getDefaultConfig(): array
    {
        return [
            'enabled'        => false,
            'api_key'        => null,
            'min_confidence' => 80,
            'max_age_days'   => 90,
            'cache_ttl'      => 60,
        ];
    }

    /**
     * {@inheritdoc}
     */
    protected function getHeaders(): array
    {
        return [
            'Accept' => 'application/json',
            'Key'    => $this->config['api_key'],
        ];
    }

    /**
     * Map AbuseIPDB category IDs to readable names.
     *
     * @param  array<int, array<string, mixed>>  $reports
     *
     * @return array<int, string>
     */
    protected function mapCategories( array $reports ): array
    {
        $categoryMap = [
            3  => 'Fraud Orders',
            4  => 'DDoS Attack',
            5  => 'FTP Brute-Force',
            6  => 'Ping of Death',
            7  => 'Phishing',
            8  => 'Fraud VoIP',
            9  => 'Open Proxy',
            10 => 'Web Spam',
            11 => 'Email Spam',
            12 => 'Blog Spam',
            13 => 'VPN IP',
            14 => 'Port Scan',
            15 => 'Hacking',
            16 => 'SQL Injection',
            17 => 'Spoofing',
            18 => 'Brute-Force',
            19 => 'Bad Web Bot',
            20 => 'Exploited Host',
            21 => 'Web App Attack',
            22 => 'SSH',
            23 => 'IoT Targeted',
        ];

        $categories = [];
        foreach ( $reports as $report ) {
            foreach ( $report['categories'] ?? [] as $categoryId ) {
                if ( isset( $categoryMap[ $categoryId ] ) && ! in_array( $categoryMap[ $categoryId ], $categories, true ) ) {
                    $categories[] = $categoryMap[ $categoryId ];
                }
            }
        }

        return $categories;
    }
}
