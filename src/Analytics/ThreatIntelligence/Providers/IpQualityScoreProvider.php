<?php

/**
 * IpQualityScoreProvider threat intelligence provider.
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

class IpQualityScoreProvider extends AbstractProvider
{
    protected const BASE_URL = 'https://ipqualityscore.com/api/json';

    /**
     * {@inheritdoc}
     */
    public function getName(): string
    {
        return 'ipqualityscore';
    }

    /**
     * {@inheritdoc}
     */
    public function getSupportedTypes(): array
    {
        return ['ip', 'email', 'url'];
    }

    /**
     * {@inheritdoc}
     */
    public function checkIp( string $ip ): ?array
    {
        if ( ! $this->isEnabled() ) {
            return null;
        }

        $url = self::BASE_URL . "/ip/{$this->config['api_key']}/{$ip}";

        $response = $this->makeRequest( $url, 'GET', [
            'query' => [
                'strictness'                 => $this->config['strictness'],
                'allow_public_access_points' => $this->config['allow_public_access_points'] ? 'true' : 'false',
                'lighter_penalties'          => $this->config['lighter_penalties'] ? 'true' : 'false',
            ],
        ] );

        if ( ! $response || ! $response['success'] ) {
            return null;
        }

        $fraudScore = $response['fraud_score'] ?? 0;

        return [
            'provider'       => $this->getName(),
            'indicator'      => $ip,
            'indicator_type' => 'ip',
            'is_malicious'   => $fraudScore >= 75 || ( $response['proxy'] ?? false ) || ( $response['vpn'] ?? false ),
            'confidence'     => $fraudScore,
            'threat_level'   => $this->determineThreatLevel( $fraudScore ),
            'threat_type'    => $this->determineIPQSThreatType( $response ),
            'categories'     => $this->extractCategories( $response ),
            'country'        => $response['country_code'] ?? null,
            'city'           => $response['city'] ?? null,
            'isp'            => $response['ISP'] ?? null,
            'is_proxy'       => $response['proxy'] ?? false,
            'is_vpn'         => $response['vpn'] ?? false,
            'is_tor'         => $response['tor'] ?? false,
            'is_crawler'     => $response['is_crawler'] ?? false,
            'is_bot'         => $response['bot_status'] ?? false,
            'recent_abuse'   => $response['recent_abuse'] ?? false,
            'raw_data'       => $response,
        ];
    }

    /**
     * Check an email address.
     *
     * @return array<string, mixed>|null
     */
    public function checkEmail( string $email ): ?array
    {
        if ( ! $this->isEnabled() ) {
            return null;
        }

        $url = self::BASE_URL . "/email/{$this->config['api_key']}/{$email}";

        $response = $this->makeRequest( $url, 'GET', [
            'query' => [
                'strictness' => $this->config['strictness'],
            ],
        ] );

        if ( ! $response || ! $response['success'] ) {
            return null;
        }

        $fraudScore = $response['fraud_score'] ?? 0;

        return [
            'provider'          => $this->getName(),
            'indicator'         => $email,
            'indicator_type'    => 'email',
            'is_malicious'      => $fraudScore >= 75 || ( $response['disposable'] ?? false ) || ! ( $response['valid'] ?? true ),
            'confidence'        => $fraudScore,
            'threat_level'      => $this->determineThreatLevel( $fraudScore ),
            'threat_type'       => $this->determineEmailThreatType( $response ),
            'is_valid'          => $response['valid'] ?? false,
            'is_disposable'     => $response['disposable'] ?? false,
            'is_honeypot'       => $response['honeypot'] ?? false,
            'is_deliverable'    => ( $response['deliverability'] ?? '' ) === 'high',
            'domain_reputation' => $response['overall_score'] ?? null,
            'recent_abuse'      => $response['recent_abuse'] ?? false,
            'raw_data'          => $response,
        ];
    }

    /**
     * Check a URL.
     *
     * @return array<string, mixed>|null
     */
    public function checkUrl( string $url ): ?array
    {
        if ( ! $this->isEnabled() ) {
            return null;
        }

        $apiUrl = self::BASE_URL . "/url/{$this->config['api_key']}";

        $response = $this->makeRequest( $apiUrl, 'GET', [
            'query' => [
                'url'        => $url,
                'strictness' => $this->config['strictness'],
            ],
        ] );

        if ( ! $response || ! $response['success'] ) {
            return null;
        }

        $riskScore = $response['risk_score'] ?? 0;

        return [
            'provider'       => $this->getName(),
            'indicator'      => $url,
            'indicator_type' => 'url',
            'is_malicious'   => ( $response['unsafe'] ?? false ) || ( $response['phishing'] ?? false ) || ( $response['malware'] ?? false ),
            'confidence'     => $riskScore,
            'threat_level'   => $this->determineThreatLevel( $riskScore ),
            'threat_type'    => $this->determineUrlThreatType( $response ),
            'is_unsafe'      => $response['unsafe'] ?? false,
            'is_phishing'    => $response['phishing'] ?? false,
            'is_malware'     => $response['malware'] ?? false,
            'is_suspicious'  => $response['suspicious'] ?? false,
            'domain'         => $response['domain'] ?? null,
            'domain_age'     => $response['domain_age']['human'] ?? null,
            'raw_data'       => $response,
        ];
    }

    /**
     * {@inheritdoc}
     */
    protected function getDefaultConfig(): array
    {
        return [
            'enabled'                    => false,
            'api_key'                    => null,
            'strictness'                 => 1, // 0-3, higher = stricter
            'allow_public_access_points' => true,
            'lighter_penalties'          => false,
            'cache_ttl'                  => 60,
        ];
    }

    /**
     * {@inheritdoc}
     */
    protected function getHeaders(): array
    {
        return [
            'Accept' => 'application/json',
        ];
    }

    /**
     * Determine threat type for IP based on IPQS response.
     *
     * @param  array<string, mixed>  $response
     */
    protected function determineIPQSThreatType( array $response ): string
    {
        if ( $response['tor'] ?? false ) {
            return 'tor_node';
        }
        if ( $response['vpn'] ?? false ) {
            return 'vpn';
        }
        if ( $response['proxy'] ?? false ) {
            return 'proxy';
        }
        if ( $response['bot_status'] ?? false ) {
            return 'bot';
        }
        if ( $response['recent_abuse'] ?? false ) {
            return 'recent_abuse';
        }

        return 'suspicious';
    }

    /**
     * Determine threat type for email.
     *
     * @param  array<string, mixed>  $response
     */
    protected function determineEmailThreatType( array $response ): string
    {
        if ( $response['disposable'] ?? false ) {
            return 'disposable_email';
        }
        if ( $response['honeypot'] ?? false ) {
            return 'honeypot';
        }
        if ( ! ( $response['valid'] ?? true ) ) {
            return 'invalid_email';
        }
        if ( $response['recent_abuse'] ?? false ) {
            return 'abusive_email';
        }

        return 'suspicious_email';
    }

    /**
     * Determine threat type for URL.
     *
     * @param  array<string, mixed>  $response
     */
    protected function determineUrlThreatType( array $response ): string
    {
        if ( $response['phishing'] ?? false ) {
            return 'phishing';
        }
        if ( $response['malware'] ?? false ) {
            return 'malware';
        }
        if ( $response['suspicious'] ?? false ) {
            return 'suspicious_url';
        }

        return 'unsafe_url';
    }

    /**
     * Extract categories from response.
     *
     * @param  array<string, mixed>  $response
     *
     * @return array<int, string>
     */
    protected function extractCategories( array $response ): array
    {
        $categories = [];

        if ( $response['proxy'] ?? false ) {
            $categories[] = 'Proxy';
        }
        if ( $response['vpn'] ?? false ) {
            $categories[] = 'VPN';
        }
        if ( $response['tor'] ?? false ) {
            $categories[] = 'Tor';
        }
        if ( $response['is_crawler'] ?? false ) {
            $categories[] = 'Crawler';
        }
        if ( $response['bot_status'] ?? false ) {
            $categories[] = 'Bot';
        }
        if ( $response['recent_abuse'] ?? false ) {
            $categories[] = 'Recent Abuse';
        }

        return $categories;
    }
}
