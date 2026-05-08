<?php

declare( strict_types=1 );

namespace ArtisanPackUI\SecurityAnalytics\Analytics\ThreatIntelligence\Contracts;

interface ThreatIntelProviderInterface
{
    /**
     * Get the provider name.
     */
    public function getName(): string;

    /**
     * Check if the provider is enabled.
     */
    public function isEnabled(): bool;

    /**
     * Check an IP address for threats.
     *
     * @return array<string, mixed>|null
     */
    public function checkIp( string $ip ): ?array;

    /**
     * Check a domain for threats.
     *
     * @return array<string, mixed>|null
     */
    public function checkDomain( string $domain ): ?array;

    /**
     * Check a URL for threats.
     *
     * @return array<string, mixed>|null
     */
    public function checkUrl( string $url ): ?array;

    /**
     * Check a file hash for threats.
     *
     * @return array<string, mixed>|null
     */
    public function checkHash( string $hash ): ?array;

    /**
     * Get supported indicator types.
     *
     * @return array<int, string>
     */
    public function getSupportedTypes(): array;
}
