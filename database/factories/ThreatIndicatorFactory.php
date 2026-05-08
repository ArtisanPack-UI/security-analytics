<?php

declare(strict_types=1);

namespace ArtisanPackUI\SecurityAnalytics\Database\Factories;

use ArtisanPackUI\SecurityAnalytics\Models\ThreatIndicator;
use Illuminate\Database\Eloquent\Factories\Factory;

/**
 * @extends Factory<ThreatIndicator>
 */
class ThreatIndicatorFactory extends Factory
{
    protected $model = ThreatIndicator::class;

    public function definition(): array
    {
        $type = $this->faker->randomElement([
            ThreatIndicator::TYPE_IP,
            ThreatIndicator::TYPE_DOMAIN,
            ThreatIndicator::TYPE_URL,
            ThreatIndicator::TYPE_HASH,
            ThreatIndicator::TYPE_EMAIL,
        ]);

        return [
            'type' => $type,
            'value' => $this->generateValueForType($type),
            'source' => $this->faker->randomElement(['abuseipdb', 'virustotal', 'internal', 'custom_feed', 'manual']),
            'threat_type' => $this->faker->randomElement([
                ThreatIndicator::THREAT_MALWARE,
                ThreatIndicator::THREAT_PHISHING,
                ThreatIndicator::THREAT_SPAM,
                ThreatIndicator::THREAT_BRUTEFORCE,
                ThreatIndicator::THREAT_BOTNET,
                ThreatIndicator::THREAT_PROXY,
                ThreatIndicator::THREAT_TOR,
                ThreatIndicator::THREAT_VPN,
            ]),
            'severity' => $this->faker->randomElement([
                ThreatIndicator::SEVERITY_INFO,
                ThreatIndicator::SEVERITY_LOW,
                ThreatIndicator::SEVERITY_MEDIUM,
                ThreatIndicator::SEVERITY_HIGH,
                ThreatIndicator::SEVERITY_CRITICAL,
            ]),
            'confidence' => $this->faker->numberBetween(10, 100),
            'first_seen_at' => $this->faker->dateTimeBetween('-90 days', '-7 days'),
            'last_seen_at' => $this->faker->dateTimeBetween('-7 days', 'now'),
            'expires_at' => $this->faker->optional(0.7)->dateTimeBetween('now', '+30 days'),
            'metadata' => [
                'reports' => $this->faker->numberBetween(1, 100),
                'categories' => $this->faker->randomElements(['malware', 'spam', 'phishing', 'botnet'], 2),
            ],
        ];
    }

    protected function generateValueForType(string $type): string
    {
        return match ($type) {
            ThreatIndicator::TYPE_IP => $this->faker->ipv4(),
            ThreatIndicator::TYPE_DOMAIN => $this->faker->domainName(),
            ThreatIndicator::TYPE_URL => $this->faker->url(),
            ThreatIndicator::TYPE_HASH => $this->faker->sha256(),
            ThreatIndicator::TYPE_EMAIL => $this->faker->safeEmail(),
            default => $this->faker->word(),
        };
    }

    public function ip(): static
    {
        return $this->state(fn (array $attributes) => [
            'type' => ThreatIndicator::TYPE_IP,
            'value' => $this->faker->ipv4(),
        ]);
    }

    public function domain(): static
    {
        return $this->state(fn (array $attributes) => [
            'type' => ThreatIndicator::TYPE_DOMAIN,
            'value' => $this->faker->domainName(),
        ]);
    }

    public function url(): static
    {
        return $this->state(fn (array $attributes) => [
            'type' => ThreatIndicator::TYPE_URL,
            'value' => $this->faker->url(),
        ]);
    }

    public function hash(): static
    {
        return $this->state(fn (array $attributes) => [
            'type' => ThreatIndicator::TYPE_HASH,
            'value' => $this->faker->sha256(),
        ]);
    }

    public function email(): static
    {
        return $this->state(fn (array $attributes) => [
            'type' => ThreatIndicator::TYPE_EMAIL,
            'value' => $this->faker->safeEmail(),
        ]);
    }

    public function malware(): static
    {
        return $this->state(fn (array $attributes) => [
            'threat_type' => ThreatIndicator::THREAT_MALWARE,
            'severity' => ThreatIndicator::SEVERITY_HIGH,
        ]);
    }

    public function phishing(): static
    {
        return $this->state(fn (array $attributes) => [
            'threat_type' => ThreatIndicator::THREAT_PHISHING,
            'severity' => ThreatIndicator::SEVERITY_HIGH,
        ]);
    }

    public function bruteforce(): static
    {
        return $this->state(fn (array $attributes) => [
            'threat_type' => ThreatIndicator::THREAT_BRUTEFORCE,
            'type' => ThreatIndicator::TYPE_IP,
            'value' => $this->faker->ipv4(),
        ]);
    }

    public function highConfidence(): static
    {
        return $this->state(fn (array $attributes) => [
            'confidence' => $this->faker->numberBetween(80, 100),
        ]);
    }

    public function critical(): static
    {
        return $this->state(fn (array $attributes) => [
            'severity' => ThreatIndicator::SEVERITY_CRITICAL,
            'confidence' => $this->faker->numberBetween(90, 100),
        ]);
    }

    public function expired(): static
    {
        return $this->state(fn (array $attributes) => [
            'expires_at' => $this->faker->dateTimeBetween('-30 days', '-1 day'),
        ]);
    }

    public function active(): static
    {
        return $this->state(fn (array $attributes) => [
            'expires_at' => $this->faker->optional(0.5)->dateTimeBetween('+7 days', '+60 days'),
        ]);
    }

    public function fromSource(string $source): static
    {
        return $this->state(fn (array $attributes) => [
            'source' => $source,
        ]);
    }
}
