<?php

declare(strict_types=1);

namespace ArtisanPackUI\SecurityAnalytics\Database\Factories;

use ArtisanPackUI\SecurityAnalytics\Models\SecurityMetric;
use Illuminate\Database\Eloquent\Factories\Factory;

/**
 * @extends Factory<SecurityMetric>
 */
class SecurityMetricFactory extends Factory
{
    protected $model = SecurityMetric::class;

    public function definition(): array
    {
        return [
            'category' => $this->faker->randomElement([
                SecurityMetric::CATEGORY_AUTHENTICATION,
                SecurityMetric::CATEGORY_AUTHORIZATION,
                SecurityMetric::CATEGORY_API,
                SecurityMetric::CATEGORY_APPLICATION,
                SecurityMetric::CATEGORY_SYSTEM,
                SecurityMetric::CATEGORY_THREAT,
                SecurityMetric::CATEGORY_PERFORMANCE,
            ]),
            'metric_name' => $this->faker->randomElement([
                'login_attempts',
                'failed_logins',
                'successful_logins',
                'api_requests',
                'blocked_requests',
                'threats_detected',
                'response_time',
                'error_rate',
            ]),
            'metric_type' => $this->faker->randomElement([
                SecurityMetric::TYPE_COUNTER,
                SecurityMetric::TYPE_GAUGE,
                SecurityMetric::TYPE_TIMING,
                SecurityMetric::TYPE_HISTOGRAM,
            ]),
            'value' => $this->faker->randomFloat(6, 0, 10000),
            'tags' => [
                'environment' => $this->faker->randomElement(['production', 'staging', 'development']),
                'host' => $this->faker->domainName(),
            ],
            'recorded_at' => $this->faker->dateTimeBetween('-24 hours', 'now'),
        ];
    }

    public function counter(): static
    {
        return $this->state(fn (array $attributes) => [
            'metric_type' => SecurityMetric::TYPE_COUNTER,
            'value' => $this->faker->numberBetween(1, 1000),
        ]);
    }

    public function gauge(): static
    {
        return $this->state(fn (array $attributes) => [
            'metric_type' => SecurityMetric::TYPE_GAUGE,
            'value' => $this->faker->randomFloat(2, 0, 100),
        ]);
    }

    public function timing(): static
    {
        return $this->state(fn (array $attributes) => [
            'metric_type' => SecurityMetric::TYPE_TIMING,
            'metric_name' => 'response_time',
            'value' => $this->faker->randomFloat(3, 10, 5000),
        ]);
    }

    public function authentication(): static
    {
        return $this->state(fn (array $attributes) => [
            'category' => SecurityMetric::CATEGORY_AUTHENTICATION,
            'metric_name' => $this->faker->randomElement(['login_attempts', 'failed_logins', 'successful_logins', 'mfa_challenges']),
        ]);
    }

    public function threat(): static
    {
        return $this->state(fn (array $attributes) => [
            'category' => SecurityMetric::CATEGORY_THREAT,
            'metric_name' => $this->faker->randomElement(['threats_detected', 'blocked_ips', 'suspicious_activities']),
        ]);
    }

    public function api(): static
    {
        return $this->state(fn (array $attributes) => [
            'category' => SecurityMetric::CATEGORY_API,
            'metric_name' => $this->faker->randomElement(['api_requests', 'rate_limited', 'unauthorized_attempts']),
        ]);
    }

    public function withTags(array $tags): static
    {
        return $this->state(fn (array $attributes) => [
            'tags' => array_merge($attributes['tags'] ?? [], $tags),
        ]);
    }

    public function recentlyRecorded(): static
    {
        return $this->state(fn (array $attributes) => [
            'recorded_at' => $this->faker->dateTimeBetween('-1 hour', 'now'),
        ]);
    }
}
