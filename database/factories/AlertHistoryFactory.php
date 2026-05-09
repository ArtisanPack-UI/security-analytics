<?php

declare(strict_types=1);

namespace ArtisanPackUI\SecurityAnalytics\Database\Factories;

use ArtisanPackUI\SecurityAnalytics\Models\AlertHistory;
use Illuminate\Database\Eloquent\Factories\Factory;

/**
 * @extends Factory<AlertHistory>
 */
class AlertHistoryFactory extends Factory
{
    protected $model = AlertHistory::class;

    public function definition(): array
    {
        return [
            'rule_id' => $this->faker->randomNumber(3),
            'anomaly_id' => $this->faker->randomNumber(3),
            'incident_id' => null,
            'severity' => $this->faker->randomElement([
                AlertHistory::SEVERITY_INFO,
                AlertHistory::SEVERITY_LOW,
                AlertHistory::SEVERITY_MEDIUM,
                AlertHistory::SEVERITY_HIGH,
                AlertHistory::SEVERITY_CRITICAL,
            ]),
            'channel' => $this->faker->randomElement(['email', 'slack', 'pagerduty', 'webhook']),
            'recipient' => $this->faker->safeEmail(),
            'status' => AlertHistory::STATUS_PENDING,
            'message' => $this->faker->sentence(),
            'sent_at' => null,
            'acknowledged_at' => null,
            'acknowledged_by' => null,
            'error_message' => null,
        ];
    }

    public function sent(): static
    {
        return $this->state(fn (array $attributes) => [
            'status' => AlertHistory::STATUS_SENT,
            'sent_at' => now(),
        ]);
    }

    public function failed(): static
    {
        return $this->state(fn (array $attributes) => [
            'status' => AlertHistory::STATUS_FAILED,
            'error_message' => $this->faker->sentence(),
        ]);
    }

    public function acknowledged(): static
    {
        return $this->state(fn (array $attributes) => [
            'status' => AlertHistory::STATUS_ACKNOWLEDGED,
            'sent_at' => now()->subMinutes(30),
            'acknowledged_at' => now(),
            'acknowledged_by' => $this->faker->randomNumber(5),
        ]);
    }
}
