<?php

declare(strict_types=1);

namespace ArtisanPackUI\SecurityAnalytics\Database\Factories;

use ArtisanPackUI\SecurityAnalytics\Models\Anomaly;
use Illuminate\Database\Eloquent\Factories\Factory;

/**
 * @extends Factory<Anomaly>
 */
class AnomalyFactory extends Factory
{
    protected $model = Anomaly::class;

    public function definition(): array
    {
        return [
            'detector' => $this->faker->randomElement(['statistical', 'behavioral', 'rule_based']),
            'category' => $this->faker->randomElement([
                Anomaly::CATEGORY_AUTHENTICATION,
                Anomaly::CATEGORY_BEHAVIORAL,
                Anomaly::CATEGORY_THREAT,
                Anomaly::CATEGORY_ACCESS,
            ]),
            'description' => $this->faker->sentence(),
            'severity' => $this->faker->randomElement([
                Anomaly::SEVERITY_INFO,
                Anomaly::SEVERITY_LOW,
                Anomaly::SEVERITY_MEDIUM,
                Anomaly::SEVERITY_HIGH,
            ]),
            'score' => $this->faker->randomFloat(2, 0, 100),
            'ip_address' => $this->faker->ipv4(),
            'metadata' => [
                'ip' => $this->faker->ipv4(),
                'user_agent' => $this->faker->userAgent(),
            ],
            'user_id' => $this->faker->optional()->randomNumber(5),
            'detected_at' => $this->faker->dateTimeBetween('-7 days', 'now'),
            'resolved_at' => null,
            'resolved_by' => null,
            'resolution_notes' => null,
        ];
    }

    public function resolved(): static
    {
        return $this->state(fn (array $attributes) => [
            'resolved_at' => now(),
            'resolved_by' => $this->faker->randomNumber(5),
            'resolution_notes' => $this->faker->sentence(),
        ]);
    }

    public function critical(): static
    {
        return $this->state(fn (array $attributes) => [
            'severity' => Anomaly::SEVERITY_CRITICAL,
            'score' => $this->faker->randomFloat(2, 90, 100),
        ]);
    }

    public function forUser(int $userId): static
    {
        return $this->state(fn (array $attributes) => [
            'user_id' => $userId,
        ]);
    }
}
