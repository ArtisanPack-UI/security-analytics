<?php

declare(strict_types=1);

namespace ArtisanPackUI\SecurityAnalytics\Database\Factories;

use ArtisanPackUI\SecurityAnalytics\Models\AlertRule;
use Illuminate\Database\Eloquent\Factories\Factory;

/**
 * @extends Factory<AlertRule>
 */
class AlertRuleFactory extends Factory
{
    protected $model = AlertRule::class;

    public function definition(): array
    {
        return [
            'name' => $this->faker->words(3, true),
            'description' => $this->faker->sentence(),
            'conditions' => [
                'severity' => ['high', 'critical'],
            ],
            'severity' => $this->faker->randomElement([
                AlertRule::SEVERITY_LOW,
                AlertRule::SEVERITY_MEDIUM,
                AlertRule::SEVERITY_HIGH,
                AlertRule::SEVERITY_CRITICAL,
            ]),
            'channels' => ['email'],
            'recipients' => [
                'email' => [$this->faker->safeEmail()],
            ],
            'is_active' => true,
            'cooldown_minutes' => 15,
            'escalation_policy' => null,
        ];
    }

    public function inactive(): static
    {
        return $this->state(fn (array $attributes) => [
            'is_active' => false,
        ]);
    }

    public function withEscalation(): static
    {
        return $this->state(fn (array $attributes) => [
            'escalation_policy' => [
                ['level' => 1, 'after_minutes' => 15, 'channels' => ['email']],
                ['level' => 2, 'after_minutes' => 30, 'channels' => ['email', 'slack']],
            ],
        ]);
    }
}
