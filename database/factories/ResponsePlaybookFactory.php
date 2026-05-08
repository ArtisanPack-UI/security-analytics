<?php

declare(strict_types=1);

namespace ArtisanPackUI\SecurityAnalytics\Database\Factories;

use ArtisanPackUI\SecurityAnalytics\Models\Anomaly;
use ArtisanPackUI\SecurityAnalytics\Models\ResponsePlaybook;
use Illuminate\Database\Eloquent\Factories\Factory;

/**
 * @extends Factory<ResponsePlaybook>
 */
class ResponsePlaybookFactory extends Factory
{
    protected $model = ResponsePlaybook::class;

    public function definition(): array
    {
        return [
            'name' => $this->faker->words(3, true).' Response',
            'description' => $this->faker->sentence(),
            'trigger_conditions' => [
                'severity' => $this->faker->randomElement([
                    Anomaly::SEVERITY_MEDIUM,
                    Anomaly::SEVERITY_HIGH,
                    Anomaly::SEVERITY_CRITICAL,
                ]),
            ],
            'actions' => [
                ['action' => 'notify_security', 'priority' => 'high'],
                ['action' => 'enable_enhanced_logging', 'duration_hours' => 24],
            ],
            'is_active' => true,
            'requires_approval' => false,
            'cooldown_minutes' => $this->faker->randomElement([0, 15, 30, 60]),
        ];
    }

    public function active(): static
    {
        return $this->state(fn (array $attributes) => [
            'is_active' => true,
        ]);
    }

    public function inactive(): static
    {
        return $this->state(fn (array $attributes) => [
            'is_active' => false,
        ]);
    }

    public function requiresApproval(): static
    {
        return $this->state(fn (array $attributes) => [
            'requires_approval' => true,
        ]);
    }

    public function automatic(): static
    {
        return $this->state(fn (array $attributes) => [
            'requires_approval' => false,
        ]);
    }

    public function withCooldown(int $minutes): static
    {
        return $this->state(fn (array $attributes) => [
            'cooldown_minutes' => $minutes,
        ]);
    }

    public function bruteForceResponse(): static
    {
        return $this->state(fn (array $attributes) => [
            'name' => 'Brute Force Response',
            'description' => 'Automatic response to brute force attacks',
            'trigger_conditions' => [
                'category' => Anomaly::CATEGORY_AUTHENTICATION,
                'severity' => [Anomaly::SEVERITY_HIGH, Anomaly::SEVERITY_CRITICAL],
            ],
            'actions' => [
                ['action' => 'rate_limit_ip', 'max_attempts' => 5, 'decay_minutes' => 60],
                ['action' => 'notify_security', 'channels' => ['email', 'slack']],
                ['action' => 'enable_enhanced_logging', 'duration_hours' => 24],
            ],
            'is_active' => true,
            'requires_approval' => false,
            'cooldown_minutes' => 30,
        ]);
    }

    public function accountCompromiseResponse(): static
    {
        return $this->state(fn (array $attributes) => [
            'name' => 'Account Compromise Response',
            'description' => 'Response to suspected account compromise',
            'trigger_conditions' => [
                'category' => Anomaly::CATEGORY_BEHAVIORAL,
                'severity' => Anomaly::SEVERITY_CRITICAL,
            ],
            'actions' => [
                ['action' => 'lock_account', 'duration_hours' => 24],
                ['action' => 'terminate_session', 'terminate_all' => true],
                ['action' => 'force_password_reset', 'send_email' => true],
                ['action' => 'notify_security', 'channels' => ['email', 'slack', 'pagerduty']],
            ],
            'is_active' => true,
            'requires_approval' => true,
            'cooldown_minutes' => 60,
        ]);
    }

    public function threatResponse(): static
    {
        return $this->state(fn (array $attributes) => [
            'name' => 'Threat Intelligence Response',
            'description' => 'Response to known threat indicators',
            'trigger_conditions' => [
                'category' => Anomaly::CATEGORY_THREAT,
            ],
            'actions' => [
                ['action' => 'block_ip', 'duration_hours' => 48],
                ['action' => 'notify_security', 'channels' => ['email']],
                ['action' => 'create_incident', 'severity' => 'high'],
            ],
            'is_active' => true,
            'requires_approval' => false,
            'cooldown_minutes' => 0,
        ]);
    }

    public function suspiciousAccessResponse(): static
    {
        return $this->state(fn (array $attributes) => [
            'name' => 'Suspicious Access Response',
            'description' => 'Response to unusual access patterns',
            'trigger_conditions' => [
                'category' => Anomaly::CATEGORY_ACCESS,
                'severity' => [Anomaly::SEVERITY_MEDIUM, Anomaly::SEVERITY_HIGH],
            ],
            'actions' => [
                ['action' => 'enable_enhanced_logging', 'duration_hours' => 48],
                ['action' => 'notify_security', 'channels' => ['email']],
            ],
            'is_active' => true,
            'requires_approval' => false,
            'cooldown_minutes' => 15,
        ]);
    }
}
