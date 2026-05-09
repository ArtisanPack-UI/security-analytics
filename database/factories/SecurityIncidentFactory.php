<?php

declare(strict_types=1);

namespace ArtisanPackUI\SecurityAnalytics\Database\Factories;

use ArtisanPackUI\SecurityAnalytics\Models\Anomaly;
use ArtisanPackUI\SecurityAnalytics\Models\SecurityIncident;
use Illuminate\Database\Eloquent\Factories\Factory;

/**
 * @extends Factory<SecurityIncident>
 */
class SecurityIncidentFactory extends Factory
{
    protected $model = SecurityIncident::class;

    public function definition(): array
    {
        $status = $this->faker->randomElement([
            SecurityIncident::STATUS_OPEN,
            SecurityIncident::STATUS_INVESTIGATING,
            SecurityIncident::STATUS_CONTAINED,
            SecurityIncident::STATUS_RESOLVED,
            SecurityIncident::STATUS_CLOSED,
        ]);

        return [
            'incident_number' => null, // Will be auto-generated
            'title' => $this->faker->sentence(4),
            'description' => $this->faker->paragraph(),
            'severity' => $this->faker->randomElement([
                SecurityIncident::SEVERITY_INFO,
                SecurityIncident::SEVERITY_LOW,
                SecurityIncident::SEVERITY_MEDIUM,
                SecurityIncident::SEVERITY_HIGH,
                SecurityIncident::SEVERITY_CRITICAL,
            ]),
            'status' => $status,
            'category' => $this->faker->randomElement([
                Anomaly::CATEGORY_AUTHENTICATION,
                Anomaly::CATEGORY_BEHAVIORAL,
                Anomaly::CATEGORY_THREAT,
                Anomaly::CATEGORY_ACCESS,
            ]),
            'source_anomaly_id' => null,
            'affected_users' => $this->faker->optional(0.7)->randomElements(
                range(1, 100),
                $this->faker->numberBetween(1, 5)
            ),
            'affected_ips' => $this->faker->optional(0.7)->randomElements(
                array_map(fn () => $this->faker->ipv4(), range(1, 10)),
                $this->faker->numberBetween(1, 3)
            ),
            'actions_taken' => $this->generateActionsForStatus($status),
            'assigned_to' => $this->faker->optional(0.6)->randomNumber(5),
            'opened_at' => $this->faker->dateTimeBetween('-30 days', '-1 day'),
            'contained_at' => in_array($status, [SecurityIncident::STATUS_CONTAINED, SecurityIncident::STATUS_RESOLVED, SecurityIncident::STATUS_CLOSED])
                ? $this->faker->dateTimeBetween('-20 days', '-12 hours')
                : null,
            'resolved_at' => in_array($status, [SecurityIncident::STATUS_RESOLVED, SecurityIncident::STATUS_CLOSED])
                ? $this->faker->dateTimeBetween('-10 days', '-6 hours')
                : null,
            'closed_at' => $status === SecurityIncident::STATUS_CLOSED
                ? $this->faker->dateTimeBetween('-5 days', 'now')
                : null,
            'root_cause' => in_array($status, [SecurityIncident::STATUS_RESOLVED, SecurityIncident::STATUS_CLOSED])
                ? $this->faker->sentence()
                : null,
            'lessons_learned' => $status === SecurityIncident::STATUS_CLOSED
                ? $this->faker->paragraph()
                : null,
        ];
    }

    protected function generateActionsForStatus(string $status): array
    {
        $actions = [];

        $actions[] = [
            'action' => 'Incident opened',
            'details' => ['source' => 'anomaly_detection'],
            'timestamp' => now()->subDays(5)->toIso8601String(),
        ];

        if (in_array($status, [SecurityIncident::STATUS_INVESTIGATING, SecurityIncident::STATUS_CONTAINED, SecurityIncident::STATUS_RESOLVED, SecurityIncident::STATUS_CLOSED])) {
            $actions[] = [
                'action' => 'Investigation started',
                'details' => ['assigned_to' => $this->faker->name()],
                'timestamp' => now()->subDays(4)->toIso8601String(),
            ];
        }

        if (in_array($status, [SecurityIncident::STATUS_CONTAINED, SecurityIncident::STATUS_RESOLVED, SecurityIncident::STATUS_CLOSED])) {
            $actions[] = [
                'action' => 'Threat contained',
                'details' => ['method' => 'IP blocked and sessions terminated'],
                'timestamp' => now()->subDays(3)->toIso8601String(),
            ];
        }

        if (in_array($status, [SecurityIncident::STATUS_RESOLVED, SecurityIncident::STATUS_CLOSED])) {
            $actions[] = [
                'action' => 'Incident resolved',
                'details' => ['root_cause' => 'Identified and mitigated'],
                'timestamp' => now()->subDays(2)->toIso8601String(),
            ];
        }

        return $actions;
    }

    public function open(): static
    {
        return $this->state(fn (array $attributes) => [
            'status' => SecurityIncident::STATUS_OPEN,
            'contained_at' => null,
            'resolved_at' => null,
            'closed_at' => null,
            'root_cause' => null,
            'lessons_learned' => null,
            'actions_taken' => [
                [
                    'action' => 'Incident opened',
                    'details' => ['source' => 'anomaly_detection'],
                    'timestamp' => now()->toIso8601String(),
                ],
            ],
        ]);
    }

    public function investigating(): static
    {
        return $this->state(fn (array $attributes) => [
            'status' => SecurityIncident::STATUS_INVESTIGATING,
            'contained_at' => null,
            'resolved_at' => null,
            'closed_at' => null,
            'root_cause' => null,
            'lessons_learned' => null,
            'actions_taken' => [
                [
                    'action' => 'Incident opened',
                    'details' => ['source' => 'anomaly_detection'],
                    'timestamp' => now()->subDays(1)->toIso8601String(),
                ],
                [
                    'action' => 'Investigation started',
                    'details' => ['assigned_to' => $this->faker->name()],
                    'timestamp' => now()->toIso8601String(),
                ],
            ],
        ]);
    }

    public function contained(): static
    {
        return $this->state(fn (array $attributes) => [
            'status' => SecurityIncident::STATUS_CONTAINED,
            'contained_at' => $this->faker->dateTimeBetween('-3 days', 'now'),
            'resolved_at' => null,
            'closed_at' => null,
            'root_cause' => null,
            'lessons_learned' => null,
            'actions_taken' => [
                [
                    'action' => 'Incident opened',
                    'details' => ['source' => 'anomaly_detection'],
                    'timestamp' => now()->subDays(3)->toIso8601String(),
                ],
                [
                    'action' => 'Investigation started',
                    'details' => ['assigned_to' => $this->faker->name()],
                    'timestamp' => now()->subDays(2)->toIso8601String(),
                ],
                [
                    'action' => 'Threat contained',
                    'details' => ['method' => 'IP blocked and sessions terminated'],
                    'timestamp' => now()->toIso8601String(),
                ],
            ],
        ]);
    }

    public function resolved(): static
    {
        return $this->state(fn (array $attributes) => [
            'status' => SecurityIncident::STATUS_RESOLVED,
            'contained_at' => $this->faker->dateTimeBetween('-5 days', '-3 days'),
            'resolved_at' => $this->faker->dateTimeBetween('-2 days', 'now'),
            'closed_at' => null,
            'root_cause' => $this->faker->sentence(),
            'lessons_learned' => null,
            'actions_taken' => [
                [
                    'action' => 'Incident opened',
                    'details' => ['source' => 'anomaly_detection'],
                    'timestamp' => now()->subDays(5)->toIso8601String(),
                ],
                [
                    'action' => 'Investigation started',
                    'details' => ['assigned_to' => $this->faker->name()],
                    'timestamp' => now()->subDays(4)->toIso8601String(),
                ],
                [
                    'action' => 'Threat contained',
                    'details' => ['method' => 'IP blocked and sessions terminated'],
                    'timestamp' => now()->subDays(3)->toIso8601String(),
                ],
                [
                    'action' => 'Incident resolved',
                    'details' => ['root_cause' => 'Identified and mitigated'],
                    'timestamp' => now()->toIso8601String(),
                ],
            ],
        ]);
    }

    public function closed(): static
    {
        return $this->state(fn (array $attributes) => [
            'status' => SecurityIncident::STATUS_CLOSED,
            'contained_at' => $this->faker->dateTimeBetween('-10 days', '-7 days'),
            'resolved_at' => $this->faker->dateTimeBetween('-6 days', '-3 days'),
            'closed_at' => $this->faker->dateTimeBetween('-2 days', 'now'),
            'root_cause' => $this->faker->sentence(),
            'lessons_learned' => $this->faker->paragraph(),
            'actions_taken' => [
                [
                    'action' => 'Incident opened',
                    'details' => ['source' => 'anomaly_detection'],
                    'timestamp' => now()->subDays(10)->toIso8601String(),
                ],
                [
                    'action' => 'Investigation started',
                    'details' => ['assigned_to' => $this->faker->name()],
                    'timestamp' => now()->subDays(9)->toIso8601String(),
                ],
                [
                    'action' => 'Threat contained',
                    'details' => ['method' => 'IP blocked and sessions terminated'],
                    'timestamp' => now()->subDays(7)->toIso8601String(),
                ],
                [
                    'action' => 'Incident resolved',
                    'details' => ['root_cause' => 'Identified and mitigated'],
                    'timestamp' => now()->subDays(3)->toIso8601String(),
                ],
                [
                    'action' => 'Incident closed',
                    'details' => ['lessons_learned' => 'Documented and shared'],
                    'timestamp' => now()->toIso8601String(),
                ],
            ],
        ]);
    }

    public function critical(): static
    {
        return $this->state(fn (array $attributes) => [
            'severity' => SecurityIncident::SEVERITY_CRITICAL,
            'title' => 'Critical Security Incident: '.$this->faker->sentence(3),
        ]);
    }

    public function high(): static
    {
        return $this->state(fn (array $attributes) => [
            'severity' => SecurityIncident::SEVERITY_HIGH,
        ]);
    }

    public function assignedTo(int $userId): static
    {
        return $this->state(fn (array $attributes) => [
            'assigned_to' => $userId,
        ]);
    }

    public function unassigned(): static
    {
        return $this->state(fn (array $attributes) => [
            'assigned_to' => null,
        ]);
    }

    public function forAnomaly(Anomaly $anomaly): static
    {
        return $this->state(fn (array $attributes) => [
            'source_anomaly_id' => $anomaly->id,
            'category' => $anomaly->category,
            'severity' => $anomaly->severity,
            'title' => 'Incident from Anomaly: '.$anomaly->description,
        ]);
    }

    public function withAffectedUsers(array $userIds): static
    {
        return $this->state(fn (array $attributes) => [
            'affected_users' => $userIds,
        ]);
    }

    public function withAffectedIps(array $ips): static
    {
        return $this->state(fn (array $attributes) => [
            'affected_ips' => $ips,
        ]);
    }

    public function authentication(): static
    {
        return $this->state(fn (array $attributes) => [
            'category' => Anomaly::CATEGORY_AUTHENTICATION,
            'title' => 'Authentication Security Incident',
        ]);
    }

    public function threat(): static
    {
        return $this->state(fn (array $attributes) => [
            'category' => Anomaly::CATEGORY_THREAT,
            'title' => 'Threat Intelligence Incident',
        ]);
    }
}
