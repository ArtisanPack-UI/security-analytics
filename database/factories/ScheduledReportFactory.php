<?php

declare(strict_types=1);

namespace ArtisanPackUI\SecurityAnalytics\Database\Factories;

use ArtisanPackUI\SecurityAnalytics\Models\ScheduledReport;
use Illuminate\Database\Eloquent\Factories\Factory;

/**
 * @extends Factory<ScheduledReport>
 */
class ScheduledReportFactory extends Factory
{
    protected $model = ScheduledReport::class;

    public function definition(): array
    {
        return [
            'report_type' => $this->faker->randomElement([
                ScheduledReport::TYPE_EXECUTIVE,
                ScheduledReport::TYPE_THREAT,
                ScheduledReport::TYPE_COMPLIANCE,
                ScheduledReport::TYPE_INCIDENT,
                ScheduledReport::TYPE_USER_ACTIVITY,
                ScheduledReport::TYPE_TREND,
            ]),
            'name' => $this->faker->words(3, true).' Report',
            'cron_expression' => $this->faker->randomElement([
                '@daily',
                '@weekly',
                '@monthly',
                '0 9 * * 1', // Monday at 9am
                '0 8 1 * *', // First of month at 8am
            ]),
            'recipients' => $this->faker->randomElements([
                $this->faker->safeEmail(),
                $this->faker->safeEmail(),
                $this->faker->safeEmail(),
            ], $this->faker->numberBetween(1, 3)),
            'options' => [
                'include_charts' => $this->faker->boolean(80),
                'date_range' => $this->faker->randomElement(['7d', '30d', '90d']),
                'sections' => $this->faker->randomElements(['summary', 'threats', 'incidents', 'metrics', 'recommendations'], 3),
            ],
            'format' => $this->faker->randomElement([
                ScheduledReport::FORMAT_PDF,
                ScheduledReport::FORMAT_HTML,
                ScheduledReport::FORMAT_CSV,
                ScheduledReport::FORMAT_JSON,
            ]),
            'is_active' => true,
            'last_run_at' => $this->faker->optional(0.7)->dateTimeBetween('-30 days', '-1 day'),
            'next_run_at' => $this->faker->optional(0.8)->dateTimeBetween('now', '+7 days'),
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

    public function due(): static
    {
        return $this->state(fn (array $attributes) => [
            'is_active' => true,
            'next_run_at' => $this->faker->dateTimeBetween('-1 hour', 'now'),
        ]);
    }

    public function daily(): static
    {
        return $this->state(fn (array $attributes) => [
            'cron_expression' => '@daily',
        ]);
    }

    public function weekly(): static
    {
        return $this->state(fn (array $attributes) => [
            'cron_expression' => '@weekly',
        ]);
    }

    public function monthly(): static
    {
        return $this->state(fn (array $attributes) => [
            'cron_expression' => '@monthly',
        ]);
    }

    public function pdf(): static
    {
        return $this->state(fn (array $attributes) => [
            'format' => ScheduledReport::FORMAT_PDF,
        ]);
    }

    public function html(): static
    {
        return $this->state(fn (array $attributes) => [
            'format' => ScheduledReport::FORMAT_HTML,
        ]);
    }

    public function csv(): static
    {
        return $this->state(fn (array $attributes) => [
            'format' => ScheduledReport::FORMAT_CSV,
        ]);
    }

    public function json(): static
    {
        return $this->state(fn (array $attributes) => [
            'format' => ScheduledReport::FORMAT_JSON,
        ]);
    }

    public function executiveSummary(): static
    {
        return $this->state(fn (array $attributes) => [
            'report_type' => ScheduledReport::TYPE_EXECUTIVE,
            'name' => 'Executive Security Summary',
            'options' => [
                'include_charts' => true,
                'date_range' => '30d',
                'sections' => ['summary', 'key_metrics', 'top_threats', 'recommendations'],
                'executive_format' => true,
            ],
        ]);
    }

    public function threatReport(): static
    {
        return $this->state(fn (array $attributes) => [
            'report_type' => ScheduledReport::TYPE_THREAT,
            'name' => 'Threat Intelligence Report',
            'options' => [
                'include_charts' => true,
                'date_range' => '7d',
                'sections' => ['threat_summary', 'indicators', 'geographic', 'trends'],
                'include_iocs' => true,
            ],
        ]);
    }

    public function complianceReport(): static
    {
        return $this->state(fn (array $attributes) => [
            'report_type' => ScheduledReport::TYPE_COMPLIANCE,
            'name' => 'Security Compliance Report',
            'options' => [
                'include_charts' => true,
                'date_range' => '30d',
                'sections' => ['compliance_status', 'audit_log', 'policy_violations', 'remediation'],
                'frameworks' => ['SOC2', 'ISO27001'],
            ],
        ]);
    }

    public function incidentReport(): static
    {
        return $this->state(fn (array $attributes) => [
            'report_type' => ScheduledReport::TYPE_INCIDENT,
            'name' => 'Security Incident Report',
            'options' => [
                'include_charts' => true,
                'date_range' => '30d',
                'sections' => ['incident_summary', 'timeline', 'response_metrics', 'lessons_learned'],
                'include_closed' => true,
            ],
        ]);
    }

    public function userActivityReport(): static
    {
        return $this->state(fn (array $attributes) => [
            'report_type' => ScheduledReport::TYPE_USER_ACTIVITY,
            'name' => 'User Activity Report',
            'options' => [
                'include_charts' => true,
                'date_range' => '7d',
                'sections' => ['login_activity', 'suspicious_behavior', 'access_patterns', 'anomalies'],
                'top_users_count' => 20,
            ],
        ]);
    }

    public function trendReport(): static
    {
        return $this->state(fn (array $attributes) => [
            'report_type' => ScheduledReport::TYPE_TREND,
            'name' => 'Security Trend Analysis',
            'options' => [
                'include_charts' => true,
                'date_range' => '90d',
                'sections' => ['trend_analysis', 'comparisons', 'forecasts', 'recommendations'],
                'comparison_period' => '90d',
            ],
        ]);
    }

    public function withRecipients(array $recipients): static
    {
        return $this->state(fn (array $attributes) => [
            'recipients' => $recipients,
        ]);
    }

    public function withOptions(array $options): static
    {
        return $this->state(fn (array $attributes) => [
            'options' => array_merge($attributes['options'] ?? [], $options),
        ]);
    }
}
