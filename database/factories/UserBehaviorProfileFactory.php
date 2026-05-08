<?php

declare(strict_types=1);

namespace ArtisanPackUI\SecurityAnalytics\Database\Factories;

use ArtisanPackUI\SecurityAnalytics\Models\UserBehaviorProfile;
use Illuminate\Database\Eloquent\Factories\Factory;

/**
 * @extends Factory<UserBehaviorProfile>
 */
class UserBehaviorProfileFactory extends Factory
{
    protected $model = UserBehaviorProfile::class;

    public function definition(): array
    {
        return [
            'user_id' => $this->faker->randomNumber(5),
            'profile_type' => $this->faker->randomElement([
                UserBehaviorProfile::TYPE_LOGIN,
                UserBehaviorProfile::TYPE_API_USAGE,
                UserBehaviorProfile::TYPE_RESOURCE_ACCESS,
                UserBehaviorProfile::TYPE_SESSION,
                UserBehaviorProfile::TYPE_GEOGRAPHIC,
            ]),
            'baseline_data' => $this->generateBaselineData(),
            'sample_count' => $this->faker->numberBetween(1, 200),
            'confidence_score' => $this->faker->randomFloat(2, 0, 100),
            'last_updated_at' => $this->faker->dateTimeBetween('-7 days', 'now'),
        ];
    }

    protected function generateBaselineData(): array
    {
        return [
            'average_sessions_per_day' => $this->faker->randomFloat(2, 1, 10),
            'typical_login_hours' => $this->faker->randomElements(range(6, 22), 8),
            'common_ips' => [$this->faker->ipv4(), $this->faker->ipv4()],
            'common_locations' => [
                ['country' => 'US', 'city' => $this->faker->city()],
            ],
            'typical_session_duration' => $this->faker->numberBetween(300, 7200),
            'common_user_agents' => [$this->faker->userAgent()],
        ];
    }

    public function loginProfile(): static
    {
        return $this->state(fn (array $attributes) => [
            'profile_type' => UserBehaviorProfile::TYPE_LOGIN,
            'baseline_data' => [
                'typical_login_hours' => $this->faker->randomElements(range(6, 22), 8),
                'average_logins_per_day' => $this->faker->randomFloat(2, 1, 5),
                'common_ips' => [$this->faker->ipv4(), $this->faker->ipv4()],
                'failed_login_rate' => $this->faker->randomFloat(4, 0, 0.1),
            ],
        ]);
    }

    public function apiUsageProfile(): static
    {
        return $this->state(fn (array $attributes) => [
            'profile_type' => UserBehaviorProfile::TYPE_API_USAGE,
            'baseline_data' => [
                'average_requests_per_hour' => $this->faker->numberBetween(10, 500),
                'typical_endpoints' => ['/api/users', '/api/data', '/api/reports'],
                'peak_hours' => $this->faker->randomElements(range(9, 17), 4),
                'error_rate' => $this->faker->randomFloat(4, 0, 0.05),
            ],
        ]);
    }

    public function geographicProfile(): static
    {
        return $this->state(fn (array $attributes) => [
            'profile_type' => UserBehaviorProfile::TYPE_GEOGRAPHIC,
            'baseline_data' => [
                'known_locations' => [
                    ['country' => 'US', 'city' => $this->faker->city(), 'lat' => $this->faker->latitude(), 'lon' => $this->faker->longitude()],
                    ['country' => 'US', 'city' => $this->faker->city(), 'lat' => $this->faker->latitude(), 'lon' => $this->faker->longitude()],
                ],
                'typical_countries' => ['US'],
                'max_travel_velocity' => 500, // km/h
            ],
        ]);
    }

    public function highConfidence(): static
    {
        return $this->state(fn (array $attributes) => [
            'sample_count' => $this->faker->numberBetween(100, 500),
            'confidence_score' => $this->faker->randomFloat(2, 80, 100),
        ]);
    }

    public function lowConfidence(): static
    {
        return $this->state(fn (array $attributes) => [
            'sample_count' => $this->faker->numberBetween(1, 10),
            'confidence_score' => $this->faker->randomFloat(2, 0, 30),
        ]);
    }

    public function forUser(int $userId): static
    {
        return $this->state(fn (array $attributes) => [
            'user_id' => $userId,
        ]);
    }

    public function needsUpdate(): static
    {
        return $this->state(fn (array $attributes) => [
            'last_updated_at' => $this->faker->dateTimeBetween('-30 days', '-2 days'),
        ]);
    }
}
