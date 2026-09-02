<?php

declare( strict_types=1 );

namespace Tests\Unit\Analytics\Models;

use ArtisanPackUI\SecurityAnalytics\Models\AlertHistory;
use ArtisanPackUI\SecurityAnalytics\Models\AlertRule;
use Tests\Unit\Analytics\AnalyticsTestCase;

class AlertRuleModelTest extends AnalyticsTestCase
{
    public function test_it_can_create_alert_rule(): void
    {
        $rule = AlertRule::factory()->create( [
            'name'      => 'High severity anomalies',
            'is_active' => true,
        ] );

        $this->assertDatabaseHas( 'alert_rules', [
            'id'        => $rule->id,
            'name'      => 'High severity anomalies',
            'is_active' => true,
        ] );
    }

    public function test_it_casts_json_and_boolean_attributes(): void
    {
        $rule = AlertRule::factory()->create( [
            'conditions' => ['severity' => ['high', 'critical']],
            'channels'   => ['email', 'slack'],
            'is_active'  => true,
        ] );

        $this->assertIsArray( $rule->conditions );
        $this->assertIsArray( $rule->channels );
        $this->assertIsBool( $rule->is_active );
        $this->assertIsInt( $rule->cooldown_minutes );
    }

    public function test_it_matches_simple_equality_conditions(): void
    {
        $rule = AlertRule::factory()->create( [
            'conditions' => ['detector' => 'brute_force'],
        ] );

        $this->assertTrue( $rule->matchesConditions( ['detector' => 'brute_force'] ) );
        $this->assertFalse( $rule->matchesConditions( ['detector' => 'geo_velocity'] ) );
    }

    public function test_it_matches_in_array_conditions(): void
    {
        $rule = AlertRule::factory()->create( [
            'conditions' => ['severity' => ['high', 'critical']],
        ] );

        $this->assertTrue( $rule->matchesConditions( ['severity' => 'critical'] ) );
        $this->assertFalse( $rule->matchesConditions( ['severity' => 'low'] ) );
    }

    public function test_it_matches_operator_conditions(): void
    {
        $rule = AlertRule::factory()->create( [
            'conditions' => ['score' => ['operator' => '>=', 'value' => 80]],
        ] );

        $this->assertTrue( $rule->matchesConditions( ['score' => 90] ) );
        $this->assertFalse( $rule->matchesConditions( ['score' => 50] ) );
    }

    public function test_it_gets_recipients_for_channel(): void
    {
        $rule = AlertRule::factory()->create( [
            'recipients' => [
                'email' => ['ops@example.com', 'security@example.com'],
                'slack' => ['#alerts'],
            ],
        ] );

        $this->assertEquals( ['ops@example.com', 'security@example.com'], $rule->getRecipientsForChannel( 'email' ) );
        $this->assertEquals( ['#alerts'], $rule->getRecipientsForChannel( 'slack' ) );
        $this->assertEquals( [], $rule->getRecipientsForChannel( 'pagerduty' ) );
    }

    public function test_it_handles_cooldown(): void
    {
        $rule = AlertRule::factory()->create( ['cooldown_minutes' => 15] );

        $this->assertFalse( $rule->isOnCooldown() );

        $rule->startCooldown();

        $this->assertTrue( $rule->isOnCooldown() );
    }

    public function test_it_never_cooldowns_when_disabled(): void
    {
        $rule = AlertRule::factory()->create( ['cooldown_minutes' => 0] );

        $rule->startCooldown();

        $this->assertFalse( $rule->isOnCooldown() );
    }

    public function test_it_gets_escalation_time(): void
    {
        $rule = AlertRule::factory()->create( [
            'escalation_policy' => [
                ['level' => 1, 'after_minutes' => 30],
                ['level' => 2, 'after_minutes' => 60],
            ],
        ] );

        $this->assertEquals( 30, $rule->getEscalationTime( 1 ) );
        $this->assertEquals( 60, $rule->getEscalationTime( 2 ) );
        $this->assertNull( $rule->getEscalationTime( 3 ) );
    }

    public function test_it_returns_null_escalation_time_without_policy(): void
    {
        $rule = AlertRule::factory()->create( ['escalation_policy' => null] );

        $this->assertNull( $rule->getEscalationTime() );
    }

    public function test_it_has_many_history_records(): void
    {
        $rule = AlertRule::factory()->create();
        AlertHistory::factory()->count( 3 )->create( ['rule_id' => $rule->id] );

        $this->assertCount( 3, $rule->history );
    }

    public function test_it_scopes_active(): void
    {
        AlertRule::factory()->count( 2 )->create( ['is_active' => true] );
        AlertRule::factory()->create( ['is_active' => false] );

        $this->assertEquals( 2, AlertRule::active()->count() );
    }

    public function test_it_scopes_by_severity(): void
    {
        AlertRule::factory()->count( 2 )->create( ['severity' => AlertRule::SEVERITY_CRITICAL] );
        AlertRule::factory()->create( ['severity' => AlertRule::SEVERITY_LOW] );

        $this->assertEquals( 2, AlertRule::severity( AlertRule::SEVERITY_CRITICAL )->count() );
    }

    public function test_it_scopes_with_channel(): void
    {
        AlertRule::factory()->create( ['channels' => ['email', 'slack']] );
        AlertRule::factory()->create( ['channels' => ['email']] );

        $this->assertEquals( 1, AlertRule::withChannel( 'slack' )->count() );
        $this->assertEquals( 2, AlertRule::withChannel( 'email' )->count() );
    }
}
