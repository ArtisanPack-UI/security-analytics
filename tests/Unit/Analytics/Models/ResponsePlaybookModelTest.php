<?php

declare( strict_types=1 );

namespace Tests\Unit\Analytics\Models;

use ArtisanPackUI\SecurityAnalytics\Database\Factories\ResponsePlaybookFactory;
use ArtisanPackUI\SecurityAnalytics\Models\Anomaly;
use ArtisanPackUI\SecurityAnalytics\Models\ResponsePlaybook;
use Tests\Unit\Analytics\AnalyticsTestCase;

class ResponsePlaybookModelTest extends AnalyticsTestCase
{
    public function test_it_can_create_playbook(): void
    {
        $playbook = ResponsePlaybookFactory::new()->create( [
            'name'      => 'Brute force response',
            'is_active' => true,
        ] );

        $this->assertDatabaseHas( 'response_playbooks', [
            'id'        => $playbook->id,
            'name'      => 'Brute force response',
            'is_active' => true,
        ] );
    }

    public function test_it_casts_json_and_boolean_attributes(): void
    {
        $playbook = ResponsePlaybookFactory::new()->create( [
            'trigger_conditions' => ['severity' => Anomaly::SEVERITY_HIGH],
            'actions'            => [['action' => 'block_ip']],
            'is_active'          => true,
            'requires_approval'  => false,
        ] );

        $this->assertIsArray( $playbook->trigger_conditions );
        $this->assertIsArray( $playbook->actions );
        $this->assertIsBool( $playbook->is_active );
        $this->assertIsBool( $playbook->requires_approval );
        $this->assertIsInt( $playbook->cooldown_minutes );
    }

    public function test_it_matches_anomaly_on_scalar_condition(): void
    {
        $playbook = ResponsePlaybookFactory::new()->create( [
            'trigger_conditions' => ['severity' => Anomaly::SEVERITY_CRITICAL],
        ] );

        $critical = Anomaly::factory()->make( ['severity' => Anomaly::SEVERITY_CRITICAL] );
        $high     = Anomaly::factory()->make( ['severity' => Anomaly::SEVERITY_HIGH] );

        $this->assertTrue( $playbook->matchesAnomaly( $critical ) );
        $this->assertFalse( $playbook->matchesAnomaly( $high ) );
    }

    public function test_it_matches_anomaly_on_array_condition(): void
    {
        $playbook = ResponsePlaybookFactory::new()->create( [
            'trigger_conditions' => ['severity' => [Anomaly::SEVERITY_HIGH, Anomaly::SEVERITY_CRITICAL]],
        ] );

        $high   = Anomaly::factory()->make( ['severity' => Anomaly::SEVERITY_HIGH] );
        $medium = Anomaly::factory()->make( ['severity' => Anomaly::SEVERITY_MEDIUM] );

        $this->assertTrue( $playbook->matchesAnomaly( $high ) );
        $this->assertFalse( $playbook->matchesAnomaly( $medium ) );
    }

    public function test_it_gets_action_names(): void
    {
        $playbook = ResponsePlaybookFactory::new()->create( [
            'actions' => [
                ['action' => 'block_ip'],
                ['name' => 'notify_team'],
                'lockout_user',
            ],
        ] );

        $this->assertEquals( ['block_ip', 'notify_team', 'lockout_user'], $playbook->getActionNames() );
    }

    public function test_it_gets_action_config(): void
    {
        $playbook = ResponsePlaybookFactory::new()->create( [
            'actions' => [
                ['action' => 'block_ip', 'duration' => 60],
                'lockout_user',
            ],
        ] );

        $this->assertEquals( ['action' => 'block_ip', 'duration' => 60], $playbook->getActionConfig( 'block_ip' ) );
        $this->assertEquals( ['action' => 'lockout_user'], $playbook->getActionConfig( 'lockout_user' ) );
        $this->assertNull( $playbook->getActionConfig( 'missing' ) );
    }

    public function test_it_handles_cooldown(): void
    {
        $playbook = ResponsePlaybookFactory::new()->create( ['cooldown_minutes' => 30] );

        $this->assertFalse( $playbook->isOnCooldown() );

        $playbook->startCooldown();

        $this->assertTrue( $playbook->isOnCooldown() );
    }

    public function test_it_scopes_active_automatic_and_requires_approval(): void
    {
        ResponsePlaybookFactory::new()->create( ['is_active' => true, 'requires_approval' => false] );
        ResponsePlaybookFactory::new()->create( ['is_active' => true, 'requires_approval' => true] );
        ResponsePlaybookFactory::new()->create( ['is_active' => false, 'requires_approval' => false] );

        $this->assertEquals( 2, ResponsePlaybook::active()->count() );
        $this->assertEquals( 2, ResponsePlaybook::automatic()->count() );
        $this->assertEquals( 1, ResponsePlaybook::requiresApproval()->count() );
    }

    public function test_it_finds_matching_playbooks_for_anomaly(): void
    {
        ResponsePlaybookFactory::new()->create( [
            'is_active'          => true,
            'trigger_conditions' => ['severity' => Anomaly::SEVERITY_CRITICAL],
        ] );
        ResponsePlaybookFactory::new()->create( [
            'is_active'          => true,
            'trigger_conditions' => ['severity' => Anomaly::SEVERITY_LOW],
        ] );
        ResponsePlaybookFactory::new()->create( [
            'is_active'          => false,
            'trigger_conditions' => ['severity' => Anomaly::SEVERITY_CRITICAL],
        ] );

        $anomaly = Anomaly::factory()->make( ['severity' => Anomaly::SEVERITY_CRITICAL] );

        $matches = ResponsePlaybook::findMatchingPlaybooks( $anomaly );

        $this->assertCount( 1, $matches );
    }
}
