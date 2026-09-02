<?php

declare( strict_types=1 );

namespace Tests\Unit\Analytics\Models;

use ArtisanPackUI\SecurityAnalytics\Models\UserBehaviorProfile;
use Tests\Unit\Analytics\AnalyticsTestCase;

class UserBehaviorProfileModelTest extends AnalyticsTestCase
{
    public function test_it_can_create_profile(): void
    {
        $profile = UserBehaviorProfile::factory()->create( [
            'user_id'      => 1,
            'profile_type' => UserBehaviorProfile::TYPE_LOGIN,
        ] );

        $this->assertDatabaseHas( 'user_behavior_profiles', [
            'id'           => $profile->id,
            'user_id'      => 1,
            'profile_type' => UserBehaviorProfile::TYPE_LOGIN,
        ] );
    }

    public function test_it_casts_attributes(): void
    {
        $profile = UserBehaviorProfile::factory()->create( [
            'baseline_data'   => ['avg_logins' => 5],
            'sample_count'    => 20,
            'last_updated_at' => now(),
        ] );

        $this->assertIsArray( $profile->baseline_data );
        $this->assertIsInt( $profile->sample_count );
        $this->assertInstanceOf( \Carbon\Carbon::class, $profile->last_updated_at );
    }

    public function test_it_gets_and_sets_baseline(): void
    {
        $profile = UserBehaviorProfile::factory()->create( [
            'baseline_data' => ['avg_session_minutes' => 30],
        ] );

        $this->assertEquals( 30, $profile->getBaseline( 'avg_session_minutes' ) );
        $this->assertEquals( 'default', $profile->getBaseline( 'missing', 'default' ) );

        $profile->setBaseline( 'typical_ip', '203.0.113.1' );
        $this->assertEquals( '203.0.113.1', $profile->getBaseline( 'typical_ip' ) );
    }

    public function test_it_checks_for_sufficient_data(): void
    {
        $enough = UserBehaviorProfile::factory()->create( ['sample_count' => 15] );
        $short  = UserBehaviorProfile::factory()->create( ['sample_count' => 5] );

        $this->assertTrue( $enough->hasSufficientData() );
        $this->assertFalse( $short->hasSufficientData() );
        $this->assertTrue( $short->hasSufficientData( 3 ) );
    }

    public function test_it_gets_confidence_level(): void
    {
        $high         = UserBehaviorProfile::factory()->create( ['confidence_score' => 85] );
        $medium       = UserBehaviorProfile::factory()->create( ['confidence_score' => 60] );
        $low          = UserBehaviorProfile::factory()->create( ['confidence_score' => 25] );
        $insufficient = UserBehaviorProfile::factory()->create( ['confidence_score' => 10] );

        $this->assertEquals( 'high', $high->getConfidenceLevel() );
        $this->assertEquals( 'medium', $medium->getConfidenceLevel() );
        $this->assertEquals( 'low', $low->getConfidenceLevel() );
        $this->assertEquals( 'insufficient', $insufficient->getConfidenceLevel() );
    }

    public function test_it_adds_a_data_point(): void
    {
        $profile = UserBehaviorProfile::factory()->create( [
            'sample_count'     => 49,
            'confidence_score' => 0,
        ] );

        $profile->addDataPoint( ['ip' => '203.0.113.1'] );

        $this->assertEquals( 50, $profile->sample_count );
        $this->assertEquals( 50.0, (float) $profile->confidence_score );
        $this->assertInstanceOf( \Carbon\Carbon::class, $profile->last_updated_at );
    }

    public function test_it_scopes_for_user_and_type(): void
    {
        // The (user_id, profile_type) pair is unique, so vary the type per user.
        UserBehaviorProfile::factory()->create( ['user_id' => 7, 'profile_type' => UserBehaviorProfile::TYPE_LOGIN] );
        UserBehaviorProfile::factory()->create( ['user_id' => 7, 'profile_type' => UserBehaviorProfile::TYPE_API_USAGE] );
        UserBehaviorProfile::factory()->create( ['user_id' => 8, 'profile_type' => UserBehaviorProfile::TYPE_API_USAGE] );

        $this->assertEquals( 2, UserBehaviorProfile::forUser( 7 )->count() );
        $this->assertEquals( 2, UserBehaviorProfile::ofType( UserBehaviorProfile::TYPE_API_USAGE )->count() );
    }

    public function test_it_scopes_with_sufficient_data(): void
    {
        UserBehaviorProfile::factory()->create( ['user_id' => 1, 'profile_type' => UserBehaviorProfile::TYPE_LOGIN, 'sample_count' => 20] );
        UserBehaviorProfile::factory()->create( ['user_id' => 2, 'profile_type' => UserBehaviorProfile::TYPE_LOGIN, 'sample_count' => 20] );
        UserBehaviorProfile::factory()->create( ['user_id' => 3, 'profile_type' => UserBehaviorProfile::TYPE_LOGIN, 'sample_count' => 3] );

        $this->assertEquals( 2, UserBehaviorProfile::withSufficientData()->count() );
        $this->assertEquals( 3, UserBehaviorProfile::withSufficientData( 1 )->count() );
    }

    public function test_it_scopes_needs_update(): void
    {
        UserBehaviorProfile::factory()->create( ['user_id' => 1, 'profile_type' => UserBehaviorProfile::TYPE_LOGIN, 'last_updated_at' => now()->subDays( 2 )] );
        UserBehaviorProfile::factory()->create( ['user_id' => 2, 'profile_type' => UserBehaviorProfile::TYPE_LOGIN, 'last_updated_at' => null] );
        UserBehaviorProfile::factory()->create( ['user_id' => 3, 'profile_type' => UserBehaviorProfile::TYPE_LOGIN, 'last_updated_at' => now()] );

        $this->assertEquals( 2, UserBehaviorProfile::needsUpdate( 24 )->count() );
    }
}
