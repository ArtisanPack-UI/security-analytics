<?php

declare( strict_types=1 );

namespace Tests\Unit\Analytics\Models;

use ArtisanPackUI\SecurityAnalytics\Models\SecurityEvent;
use Tests\Unit\Analytics\AnalyticsTestCase;

class SecurityEventModelTest extends AnalyticsTestCase
{
    public function test_it_can_create_security_event(): void
    {
        $event = $this->makeEvent( [
            'event_name' => 'login_failed',
            'severity'   => SecurityEvent::SEVERITY_WARNING,
        ] );

        $this->assertDatabaseHas( 'security_events', [
            'id'         => $event->id,
            'event_type' => SecurityEvent::TYPE_AUTHENTICATION,
            'event_name' => 'login_failed',
            'severity'   => SecurityEvent::SEVERITY_WARNING,
        ] );
    }

    public function test_it_casts_attributes(): void
    {
        $event = $this->makeEvent( [
            'details'     => ['reason' => 'bad_password'],
            'status_code' => '403',
            'user_id'     => '5',
        ] );

        $this->assertIsArray( $event->details );
        $this->assertIsInt( $event->status_code );
        $this->assertIsInt( $event->user_id );
        $this->assertInstanceOf( \Carbon\Carbon::class, $event->created_at );
    }

    public function test_it_does_not_use_updated_at(): void
    {
        $this->assertNull( SecurityEvent::UPDATED_AT );

        $event = $this->makeEvent();

        $this->assertNull( $event->updated_at );
    }

    public function test_it_detects_suspicious_events(): void
    {
        $error    = $this->makeEvent( ['severity' => SecurityEvent::SEVERITY_ERROR] );
        $critical = $this->makeEvent( ['severity' => SecurityEvent::SEVERITY_CRITICAL] );
        $info     = $this->makeEvent( ['severity' => SecurityEvent::SEVERITY_INFO] );

        $this->assertTrue( $error->isSuspicious() );
        $this->assertTrue( $critical->isSuspicious() );
        $this->assertFalse( $info->isSuspicious() );
    }

    public function test_it_formats_details(): void
    {
        $event = $this->makeEvent( ['details' => ['key' => 'value']] );
        $empty = $this->makeEvent( ['details' => null] );

        $this->assertStringContainsString( '"key": "value"', $event->getFormattedDetails() );
        $this->assertEquals( '', $empty->getFormattedDetails() );
    }

    public function test_it_generates_a_stable_fingerprint(): void
    {
        $one  = SecurityEvent::generateFingerprint( 'authentication', 'login_failed', '203.0.113.1' );
        $two  = SecurityEvent::generateFingerprint( 'authentication', 'login_failed', '203.0.113.1' );
        $diff = SecurityEvent::generateFingerprint( 'authentication', 'login_failed', '203.0.113.9' );

        $this->assertEquals( $one, $two );
        $this->assertNotEquals( $one, $diff );
        $this->assertEquals( 64, strlen( $one ) );
    }

    public function test_it_scopes_by_type_name_severity_user_and_ip(): void
    {
        $this->makeEvent( ['event_type' => SecurityEvent::TYPE_AUTHENTICATION, 'event_name' => 'login_success', 'user_id' => 1, 'ip_address' => '10.0.0.1'] );
        $this->makeEvent( ['event_type' => SecurityEvent::TYPE_API_ACCESS, 'event_name' => 'api_call', 'severity' => SecurityEvent::SEVERITY_WARNING, 'user_id' => 2, 'ip_address' => '10.0.0.2'] );

        $this->assertEquals( 1, SecurityEvent::byType( SecurityEvent::TYPE_API_ACCESS )->count() );
        $this->assertEquals( 1, SecurityEvent::byName( 'login_success' )->count() );
        $this->assertEquals( 1, SecurityEvent::bySeverity( SecurityEvent::SEVERITY_WARNING )->count() );
        $this->assertEquals( 1, SecurityEvent::byUser( 1 )->count() );
        $this->assertEquals( 1, SecurityEvent::byIp( '10.0.0.2' )->count() );
    }

    public function test_it_scopes_recent_and_date_range(): void
    {
        $this->makeEvent( ['created_at' => now()->subHours( 2 )] );
        $this->makeEvent( ['created_at' => now()->subDays( 3 )] );

        $this->assertEquals( 1, SecurityEvent::recent( 24 )->count() );
        $this->assertEquals( 2, SecurityEvent::inDateRange( now()->subDays( 5 ), now() )->count() );
    }

    public function test_it_scopes_suspicious_and_by_type_helpers(): void
    {
        $this->makeEvent( ['severity' => SecurityEvent::SEVERITY_ERROR] );
        $this->makeEvent( ['severity' => SecurityEvent::SEVERITY_CRITICAL] );
        $this->makeEvent( ['severity' => SecurityEvent::SEVERITY_INFO] );
        $this->makeEvent( ['event_type' => SecurityEvent::TYPE_AUTHORIZATION] );
        $this->makeEvent( ['event_type' => SecurityEvent::TYPE_API_ACCESS] );
        $this->makeEvent( ['event_type' => SecurityEvent::TYPE_SECURITY_VIOLATION] );

        $this->assertEquals( 2, SecurityEvent::suspicious()->count() );
        $this->assertEquals( 3, SecurityEvent::authentication()->count() );
        $this->assertEquals( 1, SecurityEvent::authorization()->count() );
        $this->assertEquals( 1, SecurityEvent::apiAccess()->count() );
        $this->assertEquals( 1, SecurityEvent::securityViolation()->count() );
    }

    /**
     * @param  array<string, mixed>  $overrides
     */
    private function makeEvent( array $overrides = [] ): SecurityEvent
    {
        // created_at is guarded, so apply it explicitly after creation when provided.
        $createdAt = $overrides['created_at'] ?? null;
        unset( $overrides['created_at'] );

        $event = SecurityEvent::create( array_merge( [
            'event_type' => SecurityEvent::TYPE_AUTHENTICATION,
            'event_name' => 'login_success',
            'severity'   => SecurityEvent::SEVERITY_INFO,
            'ip_address' => '127.0.0.1',
        ], $overrides ) );

        if ( null !== $createdAt ) {
            $event->created_at = $createdAt;
            $event->save();
        }

        return $event;
    }
}
