<?php

declare( strict_types=1 );

namespace Tests\Unit\Analytics\Models;

use ArtisanPackUI\SecurityAnalytics\Models\ScheduledReport;
use Tests\Unit\Analytics\AnalyticsTestCase;

class ScheduledReportModelTest extends AnalyticsTestCase
{
    public function test_it_can_create_scheduled_report(): void
    {
        $report = ScheduledReport::factory()->create( [
            'report_type' => ScheduledReport::TYPE_EXECUTIVE,
            'format'      => ScheduledReport::FORMAT_PDF,
            'is_active'   => true,
        ] );

        $this->assertDatabaseHas( 'scheduled_reports', [
            'id'          => $report->id,
            'report_type' => ScheduledReport::TYPE_EXECUTIVE,
            'format'      => ScheduledReport::FORMAT_PDF,
        ] );
    }

    public function test_it_casts_attributes(): void
    {
        $report = ScheduledReport::factory()->create( [
            'recipients'  => ['a@example.com'],
            'options'     => ['include_charts' => true],
            'is_active'   => true,
            'last_run_at' => now()->subDay(),
            'next_run_at' => now()->addDay(),
        ] );

        $this->assertIsArray( $report->recipients );
        $this->assertIsArray( $report->options );
        $this->assertIsBool( $report->is_active );
        $this->assertInstanceOf( \Carbon\Carbon::class, $report->last_run_at );
        $this->assertInstanceOf( \Carbon\Carbon::class, $report->next_run_at );
    }

    public function test_it_should_run_now_when_next_run_is_past(): void
    {
        $due = ScheduledReport::factory()->create( [
            'is_active'   => true,
            'next_run_at' => now()->subHour(),
        ] );

        $notDue = ScheduledReport::factory()->create( [
            'is_active'   => true,
            'next_run_at' => now()->addHour(),
        ] );

        $this->assertTrue( $due->shouldRunNow() );
        $this->assertFalse( $notDue->shouldRunNow() );
    }

    public function test_it_should_run_now_when_next_run_is_null(): void
    {
        $report = ScheduledReport::factory()->create( [
            'is_active'   => true,
            'next_run_at' => null,
        ] );

        $this->assertTrue( $report->shouldRunNow() );
    }

    public function test_it_never_runs_when_inactive(): void
    {
        $report = ScheduledReport::factory()->create( [
            'is_active'   => false,
            'next_run_at' => now()->subHour(),
        ] );

        $this->assertFalse( $report->shouldRunNow() );
    }

    public function test_it_marks_as_run(): void
    {
        $report = ScheduledReport::factory()->create( [
            'cron_expression' => '@daily',
            'last_run_at'     => null,
            'next_run_at'     => now()->subHour(),
        ] );

        $report->markAsRun();

        $this->assertInstanceOf( \Carbon\Carbon::class, $report->last_run_at );
        $this->assertTrue( $report->next_run_at->isFuture() );
    }

    public function test_it_gets_and_sets_options(): void
    {
        $report = ScheduledReport::factory()->create( [
            'options' => ['date_range' => '30d'],
        ] );

        $this->assertEquals( '30d', $report->getOption( 'date_range' ) );
        $this->assertEquals( 'default', $report->getOption( 'missing', 'default' ) );

        $report->setOption( 'include_charts', true );
        $this->assertTrue( $report->getOption( 'include_charts' ) );
    }

    public function test_it_filters_email_recipients(): void
    {
        $report = ScheduledReport::factory()->create( [
            'recipients' => ['ops@example.com', 'not-an-email', 'security@example.com'],
        ] );

        $emails = $report->getEmailRecipients();

        $this->assertCount( 2, $emails );
        $this->assertContains( 'ops@example.com', $emails );
        $this->assertContains( 'security@example.com', $emails );
    }

    public function test_it_scopes_active(): void
    {
        ScheduledReport::factory()->count( 2 )->create( ['is_active' => true] );
        ScheduledReport::factory()->create( ['is_active' => false] );

        $this->assertEquals( 2, ScheduledReport::active()->count() );
    }

    public function test_it_scopes_due(): void
    {
        ScheduledReport::factory()->create( ['is_active' => true, 'next_run_at' => now()->subHour()] );
        ScheduledReport::factory()->create( ['is_active' => true, 'next_run_at' => null] );
        ScheduledReport::factory()->create( ['is_active' => true, 'next_run_at' => now()->addHour()] );
        ScheduledReport::factory()->create( ['is_active' => false, 'next_run_at' => now()->subHour()] );

        $this->assertEquals( 2, ScheduledReport::due()->count() );
    }

    public function test_it_scopes_by_type_and_format(): void
    {
        ScheduledReport::factory()->count( 2 )->create( ['report_type' => ScheduledReport::TYPE_THREAT, 'format' => ScheduledReport::FORMAT_PDF] );
        ScheduledReport::factory()->create( ['report_type' => ScheduledReport::TYPE_COMPLIANCE, 'format' => ScheduledReport::FORMAT_CSV] );

        $this->assertEquals( 2, ScheduledReport::ofType( ScheduledReport::TYPE_THREAT )->count() );
        $this->assertEquals( 1, ScheduledReport::format( ScheduledReport::FORMAT_CSV )->count() );
    }
}
