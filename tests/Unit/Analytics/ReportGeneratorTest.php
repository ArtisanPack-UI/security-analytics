<?php

declare( strict_types=1 );

namespace Tests\Unit\Analytics;

use ArtisanPackUI\SecurityAnalytics\Analytics\Reports\Contracts\ReportInterface;
use ArtisanPackUI\SecurityAnalytics\Analytics\Reports\ReportGenerator;
use ArtisanPackUI\SecurityAnalytics\Models\ScheduledReport;
use Illuminate\Support\Facades\Mail;
use InvalidArgumentException;

/**
 * Stub report used to exercise the generator without coupling to the
 * concrete report classes' query logic.
 */
class StubReport implements ReportInterface
{
    /**
     * @param  array<string, mixed>  $options
     */
    public function __construct( protected array $options = [] )
    {
    }

    public function generate(): array
    {
        return ['summary' => 'stub', 'options' => $this->options];
    }

    public function toHtml( array $data ): string
    {
        return '<p>stub</p>';
    }

    public function toCsv( array $data ): string
    {
        return 'summary,stub';
    }

    public function toPdf( array $data ): string
    {
        return '%PDF-stub';
    }
}

class ReportGeneratorTest extends AnalyticsTestCase
{
    protected string $storagePath;

    protected function setUp(): void
    {
        parent::setUp();

        $this->storagePath = sys_get_temp_dir() . '/sa-reports-' . uniqid();
    }

    protected function tearDown(): void
    {
        if ( is_dir( $this->storagePath ) ) {
            array_map( 'unlink', glob( $this->storagePath . '/*' ) ?: [] );
            rmdir( $this->storagePath );
        }

        parent::tearDown();
    }

    public function test_it_registers_the_default_report_types(): void
    {
        $types = ( new ReportGenerator() )->getAvailableReportTypes();

        $this->assertContains( ScheduledReport::TYPE_EXECUTIVE, $types );
        $this->assertContains( ScheduledReport::TYPE_THREAT, $types );
        $this->assertContains( ScheduledReport::TYPE_INCIDENT, $types );
        $this->assertContains( ScheduledReport::TYPE_COMPLIANCE, $types );
        $this->assertContains( ScheduledReport::TYPE_USER_ACTIVITY, $types );
        $this->assertContains( ScheduledReport::TYPE_TREND, $types );
    }

    public function test_it_can_register_a_custom_report_type(): void
    {
        $generator = $this->generator();

        $this->assertContains( 'stub', $generator->getAvailableReportTypes() );
    }

    public function test_it_throws_for_an_unknown_report_type(): void
    {
        $this->expectException( InvalidArgumentException::class );

        $this->generator()->generate( 'does-not-exist' );
    }

    public function test_it_generates_a_report_and_writes_a_file(): void
    {
        $result = $this->generator()->generate( 'stub', ['format' => 'json'] );

        $this->assertEquals( 'stub', $result['type'] );
        $this->assertEquals( 'json', $result['format'] );
        $this->assertEquals( 'stub', $result['data']['summary'] );
        $this->assertFileExists( $result['path'] );
        $this->assertStringContainsString( 'stub', file_get_contents( $result['path'] ) );
    }

    public function test_it_formats_each_supported_format(): void
    {
        $html = $this->generator()->generate( 'stub', ['format' => 'html'] );
        $csv  = $this->generator()->generate( 'stub', ['format' => 'csv'] );

        $this->assertStringContainsString( '<p>stub</p>', file_get_contents( $html['path'] ) );
        $this->assertStringContainsString( 'summary,stub', file_get_contents( $csv['path'] ) );
    }

    public function test_it_generates_a_scheduled_report_and_marks_it_run(): void
    {
        $scheduled = ScheduledReport::factory()->create( [
            'report_type'     => 'stub',
            'format'          => ScheduledReport::FORMAT_JSON,
            'cron_expression' => '@daily',
            'last_run_at'     => null,
        ] );

        $result = $this->generator()->generateScheduledReport( $scheduled );

        $this->assertEquals( $scheduled->id, $result['scheduled_report_id'] );
        $this->assertEquals( $scheduled->name, $result['scheduled_report_name'] );
        $this->assertInstanceOf( \Carbon\Carbon::class, $scheduled->fresh()->last_run_at );
    }

    public function test_it_runs_due_reports(): void
    {
        Mail::fake();

        ScheduledReport::factory()->create( [
            'report_type'     => 'stub',
            'format'          => ScheduledReport::FORMAT_JSON,
            'cron_expression' => '@daily',
            'is_active'       => true,
            'next_run_at'     => now()->subHour(),
            'recipients'      => [],
        ] );

        // A future report should not be picked up.
        ScheduledReport::factory()->create( [
            'report_type'     => 'stub',
            'format'          => ScheduledReport::FORMAT_JSON,
            'cron_expression' => '@daily',
            'is_active'       => true,
            'next_run_at'     => now()->addDay(),
            'recipients'      => [],
        ] );

        $results = $this->generator()->runDueReports();

        $this->assertCount( 1, $results );
        $this->assertEquals( 'success', $results[0]['status'] );
    }

    private function generator(): ReportGenerator
    {
        return ( new ReportGenerator( ['storage_path' => $this->storagePath] ) )
            ->registerReportType( 'stub', StubReport::class );
    }
}
