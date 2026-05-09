<?php

declare( strict_types=1 );

namespace ArtisanPackUI\SecurityAnalytics\Jobs;

use ArtisanPackUI\SecurityAnalytics\Analytics\AnomalyDetection\AnomalyDetectionService;
use ArtisanPackUI\SecurityAnalytics\Analytics\IncidentResponse\IncidentResponder;
use ArtisanPackUI\SecurityAnalytics\Models\Anomaly;
use Illuminate\Bus\Queueable;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Foundation\Bus\Dispatchable;
use Illuminate\Queue\InteractsWithQueue;
use Illuminate\Queue\SerializesModels;
use Illuminate\Support\Collection;
use Log;
use Throwable;

class AnalyzeAnomalies implements ShouldQueue
{
    use Dispatchable;
use InteractsWithQueue;
use Queueable;
use SerializesModels;

    /**
     * The number of times the job may be attempted.
     *
     * @var int
     */
    public int $tries = 3;

    /**
     * The number of seconds the job can run before timing out.
     *
     * @var int
     */
    public int $timeout = 300;

    /**
     * Create a new job instance.
     *
     * @param  array<string, mixed>  $data
     */
    public function __construct(
        protected array $data = [],
        protected bool $autoRespond = true,
        protected ?string $specificDetector = null,
    ) {
    }

    /**
     * Execute the job.
     */
    public function handle(
        AnomalyDetectionService $anomalyDetection,
        IncidentResponder $incidentResponder,
    ): void {
        /** @var Collection<int, Anomaly> $anomalies */
        $anomalies = collect();

        // Run specific detector or all detectors
        if ( $this->specificDetector ) {
            $anomalies = $anomalyDetection->detectWith( $this->specificDetector, $this->data );
        } else {
            $anomalies = $anomalyDetection->detect( $this->data );
        }

        // Auto-respond to detected anomalies if enabled
        if ( $this->autoRespond && $anomalies->isNotEmpty() ) {
            foreach ( $anomalies as $anomaly ) {
                $incidentResponder->respond( $anomaly );
            }
        }

        // Log results
        Log::info( 'Anomaly analysis completed', [
            'detector'           => $this->specificDetector ?? 'all',
            'anomalies_detected' => $anomalies->count(),
            'auto_respond'       => $this->autoRespond,
        ] );
    }

    /**
     * Handle a job failure.
     */
    public function failed( Throwable $exception ): void
    {
        Log::error( 'Failed to analyze anomalies', [
            'exception' => $exception->getMessage(),
            'detector'  => $this->specificDetector,
        ] );
    }

    /**
     * Get the tags that should be assigned to the job.
     *
     * @return array<int, string>
     */
    public function tags(): array
    {
        return [
            'security',
            'anomaly-detection',
            $this->specificDetector ? "detector:{$this->specificDetector}" : 'detector:all',
        ];
    }
}
