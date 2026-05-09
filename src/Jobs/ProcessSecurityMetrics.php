<?php

declare( strict_types=1 );

namespace ArtisanPackUI\SecurityAnalytics\Jobs;

use ArtisanPackUI\SecurityAnalytics\Analytics\MetricsCollector;
use Illuminate\Bus\Queueable;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Foundation\Bus\Dispatchable;
use Illuminate\Queue\InteractsWithQueue;
use Illuminate\Queue\SerializesModels;
use Log;
use Throwable;

class ProcessSecurityMetrics implements ShouldQueue
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
    public int $timeout = 120;

    /**
     * Create a new job instance.
     *
     * @param  array<string, mixed>  $metrics
     */
    public function __construct(
        protected array $metrics = [],
        protected bool $flushBuffer = false,
    ) {
    }

    /**
     * Execute the job.
     */
    public function handle( MetricsCollector $collector ): void
    {
        // Record any provided metrics
        foreach ( $this->metrics as $metric ) {
            if ( !isset( $metric['name'], $metric['value'] ) ) {
                Log::warning( 'Skipping invalid metric', ['metric' => $metric] );
                continue;
            }

            $collector->record(
                name: $metric['name'],
                value: $metric['value'],
                type: $metric['type'] ?? 'counter',
                category: $metric['category'] ?? 'system',
                tags: $metric['tags'] ?? [],
            );
        }

        // Flush the buffer if requested
        if ( $this->flushBuffer ) {
            $collector->flush();
        }
    }

    /**
     * Handle a job failure.
     */
    public function failed( Throwable $exception ): void
    {
        Log::error( 'Failed to process security metrics', [
            'exception'     => $exception->getMessage(),
            'metrics_count' => count( $this->metrics ),
        ] );
    }
}
