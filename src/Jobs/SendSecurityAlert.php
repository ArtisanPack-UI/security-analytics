<?php

/**
 * SendSecurityAlert background job.
 *
 * @package    ArtisanPack_UI
 * @subpackage SecurityAnalytics
 *
 * @author     Jacob Martella <support@artisanpackui.dev>
 *
 * @since      1.0.0
 */

declare( strict_types=1 );

namespace ArtisanPackUI\SecurityAnalytics\Jobs;

use ArtisanPackUI\SecurityAnalytics\Analytics\Alerting\AlertManager;
use ArtisanPackUI\SecurityAnalytics\Analytics\Alerting\SecurityAlert;
use ArtisanPackUI\SecurityAnalytics\Models\AlertHistory;
use ArtisanPackUI\SecurityAnalytics\Models\Anomaly;
use ArtisanPackUI\SecurityAnalytics\Models\SecurityIncident;
use Illuminate\Bus\Queueable;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Foundation\Bus\Dispatchable;
use Illuminate\Queue\InteractsWithQueue;
use Illuminate\Queue\SerializesModels;
use InvalidArgumentException;
use Log;
use Throwable;

class SendSecurityAlert implements ShouldQueue
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
    public int $timeout = 60;

    /**
     * The number of seconds to wait before retrying the job.
     *
     * @var int
     */
    public int $backoff = 10;

    /**
     * Create a new job instance.
     *
     * @param  array<string, mixed>  $alertData
     * @param  array<int, string>|null  $channels
     */
    public function __construct(
        protected array $alertData,
        protected ?array $channels = null,
        protected ?int $alertRuleId = null,
    ) {
    }

    /**
     * Execute the job.
     */
    public function handle( AlertManager $alertManager ): void
    {
        if ( !isset( $this->alertData['title'], $this->alertData['message'] ) ) {
            throw new InvalidArgumentException( 'Alert data must contain title and message' );
        }

        $alert = new SecurityAlert(
            title: $this->alertData['title'],
            message: $this->alertData['message'],
            severity: $this->alertData['severity'] ?? 'medium',
            category: $this->alertData['category'] ?? 'security',
            metadata: $this->alertData['metadata'] ?? [],
        );

        // Set channels if specified
        if ( $this->channels ) {
            $alert->setChannels( $this->channels );
        }

        // Send the alert
        $results = $alertManager->send( $alert );

        // Record alert history
        foreach ( $results as $channel => $result ) {
            AlertHistory::create( [
                'rule_id'       => $this->alertRuleId,
                'anomaly_id'    => $this->alertData['anomaly_id'] ?? null,
                'incident_id'   => $this->alertData['incident_id'] ?? null,
                'severity'      => $alert->getSeverity(),
                'channel'       => $channel,
                'recipient'     => $result['recipient'] ?? null,
                'status'        => $result['success'] ? AlertHistory::STATUS_SENT : AlertHistory::STATUS_FAILED,
                'message'       => $alert->getMessage(),
                'sent_at'       => $result['success'] ? now() : null,
                'error_message' => $result['error'] ?? null,
            ] );
        }
    }

    /**
     * Handle a job failure.
     */
    public function failed( Throwable $exception ): void
    {
        Log::error( 'Failed to send security alert', [
            'exception'   => $exception->getMessage(),
            'alert_title' => $this->alertData['title'] ?? 'Unknown',
            'severity'    => $this->alertData['severity'] ?? 'unknown',
        ] );

        // Record failed attempt
        AlertHistory::create( [
            'rule_id'       => $this->alertRuleId,
            'anomaly_id'    => $this->alertData['anomaly_id'] ?? null,
            'incident_id'   => $this->alertData['incident_id'] ?? null,
            'severity'      => $this->alertData['severity'] ?? 'medium',
            'channel'       => 'unknown',
            'status'        => AlertHistory::STATUS_FAILED,
            'message'       => $this->alertData['message'] ?? '',
            'error_message' => $exception->getMessage(),
        ] );
    }

    /**
     * Get the tags that should be assigned to the job.
     *
     * @return array<int, string>
     */
    public function tags(): array
    {
        $severity = $this->alertData['severity'] ?? 'medium';

        return [
            'security',
            'alert',
            "severity:{$severity}",
        ];
    }

    /**
     * Create a job for an anomaly alert.
     */
    public static function forAnomaly( Anomaly $anomaly ): self
    {
        return new self( [
            'title'      => "Anomaly Detected: {$anomaly->category}",
            'message'    => $anomaly->description,
            'severity'   => $anomaly->severity,
            'category'   => 'anomaly',
            'anomaly_id' => $anomaly->id,
            'metadata'   => [
                'detector'   => $anomaly->detector,
                'score'      => $anomaly->score,
                'user_id'    => $anomaly->user_id,
                'ip_address' => $anomaly->ip_address,
            ],
        ] );
    }

    /**
     * Create a job for an incident alert.
     */
    public static function forIncident( SecurityIncident $incident ): self
    {
        return new self( [
            'title'       => "Security Incident: {$incident->incident_number}",
            'message'     => $incident->description,
            'severity'    => $incident->severity,
            'category'    => 'incident',
            'incident_id' => $incident->id,
            'metadata'    => [
                'status'   => $incident->status,
                'category' => $incident->category,
            ],
        ] );
    }
}
