<?php

declare( strict_types=1 );

namespace ArtisanPackUI\SecurityAnalytics\Analytics\IncidentResponse\Actions;

use ArtisanPackUI\SecurityAnalytics\Analytics\IncidentResponse\Contracts\ResponseActionInterface;
use ArtisanPackUI\SecurityAnalytics\Models\Anomaly;
use ArtisanPackUI\SecurityAnalytics\Models\SecurityIncident;

abstract class AbstractAction implements ResponseActionInterface
{
    /**
     * {@inheritdoc}
     */
    public function requiresApproval(): bool
    {
        return false;
    }

    /**
     * {@inheritdoc}
     */
    public function validate( array $config = [] ): array
    {
        return []; // No errors by default
    }

    /**
     * Create a success result.
     *
     * @param  array<string, mixed>  $data
     *
     * @return array<string, mixed>
     */
    protected function success( string $message, array $data = [] ): array
    {
        return [
            'success'     => true,
            'action'      => $this->getName(),
            'message'     => $message,
            'data'        => $data,
            'executed_at' => now()->toIso8601String(),
        ];
    }

    /**
     * Create a failure result.
     *
     * @param  array<string, mixed>  $data
     *
     * @return array<string, mixed>
     */
    protected function failure( string $message, array $data = [] ): array
    {
        return [
            'success'     => false,
            'action'      => $this->getName(),
            'message'     => $message,
            'data'        => $data,
            'executed_at' => now()->toIso8601String(),
        ];
    }

    /**
     * Log the action to the incident.
     *
     * @param  array<string, mixed>  $result
     */
    protected function logToIncident( SecurityIncident $incident, array $result ): void
    {
        $incident->addAction( $this->getName(), $result );
    }

    /**
     * Get user ID from anomaly metadata.
     */
    protected function getUserIdFromAnomaly( Anomaly $anomaly ): ?int
    {
        return $anomaly->user_id ?? ( $anomaly->metadata['user_id'] ?? null );
    }

    /**
     * Get IP address from anomaly metadata.
     */
    protected function getIpFromAnomaly( Anomaly $anomaly ): ?string
    {
        // First check the ip_address column, then fall back to metadata
        return $anomaly->ip_address ?? ( $anomaly->metadata['ip'] ?? ( $anomaly->metadata['ip_address'] ?? null ));
    }
}
