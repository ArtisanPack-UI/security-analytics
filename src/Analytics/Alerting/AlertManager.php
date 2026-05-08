<?php

declare( strict_types=1 );

namespace ArtisanPackUI\SecurityAnalytics\Analytics\Alerting;

use ArtisanPackUI\SecurityAnalytics\Analytics\Alerting\Channels\EmailChannel;
use ArtisanPackUI\SecurityAnalytics\Analytics\Alerting\Channels\PagerDutyChannel;
use ArtisanPackUI\SecurityAnalytics\Analytics\Alerting\Channels\SlackChannel;
use ArtisanPackUI\SecurityAnalytics\Analytics\Alerting\Contracts\AlertChannelInterface;
use ArtisanPackUI\SecurityAnalytics\Models\AlertHistory;
use ArtisanPackUI\SecurityAnalytics\Models\AlertRule;
use ArtisanPackUI\SecurityAnalytics\Models\Anomaly;
use Exception;
use Illuminate\Support\Collection;

class AlertManager
{
    /**
     * @var array<string, AlertChannelInterface>
     */
    protected array $channels = [];

    /**
     * @var array<string, mixed>
     */
    protected array $config;

    /**
     * @param  array<string, mixed>  $config
     */
    public function __construct( array $config = [] )
    {
        $this->config = array_merge( $this->getDefaultConfig(), $config );
        $this->registerDefaultChannels();
    }

    /**
     * Register an alert channel.
     */
    public function registerChannel( AlertChannelInterface $channel ): self
    {
        $this->channels[ $channel->getName() ] = $channel;

        return $this;
    }

    /**
     * Get a channel by name.
     */
    public function getChannel( string $name ): ?AlertChannelInterface
    {
        return $this->channels[ $name ] ?? null;
    }

    /**
     * Get all enabled channels.
     *
     * @return array<string, AlertChannelInterface>
     */
    public function getEnabledChannels(): array
    {
        return array_filter( $this->channels, fn ( $c ) => $c->isEnabled() );
    }

    /**
     * Process an anomaly and send alerts based on matching rules.
     *
     * @return array<string, mixed>
     */
    public function processAnomaly( Anomaly $anomaly ): array
    {
        if ( ! $this->config['enabled'] ) {
            return ['skipped' => true, 'reason' => 'Alerting is disabled'];
        }

        $results = [];

        // Find matching alert rules
        $rules = $this->findMatchingRules( $anomaly );

        foreach ( $rules as $rule ) {
            $results[ $rule->name ] = $this->executeRule( $rule, $anomaly );
        }

        return [
            'anomaly_id'    => $anomaly->id,
            'rules_matched' => $rules->count(),
            'results'       => $results,
        ];
    }

    /**
     * Send an alert through a channel.
     *
     * @param  array<int, string>  $recipients
     *
     * @return array<string, mixed>
     */
    public function sendAlert(
        AlertChannelInterface $channel,
        Anomaly $anomaly,
        AlertRule $rule,
        array $recipients,
    ): array {
        try {
            return $channel->send( $anomaly, $rule, $recipients );
        } catch ( Exception $e ) {
            return [
                'success' => false,
                'error'   => $e->getMessage(),
            ];
        }
    }

    /**
     * Send a direct alert without rule matching.
     *
     * @param  array<int, string>  $channels
     * @param  array<int, string>  $recipients
     *
     * @return array<string, mixed>
     */
    public function sendDirectAlert(
        Anomaly $anomaly,
        array $channels,
        array $recipients,
        ?string $message = null,
    ): array {
        // Create a temporary rule for the direct alert
        $rule = new AlertRule( [
            'name'     => 'Direct Alert',
            'severity' => $anomaly->severity,
            'channels' => $channels,
        ] );

        $results = [];

        foreach ( $channels as $channelName ) {
            $channel = $this->getChannel( $channelName );

            if ( ! $channel || ! $channel->isEnabled() ) {
                $results[ $channelName ] = ['success' => false, 'error' => 'Channel not available'];
                continue;
            }

            $results[ $channelName ] = $channel->send( $anomaly, $rule, $recipients );
        }

        return $results;
    }

    /**
     * Get alert statistics.
     *
     * @return array<string, mixed>
     */
    public function getStatistics( int $days = 7 ): array
    {
        $startDate = now()->subDays( $days );

        $history = AlertHistory::where( 'created_at', '>=', $startDate )->get();

        return [
            'total_alerts' => $history->count(),
            'by_status'    => $history->groupBy( 'status' )->map->count(),
            'by_channel'   => $history->groupBy( 'channel' )->map->count(),
            'by_severity'  => $history->groupBy( 'severity' )->map->count(),
            'success_rate' => $history->count() > 0
                ? round( $history->where( 'status', AlertHistory::STATUS_SENT )->count() / $history->count() * 100, 2 )
                : 0,
            'acknowledged_count' => $history->where( 'status', AlertHistory::STATUS_ACKNOWLEDGED )->count(),
            'period'             => [
                'start' => $startDate->toIso8601String(),
                'end'   => now()->toIso8601String(),
                'days'  => $days,
            ],
        ];
    }

    /**
     * Get unacknowledged alerts.
     *
     * @return Collection<int, AlertHistory>
     */
    public function getUnacknowledged( ?string $severity = null ): Collection
    {
        $query = AlertHistory::unacknowledged()->orderByDesc( 'created_at' );

        if ( $severity ) {
            $query->where( 'severity', $severity );
        }

        return $query->get();
    }

    /**
     * Acknowledge an alert.
     */
    public function acknowledge( int $alertId, ?int $userId = null ): bool
    {
        $alert = AlertHistory::find( $alertId );

        if ( ! $alert ) {
            return false;
        }

        $alert->acknowledge( $userId );

        return true;
    }

    /**
     * Bulk acknowledge alerts.
     *
     * @param  array<int, int>  $alertIds
     */
    public function bulkAcknowledge( array $alertIds, ?int $userId = null ): int
    {
        $count = 0;

        foreach ( $alertIds as $id ) {
            if ( $this->acknowledge( $id, $userId ) ) {
                $count++;
            }
        }

        return $count;
    }

    /**
     * Get default configuration.
     *
     * @return array<string, mixed>
     */
    protected function getDefaultConfig(): array
    {
        return [
            'enabled'          => true,
            'default_cooldown' => 15,
            'channels'         => [],
        ];
    }

    /**
     * Register default alert channels.
     */
    protected function registerDefaultChannels(): void
    {
        $channelConfigs = $this->config['channels'] ?? [];

        $this->registerChannel( new EmailChannel( $channelConfigs['email'] ?? [] ) );
        $this->registerChannel( new SlackChannel( $channelConfigs['slack'] ?? [] ) );
        $this->registerChannel( new PagerDutyChannel( $channelConfigs['pagerduty'] ?? [] ) );
    }

    /**
     * Find alert rules that match an anomaly.
     *
     * @return Collection<int, AlertRule>
     */
    protected function findMatchingRules( Anomaly $anomaly ): Collection
    {
        return AlertRule::active()
            ->get()
            ->filter( function ( AlertRule $rule ) use ( $anomaly ) {
                // Check if rule matches anomaly data
                $data = [
                    'category' => $anomaly->category,
                    'severity' => $anomaly->severity,
                    'score'    => $anomaly->score,
                    'detector' => $anomaly->detector,
                    'user_id'  => $anomaly->user_id,
                    ...$anomaly->metadata ?? [],
                ];

                return $rule->matchesConditions( $data );
            } );
    }

    /**
     * Execute an alert rule.
     *
     * @return array<string, mixed>
     */
    protected function executeRule( AlertRule $rule, Anomaly $anomaly ): array
    {
        // Check cooldown
        $contextKey = $this->getContextKey( $anomaly );
        if ( $rule->isOnCooldown( $contextKey ) ) {
            return ['skipped' => true, 'reason' => 'Rule is on cooldown'];
        }

        $results = [];

        // Send to each configured channel
        $ruleChannels = $rule->channels ?? [];

        foreach ( $ruleChannels as $channelName ) {
            $channel = $this->getChannel( $channelName );

            if ( ! $channel || ! $channel->isEnabled() ) {
                $results[ $channelName ] = [
                    'success' => false,
                    'error'   => 'Channel not available',
                ];
                continue;
            }

            $recipients              = $rule->getRecipientsForChannel( $channelName );
            $result                  = $this->sendAlert( $channel, $anomaly, $rule, $recipients );
            $results[ $channelName ] = $result;

            // Record in alert history
            $this->recordAlertHistory( $rule, $anomaly, $channelName, $result, $recipients );
        }

        // Start cooldown if at least one alert was sent
        $sentCount = collect( $results )->filter( fn ( $r ) => $r['success'] ?? false )->count();
        if ( $sentCount > 0 ) {
            $rule->startCooldown( $contextKey );
        }

        return [
            'channels_attempted' => count( $ruleChannels ),
            'channels_succeeded' => $sentCount,
            'details'            => $results,
        ];
    }

    /**
     * Record alert in history.
     *
     * @param  array<string, mixed>  $result
     * @param  array<int, string>  $recipients
     */
    protected function recordAlertHistory(
        AlertRule $rule,
        Anomaly $anomaly,
        string $channel,
        array $result,
        array $recipients,
    ): void {
        $status = ( $result['success'] ?? false )
            ? AlertHistory::STATUS_SENT
            : AlertHistory::STATUS_FAILED;

        AlertHistory::create( [
            'rule_id'       => $rule->id,
            'anomaly_id'    => $anomaly->id,
            'severity'      => $anomaly->severity,
            'channel'       => $channel,
            'recipient'     => implode( ', ', $recipients ),
            'status'        => $status,
            'message'       => $anomaly->description,
            'sent_at'       => AlertHistory::STATUS_SENT === $status ? now() : null,
            'error_message' => $result['error'] ?? null,
        ] );
    }

    /**
     * Get context key for cooldown.
     */
    protected function getContextKey( Anomaly $anomaly ): string
    {
        return "{$anomaly->category}:{$anomaly->user_id}:{$anomaly->detector}";
    }
}
