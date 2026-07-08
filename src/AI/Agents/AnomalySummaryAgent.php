<?php

/**
 * AnomalySummaryAgent.
 *
 * @package    ArtisanPack_UI
 * @subpackage SecurityAnalytics
 *
 * @author     Jacob Martella <support@artisanpackui.dev>
 *
 * @since      1.1.0
 */

declare( strict_types=1 );

namespace ArtisanPackUI\SecurityAnalytics\AI\Agents;

use ArtisanPackUI\Ai\Agents\ArtisanPackAgent;
use ArtisanPackUI\Ai\Credentials\Credentials;
use ArtisanPackUI\SecurityAnalytics\AI\Concerns\CallsLaravelAi;
use ArtisanPackUI\SecurityAnalytics\Models\Anomaly;
use Illuminate\Contracts\JsonSchema\JsonSchema;
use InvalidArgumentException;
use Laravel\Ai\Contracts\Agent;
use Laravel\Ai\Contracts\HasStructuredOutput;

/**
 * Produces a periodic (daily / weekly) digest of unusual security activity.
 *
 * Intended for stakeholders who don't watch the SIEM in real time. Takes a
 * window (in hours), pulls recent anomalies + aggregate statistics, and
 * returns a structured digest: headline, plain-language body, top-severity
 * breakdown, top detectors, and any recommended follow-ups.
 *
 * When {@see \ArtisanPackUI\Ai\Agents\SummarizationAgent} lands in
 * `artisanpack-ui/ai`, this class will move to extend it and inherit the
 * shared summary framing. Until then it extends {@see ArtisanPackAgent}
 * directly so the digest surface is available in v1.1.
 *
 * @package    ArtisanPack_UI
 * @subpackage SecurityAnalytics
 *
 * @since      1.1.0
 */
class AnomalySummaryAgent extends ArtisanPackAgent implements Agent, HasStructuredOutput
{
    use CallsLaravelAi;

    /**
     * Feature key registered with the AI feature registry.
     *
     * @since 1.1.0
     *
     * @var string
     */
    public string $featureKey = 'security.anomaly_summary';

    /**
     * Owning composer package.
     *
     * @since 1.1.0
     *
     * @var string
     */
    public string $package = 'artisanpack-ui/security-analytics';

    /**
     * Default model — Haiku is fast and cheap enough for a scheduled digest.
     * Consumers who want richer prose can override with {@see withModel()}.
     *
     * @since 1.1.0
     *
     * @var string
     */
    public string $defaultModel = 'claude-haiku-4-5-20251001';

    /**
     * Streaming on by default — digests are longer than triage output and
     * responders appreciate incremental rendering in the email preview.
     *
     * @since 1.1.0
     *
     * @var bool
     */
    public bool $stream = true;

    /**
     * System prompt describing the digest task.
     */
    public function instructions(): string
    {
        return <<<'PROMPT'
            You are writing a periodic security digest for a stakeholder who
            reads it out-of-band from the SIEM. You are given a window (in
            hours), a list of anomalies detected in that window, and a small
            aggregate summary. Your job is to produce a scannable digest.

            Rules:
              - "headline" is a single sentence (<= 100 chars) that captures
                the most important thing in the window. If nothing notable
                happened, say so.
              - "body" is 3-6 sentences of plain-language narrative. No
                bulleted lists. No jargon. No fake precision (do not invent
                counts you were not given).
              - "top_severities" lists the top three severity buckets by
                count, ordered high to low. Use severities exactly as given
                in the input (info, low, medium, high, critical). Do not
                invent buckets that have zero anomalies.
              - "top_detectors" lists up to three detectors that produced the
                most anomalies in the window.
              - "recommended_followups" is 0-3 concrete follow-ups a human
                could act on this week. Empty list is fine.
            PROMPT;
    }

    /**
     * @return array<string, mixed>
     */
    public function outputSchema(): array
    {
        return [
            'type'       => 'object',
            'properties' => [
                'headline'       => [ 'type' => 'string' ],
                'body'           => [ 'type' => 'string' ],
                'top_severities' => [
                    'type'  => 'array',
                    'items' => [
                        'type'       => 'object',
                        'properties' => [
                            'severity' => [
                                'type' => 'string',
                                'enum' => [ 'info', 'low', 'medium', 'high', 'critical' ],
                            ],
                            'count' => [ 'type' => 'integer' ],
                        ],
                        'required' => [ 'severity', 'count' ],
                    ],
                ],
                'top_detectors' => [
                    'type'  => 'array',
                    'items' => [
                        'type'       => 'object',
                        'properties' => [
                            'detector' => [ 'type' => 'string' ],
                            'count'    => [ 'type' => 'integer' ],
                        ],
                        'required' => [ 'detector', 'count' ],
                    ],
                ],
                'recommended_followups' => [
                    'type'  => 'array',
                    'items' => [ 'type' => 'string' ],
                ],
            ],
            'required' => [ 'headline', 'body', 'top_severities', 'top_detectors', 'recommended_followups' ],
        ];
    }

    /**
     * Structured-output schema for laravel/ai. Mirrors {@see outputSchema()}
     * but uses the fluent {@see JsonSchema} builder that the provider layer
     * expects.
     *
     * @return array<string, \Illuminate\JsonSchema\Types\Type>
     */
    public function schema( JsonSchema $schema ): array
    {
        $severityBucket = $schema->object( [
            'severity' => $schema->string()->enum( [ 'info', 'low', 'medium', 'high', 'critical' ] )->required(),
            'count'    => $schema->integer()->required(),
        ] );

        $detectorBucket = $schema->object( [
            'detector' => $schema->string()->required(),
            'count'    => $schema->integer()->required(),
        ] );

        return [
            'headline'              => $schema->string()->required(),
            'body'                  => $schema->string()->required(),
            'top_severities'        => $schema->array()->items( $severityBucket )->required(),
            'top_detectors'         => $schema->array()->items( $detectorBucket )->required(),
            'recommended_followups' => $schema->array()->items( $schema->string() )->required(),
        ];
    }

    /**
     * Call the provider with the digest payload.
     *
     * Input shape:
     *   - int — window in hours (agent pulls the anomalies itself).
     *   - array with keys `window_hours` (int), `anomalies` (array of
     *     anomaly rows), `statistics` (aggregate array). Any missing key is
     *     hydrated from the query layer.
     *
     * @param  Credentials  $credentials   Resolved credentials.
     * @param  string       $model         Resolved model identifier.
     * @param  string       $instructions  Resolved system prompt.
     *
     * @return array{ output: array<string, mixed>, input_tokens: int, output_tokens: int }
     */
    protected function execute( Credentials $credentials, string $model, string $instructions ): array
    {
        return $this->promptStructured(
            credentials: $credentials,
            model: $model,
            userPrompt: $this->buildUserPrompt(),
        );
    }

    /**
     * Assemble the user-role prompt sent alongside the system-role
     * `instructions()`. The payload is a JSON snapshot of the anomaly
     * window plus aggregate statistics.
     */
    protected function buildUserPrompt(): string
    {
        $payload = $this->payload();

        return "Produce a security anomaly digest and return the structured JSON per the schema.\n\n"
            . 'Window (hours): ' . $payload['window_hours'] . "\n\n"
            . 'Anomalies in window:' . "\n" . json_encode( $payload['anomalies'], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES ) . "\n\n"
            . 'Aggregate statistics:' . "\n" . json_encode( $payload['statistics'], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES );
    }

    /**
     * Digest fingerprint keyed by window + anomaly ids so a re-run with the
     * same data hits cache.
     */
    protected function cacheFingerprint(): string
    {
        $payload = $this->payload();

        $anomalyIds = array_values( array_filter( array_map(
            static fn ( $item ) => is_array( $item ) && isset( $item['id'] ) ? (int) $item['id'] : null,
            $payload['anomalies'] ?? [],
        ) ) );

        sort( $anomalyIds );

        return 'anomaly-summary:' . hash( 'sha256', json_encode( [
            'window'    => $payload['window_hours'] ?? 24,
            'anomalies' => $anomalyIds,
        ] ) );
    }

    /**
     * @return array{ window_hours: int, anomalies: array<int, array<string, mixed>>, statistics: array<string, mixed> }
     */
    protected function payload(): array
    {
        $input = $this->input();

        if ( is_int( $input ) ) {
            return $this->buildPayloadFromWindow( $input );
        }

        if ( is_array( $input ) ) {
            $window = $input['window_hours'] ?? 24;

            if ( ! is_int( $window ) ) {
                throw new InvalidArgumentException(
                    'AnomalySummaryAgent: `window_hours` must be an int.',
                );
            }

            return [
                'window_hours' => $window,
                'anomalies'    => array_values( $input['anomalies'] ?? $this->fetchAnomalies( $window ) ),
                'statistics'   => $input['statistics'] ?? $this->buildStatistics( $window ),
            ];
        }

        throw new InvalidArgumentException( sprintf(
            'AnomalySummaryAgent: unsupported input type %s.',
            get_debug_type( $input ),
        ) );
    }

    /**
     * @return array{ window_hours: int, anomalies: array<int, array<string, mixed>>, statistics: array<string, mixed> }
     */
    protected function buildPayloadFromWindow( int $hours ): array
    {
        return [
            'window_hours' => $hours,
            'anomalies'    => $this->fetchAnomalies( $hours ),
            'statistics'   => $this->buildStatistics( $hours ),
        ];
    }

    /**
     * @return array<int, array<string, mixed>>
     */
    protected function fetchAnomalies( int $hours ): array
    {
        return Anomaly::query()
            ->where( 'detected_at', '>=', now()->subHours( $hours ) )
            ->orderByDesc( 'detected_at' )
            ->limit( 50 )
            ->get()
            ->map( fn ( Anomaly $anomaly ) => [
                'id'          => $anomaly->id,
                'detector'    => $anomaly->detector,
                'category'    => $anomaly->category,
                'severity'    => $anomaly->severity,
                'score'       => $anomaly->score,
                'description' => $anomaly->description,
                'detected_at' => $anomaly->detected_at?->toIso8601String(),
            ] )
            ->all();
    }

    /**
     * @return array<string, mixed>
     */
    protected function buildStatistics( int $hours ): array
    {
        $anomalies = Anomaly::query()
            ->where( 'detected_at', '>=', now()->subHours( $hours ) )
            ->get();

        $bySeverity = $anomalies->groupBy( 'severity' )->map->count()->toArray();
        $byDetector = $anomalies->groupBy( 'detector' )->map->count()->toArray();

        arsort( $bySeverity );
        arsort( $byDetector );

        return [
            'total_count' => $anomalies->count(),
            'by_severity' => $bySeverity,
            'by_detector' => $byDetector,
        ];
    }
}
