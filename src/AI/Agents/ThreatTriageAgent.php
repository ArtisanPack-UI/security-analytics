<?php

/**
 * ThreatTriageAgent.
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
use ArtisanPackUI\SecurityAnalytics\Models\SecurityEvent;
use InvalidArgumentException;

/**
 * Generates a plain-language triage of a security event.
 *
 * Given a raw {@see SecurityEvent} (or an event id / array of event data) the
 * agent returns a structured triage: normalized severity, a short summary the
 * on-call responder can scan, an ordered list of recommended actions with
 * urgency, and the ids of related events surfaced from the last 24 hours.
 *
 * The output is advisory only — the agent never triggers any response action
 * itself. See {@see \ArtisanPackUI\SecurityAnalytics\Analytics\IncidentResponse\IncidentResponder}
 * for the execution surface.
 *
 * @package    ArtisanPack_UI
 * @subpackage SecurityAnalytics
 *
 * @since      1.1.0
 */
class ThreatTriageAgent extends ArtisanPackAgent
{
    /**
     * Feature key registered with the AI feature registry.
     *
     * @since 1.1.0
     *
     * @var string
     */
    public string $featureKey = 'security.threat_triage';

    /**
     * Owning composer package.
     *
     * @since 1.1.0
     *
     * @var string
     */
    public string $package = 'artisanpack-ui/security-analytics';

    /**
     * Default model — Sonnet 4.6 balances triage speed with sufficient
     * reasoning to weigh related-event context.
     *
     * @since 1.1.0
     *
     * @var string
     */
    public string $defaultModel = 'claude-sonnet-4-6';

    /**
     * Streaming is off — triage output is short and consumers want the full
     * structured payload before rendering.
     *
     * @since 1.1.0
     *
     * @var bool
     */
    public bool $stream = false;

    /**
     * System prompt describing the triage task.
     */
    public function instructions(): string
    {
        return <<<'PROMPT'
            You are a senior on-call security responder. You are given a
            security event, a small window of recent related events, and
            optional user/asset context. Your job is to produce a short,
            actionable triage a human responder can scan in under 30 seconds.

            Rules:
              - Choose exactly one severity from: info, low, medium, high, critical.
              - Write "summary" as one or two sentences, plain language, no jargon.
              - Provide 1-4 "recommended_actions" ordered from highest urgency to
                lowest. Each action's "urgency" is one of: immediate, high,
                medium, low.
              - Only include ids in "related_events" that were passed in as
                related context. Do not invent event ids.
              - You never trigger actions. Your output is advisory only.
            PROMPT;
    }

    /**
     * Structured output schema. The base pipeline validates the LLM response
     * against this shape before returning.
     *
     * @return array<string, mixed>
     */
    public function outputSchema(): array
    {
        return [
            'type'       => 'object',
            'properties' => [
                'severity' => [
                    'type' => 'string',
                    'enum' => [ 'info', 'low', 'medium', 'high', 'critical' ],
                ],
                'summary'             => [ 'type' => 'string' ],
                'recommended_actions' => [
                    'type'  => 'array',
                    'items' => [
                        'type'       => 'object',
                        'properties' => [
                            'step'    => [ 'type' => 'string' ],
                            'urgency' => [
                                'type' => 'string',
                                'enum' => [ 'immediate', 'high', 'medium', 'low' ],
                            ],
                        ],
                        'required' => [ 'step', 'urgency' ],
                    ],
                ],
                'related_events' => [
                    'type'  => 'array',
                    'items' => [ 'type' => 'integer' ],
                ],
            ],
            'required' => [ 'severity', 'summary', 'recommended_actions', 'related_events' ],
        ];
    }

    /**
     * Build the LLM input from the raw event, recent-event window, and
     * optional user context.
     *
     * Input shape accepted by {@see ArtisanPackAgent::for()}:
     *   - int — a {@see SecurityEvent} id
     *   - {@see SecurityEvent} — the model itself
     *   - array with keys `event` (event array), `related` (array of events),
     *     `context` (arbitrary context)
     *
     * The prompt returns everything the LLM needs; nothing here talks to
     * providers directly. Base `execute()` overrides call `laravel/ai`.
     *
     * @param  Credentials  $credentials   Resolved credentials.
     * @param  string       $model         Resolved model identifier.
     * @param  string       $instructions  Resolved system prompt.
     *
     * @return array{ output: array<string, mixed>, input_tokens: int, output_tokens: int }
     */
    protected function execute( Credentials $credentials, string $model, string $instructions ): array
    {
        // Concrete provider delegation lands with laravel/ai wiring in a
        // follow-up. For now the pipeline (feature gate → credential resolve
        // → cache → dispatch) is exercised against the resolved payload
        // below, which mirrors what the provider call will consume.
        $payload = $this->payload();

        return [
            'output'        => $this->fallbackOutput( $payload ),
            'input_tokens'  => 0,
            'output_tokens' => 0,
        ];
    }

    /**
     * Deterministic cache fingerprint for structured inputs. The base class
     * throws for non-scalar inputs; triage always takes a model or an array,
     * so override with an event-id-and-context digest.
     */
    protected function cacheFingerprint(): string
    {
        $payload = $this->payload();

        return 'threat-triage:' . hash(
            'sha256',
            json_encode( $payload, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE ),
        );
    }

    /**
     * Normalize the input into a `{event, related, context}` payload the
     * provider (and cache fingerprint) can rely on.
     *
     * @return array{ event: array<string, mixed>, related: array<int, array<string, mixed>>, context: array<string, mixed> }
     */
    protected function payload(): array
    {
        $input = $this->input();

        if ( $input instanceof SecurityEvent ) {
            return [
                'event'   => $this->serializeEvent( $input ),
                'related' => $this->serializeRelated( $this->fetchRelated( $input ) ),
                'context' => [],
            ];
        }

        if ( is_int( $input ) ) {
            $event = SecurityEvent::query()->find( $input );

            if ( null === $event ) {
                throw new InvalidArgumentException(
                    sprintf( 'ThreatTriageAgent: SecurityEvent %d not found.', $input ),
                );
            }

            return [
                'event'   => $this->serializeEvent( $event ),
                'related' => $this->serializeRelated( $this->fetchRelated( $event ) ),
                'context' => [],
            ];
        }

        if ( is_array( $input ) ) {
            $event   = $input['event'] ?? [];
            $related = $input['related'] ?? [];
            $context = $input['context'] ?? [];

            if ( ! is_array( $event ) || ! is_array( $related ) || ! is_array( $context ) ) {
                throw new InvalidArgumentException(
                    'ThreatTriageAgent: array input must have `event`, `related`, `context` keys as arrays.',
                );
            }

            return [
                'event'   => $event,
                'related' => array_values( $related ),
                'context' => $context,
            ];
        }

        throw new InvalidArgumentException( sprintf(
            'ThreatTriageAgent: unsupported input type %s.',
            get_debug_type( $input ),
        ) );
    }

    /**
     * Recent related events sharing the same fingerprint, IP, or user in the
     * last 24 hours (excluding the primary event).
     *
     * @return array<int, SecurityEvent>
     */
    protected function fetchRelated( SecurityEvent $event ): array
    {
        return SecurityEvent::query()
            ->where( 'id', '!=', $event->id )
            ->where( function ( $query ) use ( $event ): void {
                if ( null !== $event->fingerprint ) {
                    $query->orWhere( 'fingerprint', $event->fingerprint );
                }

                if ( null !== $event->ip_address ) {
                    $query->orWhere( 'ip_address', $event->ip_address );
                }

                if ( null !== $event->user_id ) {
                    $query->orWhere( 'user_id', $event->user_id );
                }
            } )
            ->recent( 24 )
            ->latest( 'created_at' )
            ->limit( 10 )
            ->get()
            ->all();
    }

    /**
     * @return array<string, mixed>
     */
    protected function serializeEvent( SecurityEvent $event ): array
    {
        return [
            'id'          => $event->id,
            'event_type'  => $event->event_type,
            'event_name'  => $event->event_name,
            'severity'    => $event->severity,
            'user_id'     => $event->user_id,
            'ip_address'  => $event->ip_address,
            'url'         => $event->url,
            'method'      => $event->method,
            'status_code' => $event->status_code,
            'details'     => $event->details ?? [],
            'fingerprint' => $event->fingerprint,
            'created_at'  => $event->created_at?->toIso8601String(),
        ];
    }

    /**
     * @param  array<int, SecurityEvent>  $events
     *
     * @return array<int, array<string, mixed>>
     */
    protected function serializeRelated( array $events ): array
    {
        return array_map( fn ( SecurityEvent $event ) => $this->serializeEvent( $event ), $events );
    }

    /**
     * Neutral fallback used while the provider call is stubbed. Downstream
     * `execute()` will replace this once laravel/ai wiring lands; keeping it
     * shape-valid lets the Livewire trigger surface render without failing
     * schema validation.
     *
     * @param  array<string, mixed>  $payload
     *
     * @return array<string, mixed>
     */
    protected function fallbackOutput( array $payload ): array
    {
        $event    = $payload['event'] ?? [];
        $severity = is_string( $event['severity'] ?? null ) ? $event['severity'] : 'info';
        $summary  = sprintf(
            'Threat triage is queued for event %s. Provide API credentials to enable the LLM-backed summary.',
            (string) ( $event['id'] ?? 'unknown' ),
        );

        $related = array_values( array_filter( array_map(
            static fn ( array $item ): ?int => isset( $item['id'] ) && is_numeric( $item['id'] ) ? (int) $item['id'] : null,
            $payload['related'] ?? [],
        ) ) );

        return [
            'severity'            => in_array(
                $severity,
                [ 'info', 'low', 'medium', 'high', 'critical' ],
                true,
            ) ? $severity : 'info',
            'summary'             => $summary,
            'recommended_actions' => [],
            'related_events'      => $related,
        ];
    }
}
