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
use ArtisanPackUI\SecurityAnalytics\AI\Concerns\CallsLaravelAi;
use ArtisanPackUI\SecurityAnalytics\Models\SecurityEvent;
use Illuminate\Contracts\JsonSchema\JsonSchema;
use InvalidArgumentException;
use Laravel\Ai\Contracts\Agent;
use Laravel\Ai\Contracts\HasStructuredOutput;

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
class ThreatTriageAgent extends ArtisanPackAgent implements Agent, HasStructuredOutput
{
    use CallsLaravelAi;

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
     *
     * Layered precedence: the base pipeline computes a resolved instructions
     * string (settings-store override → config override → class default) and
     * hands it to `execute()`, which stashes it on the trait's
     * `$currentInstructions` for the duration of the run. `laravel/ai` reads
     * `instructions()` directly off the agent, so this method must consult
     * the runtime override first.
     */
    public function instructions(): string
    {
        return $this->currentInstructions ?? $this->defaultInstructions();
    }

    /**
     * Structured-output schema for laravel/ai. Single source of truth — the
     * trait derives {@see outputSchema()} from this via `ObjectSchema`.
     *
     * @return array<string, \Illuminate\JsonSchema\Types\Type>
     */
    public function schema( JsonSchema $schema ): array
    {
        $action = $schema->object( [
            'step'    => $schema->string()->required(),
            'urgency' => $schema->string()->enum( [ 'immediate', 'high', 'medium', 'low' ] )->required(),
        ] );

        return [
            'severity'            => $schema->string()->enum( [ 'info', 'low', 'medium', 'high', 'critical' ] )->required(),
            'summary'             => $schema->string()->required(),
            'recommended_actions' => $schema->array()->items( $action )->required(),
            'related_events'      => $schema->array()->items( $schema->integer() )->required(),
        ];
    }

    /**
     * Class-default system prompt. Consumers override via the AI Settings
     * admin UI or `artisanpack.ai.features.security.threat_triage.instructions`.
     */
    protected function defaultInstructions(): string
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
        return $this->promptStructured(
            credentials: $credentials,
            model: $model,
            instructions: $instructions,
            userPrompt: $this->buildUserPrompt(),
        );
    }

    /**
     * Assemble the user-role prompt sent alongside the system-role
     * `instructions()`. The payload is a JSON snapshot of the event, its
     * related-event window, and any extra context.
     */
    protected function buildUserPrompt(): string
    {
        $payload = $this->payload();

        return "Triage the following security event and return the structured JSON per the schema.\n\n"
            . 'Event:' . "\n" . json_encode( $payload['event'], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES ) . "\n\n"
            . 'Recent related events:' . "\n" . json_encode( $payload['related'], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES ) . "\n\n"
            . 'Additional context:' . "\n" . json_encode( $payload['context'], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES );
    }

    /**
     * Deterministic cache fingerprint for structured inputs. The base class
     * throws for non-scalar inputs; triage always takes a model or an array,
     * so override with an event-id-and-context digest.
     */
    protected function cacheFingerprint(): string
    {
        $encoded = json_encode(
            $this->payload(),
            JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE,
        );

        // Under strict types, hash() rejects a false return. Fall through
        // to a deterministic marker so an unencodable payload doesn't crash
        // the base pipeline before execute() runs.
        if ( false === $encoded ) {
            $encoded = 'threat-triage:unencodable-payload';
        }

        return 'threat-triage:' . hash( 'sha256', $encoded );
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
        // Empty closure-wheres are a no-op in Eloquent, which would return
        // arbitrary recent events across all tenants/users and leak their
        // PII into the LLM prompt. Skip the query entirely when we have no
        // correlation keys to filter on.
        if (
            null === $event->fingerprint
            && null === $event->ip_address
            && null === $event->user_id
        ) {
            return [];
        }

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
}
