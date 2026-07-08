<?php

/**
 * IncidentResponseAgent.
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
use ArtisanPackUI\SecurityAnalytics\Models\ResponsePlaybook;
use ArtisanPackUI\SecurityAnalytics\Models\SecurityIncident;
use Illuminate\Contracts\JsonSchema\JsonSchema;
use InvalidArgumentException;
use Laravel\Ai\Contracts\Agent;
use Laravel\Ai\Contracts\HasStructuredOutput;

/**
 * Suggests next steps for a security incident.
 *
 * Reads the current {@see SecurityIncident} state, timeline of actions taken
 * so far, and any matching {@see ResponsePlaybook}s, and returns a small,
 * ordered list of next actions with rationale and risk. Suggestion only —
 * this agent never triggers any action; execution stays in the human's
 * hands via {@see \ArtisanPackUI\SecurityAnalytics\Analytics\IncidentResponse\IncidentResponder}.
 *
 * @package    ArtisanPack_UI
 * @subpackage SecurityAnalytics
 *
 * @since      1.1.0
 */
class IncidentResponseAgent extends ArtisanPackAgent implements Agent, HasStructuredOutput
{
    use CallsLaravelAi;

    /**
     * Feature key registered with the AI feature registry.
     *
     * @since 1.1.0
     *
     * @var string
     */
    public string $featureKey = 'security.incident_response';

    /**
     * Owning composer package.
     *
     * @since 1.1.0
     *
     * @var string
     */
    public string $package = 'artisanpack-ui/security-analytics';

    /**
     * Default model — Opus 4.7. Incident response reasoning is the highest-
     * stakes surface in this package and warrants the deepest model tier.
     *
     * @since 1.1.0
     *
     * @var string
     */
    public string $defaultModel = 'claude-opus-4-7';

    /**
     * Streaming off — the caller is a human deciding what to do next and
     * they want the full ordered list, not a partial stream.
     *
     * @since 1.1.0
     *
     * @var bool
     */
    public bool $stream = false;

    /**
     * System prompt describing the incident-response task.
     */
    public function instructions(): string
    {
        return <<<'PROMPT'
            You are advising an incident responder on next steps for an open
            security incident. You are given the incident state, its
            timeline of actions taken so far, and one or more playbooks that
            match the underlying anomaly.

            Rules:
              - Suggest 1-4 "suggested_next_actions", ordered by what should
                happen first. Do not repeat actions already recorded in the
                timeline unless there is a specific reason to re-run.
              - Each "step" is a concrete, single-line action a responder can
                execute (e.g. "Rotate the compromised API token") — not a
                philosophy.
              - Each "rationale" is one sentence explaining why this step is
                worth taking given the current state.
              - Each "risk" is one of: low, medium, high — reflecting the
                impact-if-wrong of taking this step (not the severity of the
                incident itself).
              - Do NOT trigger actions. Your output is advisory only.
              - Prefer steps that appear in the provided playbooks; only
                deviate when the playbook does not fit the current state.
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
                'suggested_next_actions' => [
                    'type'  => 'array',
                    'items' => [
                        'type'       => 'object',
                        'properties' => [
                            'step'      => [ 'type' => 'string' ],
                            'rationale' => [ 'type' => 'string' ],
                            'risk'      => [
                                'type' => 'string',
                                'enum' => [ 'low', 'medium', 'high' ],
                            ],
                        ],
                        'required' => [ 'step', 'rationale', 'risk' ],
                    ],
                ],
            ],
            'required' => [ 'suggested_next_actions' ],
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
        $suggestion = $schema->object( [
            'step'      => $schema->string()->required(),
            'rationale' => $schema->string()->required(),
            'risk'      => $schema->string()->enum( [ 'low', 'medium', 'high' ] )->required(),
        ] );

        return [
            'suggested_next_actions' => $schema->array()->items( $suggestion )->required(),
        ];
    }

    /**
     * Build the LLM input from incident state, timeline, and playbooks.
     *
     * Input shape:
     *   - int — a {@see SecurityIncident} id (agent hydrates state + playbooks).
     *   - {@see SecurityIncident} — the incident model.
     *   - array with keys `incident` (array), `timeline` (array), `playbooks`
     *     (array). All keys required when passing an array.
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
     * `instructions()`. The payload is a JSON snapshot of the incident
     * state, its action timeline, and any matching playbooks.
     */
    protected function buildUserPrompt(): string
    {
        $payload = $this->payload();

        return "Advise on next steps for the following security incident and return the structured JSON per the schema.\n\n"
            . 'Incident:' . "\n" . json_encode( $payload['incident'], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES ) . "\n\n"
            . 'Timeline so far:' . "\n" . json_encode( $payload['timeline'], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES ) . "\n\n"
            . 'Matching playbooks:' . "\n" . json_encode( $payload['playbooks'], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES );
    }

    /**
     * Fingerprint that includes the incident's updated_at so re-running the
     * agent after new timeline entries invalidates the cache.
     */
    protected function cacheFingerprint(): string
    {
        $payload = $this->payload();

        return 'incident-response:' . hash( 'sha256', json_encode( [
            'incident_id'    => $payload['incident']['id'] ?? null,
            'timeline_count' => count( $payload['timeline'] ?? [] ),
            'updated_at'     => $payload['incident']['updated_at'] ?? null,
        ] ) );
    }

    /**
     * @return array{ incident: array<string, mixed>, timeline: array<int, array<string, mixed>>, playbooks: array<int, array<string, mixed>> }
     */
    protected function payload(): array
    {
        $input = $this->input();

        if ( $input instanceof SecurityIncident ) {
            return $this->buildPayloadFromIncident( $input );
        }

        if ( is_int( $input ) ) {
            $incident = SecurityIncident::query()->find( $input );

            if ( null === $incident ) {
                throw new InvalidArgumentException(
                    sprintf( 'IncidentResponseAgent: SecurityIncident %d not found.', $input ),
                );
            }

            return $this->buildPayloadFromIncident( $incident );
        }

        if ( is_array( $input ) ) {
            $incident  = $input['incident'] ?? null;
            $timeline  = $input['timeline'] ?? null;
            $playbooks = $input['playbooks'] ?? null;

            if ( ! is_array( $incident ) || ! is_array( $timeline ) || ! is_array( $playbooks ) ) {
                throw new InvalidArgumentException(
                    'IncidentResponseAgent: array input requires `incident`, `timeline`, `playbooks` arrays.',
                );
            }

            return [
                'incident'  => $incident,
                'timeline'  => array_values( $timeline ),
                'playbooks' => array_values( $playbooks ),
            ];
        }

        throw new InvalidArgumentException( sprintf(
            'IncidentResponseAgent: unsupported input type %s.',
            get_debug_type( $input ),
        ) );
    }

    /**
     * @return array{ incident: array<string, mixed>, timeline: array<int, array<string, mixed>>, playbooks: array<int, array<string, mixed>> }
     */
    protected function buildPayloadFromIncident( SecurityIncident $incident ): array
    {
        $playbooks = [];

        if ( null !== $incident->sourceAnomaly ) {
            $playbooks = ResponsePlaybook::query()
                ->where( 'is_active', true )
                ->get()
                ->filter( fn ( ResponsePlaybook $playbook ) => $playbook->matchesAnomaly( $incident->sourceAnomaly ) )
                ->values()
                ->all();
        }

        return [
            'incident'  => $this->serializeIncident( $incident ),
            'timeline'  => array_values( $incident->actions_taken ?? [] ),
            'playbooks' => array_map( fn ( ResponsePlaybook $playbook ) => $this->serializePlaybook( $playbook ), $playbooks ),
        ];
    }

    /**
     * @return array<string, mixed>
     */
    protected function serializeIncident( SecurityIncident $incident ): array
    {
        return [
            'id'              => $incident->id,
            'incident_number' => $incident->incident_number,
            'title'           => $incident->title,
            'description'     => $incident->description,
            'severity'        => $incident->severity,
            'status'          => $incident->status,
            'category'        => $incident->category,
            'affected_users'  => $incident->affected_users ?? [],
            'affected_ips'    => $incident->affected_ips ?? [],
            'opened_at'       => $incident->opened_at?->toIso8601String(),
            'contained_at'    => $incident->contained_at?->toIso8601String(),
            'resolved_at'     => $incident->resolved_at?->toIso8601String(),
            'updated_at'      => $incident->updated_at?->toIso8601String(),
        ];
    }

    /**
     * @return array<string, mixed>
     */
    protected function serializePlaybook( ResponsePlaybook $playbook ): array
    {
        return [
            'id'                => $playbook->id,
            'name'              => $playbook->name,
            'description'       => $playbook->description,
            'actions'           => $playbook->getActionNames(),
            'requires_approval' => (bool) $playbook->requires_approval,
        ];
    }
}
