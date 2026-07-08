<?php

/**
 * Shared laravel/ai wiring for the security-analytics AI agents.
 *
 * @package    ArtisanPack_UI
 * @subpackage SecurityAnalytics
 *
 * @author     Jacob Martella <support@artisanpackui.dev>
 *
 * @since      1.1.0
 */

declare( strict_types=1 );

namespace ArtisanPackUI\SecurityAnalytics\AI\Concerns;

use ArtisanPackUI\Ai\Credentials\Credentials;
use Illuminate\JsonSchema\JsonSchemaTypeFactory;
use Laravel\Ai\Ai;
use Laravel\Ai\ObjectSchema;
use Laravel\Ai\Promptable;
use Laravel\Ai\Responses\StructuredAgentResponse;
use RuntimeException;

/**
 * Concrete provider delegation for the three security-analytics agents.
 *
 * Each agent extends {@see \ArtisanPackUI\Ai\Agents\ArtisanPackAgent} and
 * inherits the frozen v1.x pipeline (feature gate, credential resolver,
 * cache, `AgentUsageRecorded` dispatch). This trait pulls in `laravel/ai`'s
 * {@see Promptable} so subclasses can call `$this->promptStructured()` from
 * their `execute()` implementation to talk to the resolved provider.
 *
 * @package    ArtisanPack_UI
 * @subpackage SecurityAnalytics
 *
 * @since      1.1.0
 */
trait CallsLaravelAi
{
    use Promptable;

    /**
     * Resolved instructions the base pipeline computed for this run.
     *
     * Populated by {@see promptStructured()} for the duration of a single
     * `execute()` call and consulted by the subclass's `instructions()`
     * override. `laravel/ai` calls `$agent->instructions()` directly on the
     * agent (see `Providers\Concerns\GeneratesText.php`), so any settings-
     * or config-layer override must land in the return value of that method
     * — not just on the `execute()` argument.
     *
     * @since 1.1.0
     */
    protected ?string $currentInstructions = null;

    /**
     * Materialize the fluent schema into the array-shaped representation
     * the base {@see ArtisanPackAgent::outputSchema()} contract expects.
     *
     * Single source of truth: subclasses implement `schema()` only; the
     * required-keys derivation for {@see unwrapStructured()} and any
     * consumer that wants the plain JSON Schema flow through here.
     *
     * @since 1.1.0
     *
     * @return array<string, mixed>
     */
    public function outputSchema(): array
    {
        return ( new ObjectSchema( $this->schema( new JsonSchemaTypeFactory() ) ) )->toSchema();
    }

    /**
     * Invoke `laravel/ai` and unpack the structured response into the
     * envelope the {@see ArtisanPackAgent::run()} pipeline expects.
     *
     * The credentials passed here come from the base pipeline's resolver
     * chain — they're pushed into the `ai.providers.{provider}` config
     * slot and the manager's cached provider is invalidated so the next
     * resolution rebuilds against the right key / base URL. Scoped to the
     * current invocation via try/finally.
     *
     * @param  Credentials  $credentials   Resolved provider credentials.
     * @param  string       $model         Resolved model identifier.
     * @param  string       $instructions  Resolved system prompt (may layer over the class default).
     * @param  string       $userPrompt    The user-role prompt body.
     *
     * @return array{ output: array<string, mixed>, input_tokens: int, output_tokens: int }
     */
    protected function promptStructured(
        Credentials $credentials,
        string $model,
        string $instructions,
        string $userPrompt,
    ): array {
        $this->configureProvider( $credentials );

        // Store the resolved instructions so the subclass's overridden
        // `instructions()` method returns them when `laravel/ai` reads them
        // off the agent. Guarded by try/finally so no leakage between runs.
        $this->currentInstructions = $instructions;

        try {
            $response = $this->prompt(
                prompt: $userPrompt,
                provider: $credentials->provider,
                model: $model,
            );
        } finally {
            $this->currentInstructions = null;
        }

        if ( ! $response instanceof StructuredAgentResponse ) {
            throw new RuntimeException( sprintf(
                'Expected a StructuredAgentResponse from provider [%s] for model [%s]; got %s.',
                $credentials->provider,
                $model,
                get_debug_type( $response ),
            ) );
        }

        return [
            'output'        => $this->unwrapStructured( $response->structured ),
            'input_tokens'  => $response->usage->promptTokens,
            'output_tokens' => $response->usage->completionTokens,
        ];
    }

    /**
     * Unwrap a single-key envelope that some models (notably Anthropic's
     * Opus family) add around structured tool call arguments — e.g.
     * `{"$PARAMETER_NAME": {actual}}` or `{"data": {actual}}` — when they
     * treat the tool's `input_schema` as an outer container rather than
     * the payload itself.
     *
     * Only unwraps when the outer structure is a single-key associative
     * array whose value is an array that shares at least one required
     * top-level key with {@see outputSchema()}. That intersection check
     * is sufficient: a correctly-shaped flat response like
     * `{"only_required_key": [...list...]}` has integer keys inside the
     * list, so the intersection is empty and the response passes through
     * untouched. A double-wrap under the same required key like
     * `{"only_required_key": {"only_required_key": [...list...]}}` has a
     * string-keyed inner map that DOES intersect, so we unwrap.
     *
     * @param  array<string, mixed>  $structured
     *
     * @return array<string, mixed>
     */
    protected function unwrapStructured( array $structured ): array
    {
        if ( 1 !== count( $structured ) ) {
            return $structured;
        }

        $inner = reset( $structured );

        if ( ! is_array( $inner ) ) {
            return $structured;
        }

        $expectedRequired = $this->outputSchema()['required'] ?? [];

        if ( ! is_array( $expectedRequired ) || [] === $expectedRequired ) {
            return $structured;
        }

        $overlap = array_intersect( $expectedRequired, array_keys( $inner ) );

        return count( $overlap ) > 0 ? $inner : $structured;
    }

    /**
     * Push the resolved credentials into `laravel/ai`'s runtime config so
     * the manager wires the right API key / base URL when the driver spins
     * up, then invalidate any cached provider instance so the next
     * resolution rebuilds against the new config.
     *
     * `laravel/ai`'s `AiManager` extends `MultipleInstanceManager`, which
     * caches resolved providers in `$this->instances[$name]`, and
     * `Provider::__construct` snapshots the config array by value. Without
     * the `forgetInstance()` call, a second agent's credentials would be
     * silently ignored — the first key seen by the process would be reused
     * for every subsequent call.
     *
     * Also read-modify-writes existing per-provider config so `.driver`
     * and other fields set by the host app's `config/ai.php` are preserved.
     */
    protected function configureProvider( Credentials $credentials ): void
    {
        $providerKey = 'ai.providers.' . $credentials->provider;
        $existing    = (array) config( $providerKey, [] );

        $existing['key'] = $credentials->apiKey;

        if ( null !== $credentials->baseUrl && '' !== $credentials->baseUrl ) {
            $existing['url'] = $credentials->baseUrl;
        }

        // Preserve the driver slug if the host app hasn't defined a config
        // block yet — the manager needs a `.driver` key to resolve.
        if ( ! isset( $existing['driver'] ) ) {
            $existing['driver'] = $credentials->provider;
        }

        config()->set( $providerKey, $existing );

        Ai::forgetInstance( $credentials->provider );
    }
}
