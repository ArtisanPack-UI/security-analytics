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
     * Invoke `laravel/ai` and unpack the structured response into the
     * envelope the {@see ArtisanPackAgent::run()} pipeline expects.
     *
     * The credentials passed here come from the base pipeline's resolver
     * chain — they're pushed into the `ai.providers.{provider}` config
     * slot so `laravel/ai`'s manager resolves against the right key /
     * base URL. This is scoped to the current request and safe to repeat.
     *
     * @param  Credentials  $credentials  Resolved provider credentials.
     * @param  string       $model        Resolved model identifier.
     * @param  string       $userPrompt   The user-role prompt body.
     *
     * @return array{ output: array<string, mixed>, input_tokens: int, output_tokens: int }
     */
    protected function promptStructured(
        Credentials $credentials,
        string $model,
        string $userPrompt,
    ): array {
        $this->configureProvider( $credentials );

        $response = $this->prompt(
            prompt: $userPrompt,
            provider: $credentials->provider,
            model: $model,
        );

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
     * Only unwraps when:
     *   - the outer structure is a single-key associative array
     *   - the single value is an array that shares at least one required
     *     top-level key with {@see outputSchema()}
     *
     * Multi-key responses (the normal case) pass through untouched.
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

        // If the outer key is already one of the required top-level fields,
        // don't unwrap — that would strip a valid single-required-field
        // response.
        $outerKey = array_key_first( $structured );

        if ( in_array( $outerKey, $expectedRequired, true ) ) {
            return $structured;
        }

        $overlap = array_intersect( $expectedRequired, array_keys( $inner ) );

        return count( $overlap ) > 0 ? $inner : $structured;
    }

    /**
     * Push the resolved credentials into `laravel/ai`'s runtime config so
     * the manager wires the right API key / base URL when the driver spins
     * up. Idempotent within a request.
     */
    protected function configureProvider( Credentials $credentials ): void
    {
        $providerKey = 'ai.providers.' . $credentials->provider;

        config()->set( $providerKey . '.key', $credentials->apiKey );

        if ( null !== $credentials->baseUrl && '' !== $credentials->baseUrl ) {
            config()->set( $providerKey . '.url', $credentials->baseUrl );
        }
    }
}
