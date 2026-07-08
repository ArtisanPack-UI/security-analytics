---
title: AI features
---

# AI features

`v1.1.0` adds three AI-assisted surfaces to the package, built on top of `artisanpack-ui/ai`. Each is opt-in (togglable at runtime via the shared feature registry), advisory-only (nothing runs automatically), and short-circuits cleanly when the toggle is off or when credentials cannot be resolved — no LLM calls happen in either case.

## The three features

| Feature key | Agent class | Livewire component | Default model | Purpose |
|---|---|---|---|---|
| `security.threat_triage` | `ThreatTriageAgent` | `ThreatTriagePanel` | `claude-sonnet-4-6` | Plain-language severity + recommended actions for a single `SecurityEvent`. |
| `security.anomaly_summary` | `AnomalySummaryAgent` | `AnomalySummaryPanel` | `claude-haiku-4-5-20251001` | Periodic digest of unusual events over a configurable window (1–720 hours). |
| `security.incident_response` | `IncidentResponseAgent` | `IncidentResponsePanel` | `claude-opus-4-7` | Advisory-only next-step suggestions for an open incident. Never triggers actions. |

All three implement `Laravel\Ai\Contracts\Agent` and `Laravel\Ai\Contracts\HasStructuredOutput`, so the response is validated JSON matching each agent's schema — no free-text parsing on your side.

## Discovery

The service provider exposes an `aiFeatures()` method that `artisanpack-ui/ai`'s boot pass walks looking for feature registrations:

```php
public function aiFeatures(): array
{
    return [
        'security.threat_triage'     => [ 'agent' => ThreatTriageAgent::class, ... ],
        'security.anomaly_summary'   => [ 'agent' => AnomalySummaryAgent::class, ... ],
        'security.incident_response' => [ 'agent' => IncidentResponseAgent::class, ... ],
    ];
}
```

No manual registration on the host app's side. If `artisanpack-ui/ai` isn't installed the discovery pass never runs and the features stay dormant.

## Livewire panels

Each agent has a matching Livewire trigger panel registered under a namespaced tag. Drop them into any Blade view:

```blade
{{-- On the security-event detail surface --}}
<livewire:security-analytics.threat-triage-panel :event-id="$event->id" />

{{-- Somewhere on the dashboard --}}
<livewire:security-analytics.anomaly-summary-panel />

{{-- On the incident detail surface --}}
<livewire:security-analytics.incident-response-panel :incident-id="$incident->id" />
```

Each panel:

- Gates on the standard `view-security-events` / `view-security-dashboard` abilities
- Marks target IDs `#[Locked]` so the client can't rewire the target via the wire protocol
- Renders a disabled state when the feature is toggled off or credentials aren't configured (no LLM call fires)
- Logs any provider exception server-side and shows the user a generic error message (so Guzzle stack traces don't leak API keys into the DOM)

### Shipped Blade views

Plain HTML + Tailwind by design — the package doesn't depend on `artisanpack-ui/livewire-ui-components`. Override the shipped views by shadowing them:

```
resources/views/vendor/security-analytics/livewire/threat-triage-panel.blade.php
resources/views/vendor/security-analytics/livewire/anomaly-summary-panel.blade.php
resources/views/vendor/security-analytics/livewire/incident-response-panel.blade.php
```

Laravel resolves your overrides before the package defaults.

## Direct invocation

The three agents are also usable from PHP (jobs, commands, controllers) without the Livewire panel:

```php
use ArtisanPackUI\SecurityAnalytics\AI\Agents\ThreatTriageAgent;

$triage = ThreatTriageAgent::for( $securityEvent )->run();

// [
//   'severity'            => 'high',
//   'summary'             => '…',
//   'recommended_actions' => [ [ 'step' => '…', 'urgency' => 'immediate' ], … ],
//   'related_events'      => [ 42, 43, 44 ],
// ]
```

Input shapes accepted:

| Agent | Input |
|---|---|
| `ThreatTriageAgent` | `SecurityEvent` model, event id (int), or `[ 'event' => [...], 'related' => [...], 'context' => [...] ]` |
| `AnomalySummaryAgent` | Window in hours (int), or `[ 'window_hours' => int, 'anomalies' => [...], 'statistics' => [...] ]` |
| `IncidentResponseAgent` | `SecurityIncident` model, incident id (int), or `[ 'incident' => [...], 'timeline' => [...], 'playbooks' => [...] ]` |

## Toggling features

Each feature is togglable at runtime via `artisanpack-ui/ai`'s feature registry:

```php
use ArtisanPackUI\Ai\Contracts\FeatureRegistry;

$registry = app( FeatureRegistry::class );

$registry->disable( 'security.threat_triage' );
$registry->enable( 'security.threat_triage' );
$registry->isToggleOn( 'security.threat_triage' );
$registry->isEnabled( 'security.threat_triage' ); // toggle + credentials
```

When disabled, `ThreatTriageAgent::for(...)->run()` throws `FeatureDisabledException`. The Livewire panels catch this and render a disabled state; direct callers can catch it themselves.

## Overriding prompts and models

Prompt and model overrides layer via `artisanpack.ai.features.{feature_key}`:

```php
// config/artisanpack/ai.php
return [
    'features' => [
        'security.threat_triage' => [
            'model'        => 'claude-haiku-4-5-20251001',
            'instructions' => <<<'PROMPT'
                Your team's custom triage prompt goes here.
                Keep the schema fields (severity/summary/…) intact.
                PROMPT,
        ],
    ],
];
```

Precedence (top wins):

1. `FeatureSettings` store (usually written by the AI Settings admin UI)
2. `artisanpack.ai.features.{key}.instructions` / `.model` config value
3. Class defaults on the agent

Instructions are applied per-run through the `CallsLaravelAi` trait, so overrides don't require a redeploy.

## Credentials

Credentials resolve via `artisanpack-ui/ai`'s `CredentialResolver` chain:

1. Runtime override on the agent (`->withCredentials($creds)`)
2. `FeatureSettings` store (per-feature)
3. Env vars (`ARTISANPACK_AI_API_KEY`, `ARTISANPACK_AI_PROVIDER`, `ARTISANPACK_AI_DEFAULT_MODEL`, …)

The security-analytics agents don't hard-code Anthropic — flip `ARTISANPACK_AI_PROVIDER` to `openai` / `gemini` / `ollama` / etc. and the same agents route to that provider. Default models on each agent are Anthropic-flavored but overridable via config as above.

Under Octane, RoadRunner, and queue workers, the `CallsLaravelAi::configureProvider()` step invalidates `laravel/ai`'s cached provider so a rotated key (or a per-tenant credential injection between agents) actually lands — see the `Fixed` block in [CHANGELOG.md](../../CHANGELOG.md) under 1.1.0.

## Caching

Each agent caches responses using a content-derived fingerprint:

- `ThreatTriageAgent` — event fields + related-event window + context
- `AnomalySummaryAgent` — window + per-anomaly (id, severity, detector) tuples
- `IncidentResponseAgent` — incident id + severity + status + updated_at + timeline contents

TTL and the cache store are the AI package's `artisanpack.ai.cache.*` settings — see `artisanpack-ui/ai`'s docs. Set `$agent->cacheable = false` (or per-feature config) to disable caching entirely.

## Cost + performance

- **ThreatTriageAgent** (Sonnet 4.6) — one round-trip per event; typical response ~1–3 seconds. Related-event fetch is capped at 10 rows.
- **AnomalySummaryAgent** (Haiku 4.5) — one round-trip per window; anomaly rows capped at 50 for the LLM payload, but aggregate `total_count` / `by_severity` / `by_detector` are computed via DB `GROUP BY` so they're accurate for busy windows.
- **IncidentResponseAgent** (Opus 4.7) — one round-trip per invocation. Deeper model tier, so ~3–8 seconds per call; use sparingly on high-volume queue paths.

The `AgentUsageRecorded` event fires after every run — subscribe to it to bill tokens back to a per-tenant budget (`artisanpack-ui/ai` also ships a `BudgetSettings` service that consumes the same event).

## Advisory-only

None of the three agents trigger response actions. They emit structured advice; the responder decides what to run. The action-execution surface remains `Analytics\IncidentResponse\IncidentResponder` (10 pluggable actions, playbook-driven approval). See [Incident response](incident-response.md) for that surface.

## Follow-ups

- [Incident response](incident-response.md) — the manual + playbook-driven action surface the AI advises on
- [Dashboard](dashboard.md) — where the AI panels typically get mounted
- `artisanpack-ui/ai` docs — the AI Settings admin UI, credential resolver chain, feature registry, budget tracking
