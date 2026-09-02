---
title: Requirements
---

# Requirements

## PHP

- PHP 8.3+ (bumped from 8.2 in v1.1.0 to align with `artisanpack-ui/ai`'s transitive `laravel/ai` dependency)

## Laravel

- Laravel 11 / 12 / 13

## Composer dependencies (pulled in automatically)

- `artisanpack-ui/core: ^1.0`
- `artisanpack-ui/ai: ^1.0.0-alpha.1` — foundation for the three AI features (see [AI features](../usage/ai-features.md))

## Optional dependencies

- **`livewire/livewire` (^3.6 \| ^4.0)** — required for the dashboard UI **and** the three AI trigger panels (`ThreatTriagePanel`, `AnomalySummaryPanel`, `IncidentResponsePanel`). The rest of the package (logging, detection, SIEM, alerts, jobs, commands) works without Livewire installed.
- **`pragmarx/google2fa` (^8.0)** — only required if you wire a TwoFactor-related action into a playbook.

## AI provider credentials (per-feature)

The three AI features route through `laravel/ai`'s provider system via `artisanpack-ui/ai`'s credential resolver. Configure once via the AI package's env vars or admin UI; the security-analytics agents pick them up automatically. Anthropic, OpenAI, Gemini, Ollama, and the rest of the `laravel/ai` provider set are all supported — the agents' default models target Anthropic (Opus 4.7 / Sonnet 4.6 / Haiku 4.5) but can be overridden per feature via `artisanpack.ai.features.{key}.model` or the AI Settings admin surface.

## External services (per-feature)

| Feature | Service |
|---|---|
| `VirusTotalProvider` (threat intel) | VirusTotal API key |
| `AbuseIPDBProvider` | AbuseIPDB API key |
| `GoogleSafeBrowsingProvider` | Google Safe Browsing API key |
| `IpQualityScoreProvider` | IpQualityScore API key |
| `DatadogExporter` | Datadog API key + site |
| `ElasticsearchExporter` | Elasticsearch cluster URL + auth |
| `SplunkExporter` | Splunk HEC endpoint + token |
| `SlackChannel` | Slack incoming webhook URL |
| `PagerDutyChannel` | PagerDuty integration key |
| `OpsGenieChannel` | OpsGenie API key |
| `TeamsChannel` | Microsoft Teams incoming webhook URL |
| `SmsChannel` | Configured SMS driver (Twilio, etc.) |

Each driver is opt-in — install only the credentials you'll actually use.

## Database

Any Eloquent-supported driver. The shipped migrations use standard column types.

For high-volume event logging (>10k events/min), consider:
- Partitioning the `security_events` table by month
- Routing events to a dedicated database connection via `artisanpack.security-analytics.database.connection`
- Running `security:prune-analytics` more frequently and/or with a shorter retention window
