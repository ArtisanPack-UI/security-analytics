---
title: Requirements
---

# Requirements

## PHP

- PHP 8.2+

## Laravel

- Laravel 10 / 11 / 12
- Laravel 13 (requires PHP 8.3+)

## Composer dependencies (pulled in automatically)

- `artisanpack-ui/core: ^1.0`

## Optional dependencies

- **`livewire/livewire` (^3.6 \| ^4.0)** — only required for the dashboard UI. The rest of the package (logging, detection, SIEM, alerts, jobs, commands) works without Livewire installed.
- **`pragmarx/google2fa` (^8.0)** — only required if you wire a TwoFactor-related action into a playbook.

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
