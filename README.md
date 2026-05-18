# ArtisanPack UI — Security Analytics

Security analytics for Laravel: structured security event logging, pluggable anomaly detection, threat intelligence aggregation, SIEM export (Datadog / Elasticsearch / Splunk / Syslog / Webhook), playbook-driven incident response automation, multi-channel alerting, reports, and a Livewire dashboard.

This package is part of the **ArtisanPack UI Security 2.0** split — the analytics, monitoring, and incident-response features previously bundled inside `artisanpack-ui/security` (1.x) live here in 2.0+.

## Features

- **Event logging** — `SecurityEventLogger` plus a `LogAuthenticationEvents` listener that captures Laravel auth events automatically into a structured `security_events` table.
- **Anomaly detection** — 8 pluggable detectors (`BruteForce`, `CredentialStuffing`, `GeoVelocity`, `PrivilegeEscalation`, `AccessPattern`, `Behavioral`, `Statistical`, `RuleBased`) orchestrated by `AnomalyDetectionService` with per-user baselines via `BaselineManager`.
- **Threat intelligence** — 5 pluggable providers (`AbuseIPDB`, `GoogleSafeBrowsing`, `IpQualityScore`, `VirusTotal`, `CustomFeed`) aggregated by `ThreatIntelligenceService`.
- **SIEM export** — 5 pluggable exporters (`Datadog`, `Elasticsearch`, `Splunk`, `Syslog`, `Webhook`) backed by `SiemExportService`.
- **Incident response automation** — 10 pluggable actions (block IP / user, lock account, revoke sessions, force password reset, require 2FA, terminate session, notify admin, rate-limit IP, enable enhanced logging, log event) coordinated by `IncidentResponder` and driven by `ResponsePlaybook` definitions.
- **Alerting** — 8 channels (`Database`, `Email`, `OpsGenie`, `PagerDuty`, `Slack`, `Sms`, `Teams`, `Webhook`) routed via `AlertManager` with `AlertRule` definitions and `AlertHistory` audit.
- **Reports** — 6 report types (`ExecutiveSummary`, `Incident`, `Compliance`, `Threat`, `Trend`, `UserActivity`) generated on-demand or on a schedule via `ScheduledReport`.
- **Dashboard** — bundled `SecurityDashboardController` (10 JSON endpoints) plus 4 Livewire components (`SecurityDashboard`, `SecurityEventList`, `SecurityStats`, `SuspiciousActivityList`) with shipped Blade views.
- **Eloquent models** (11), migrations (10), and factories (9) for the full schema.
- **Console commands** (11) for processing, pruning, exporting, generating reports, syncing threat feeds, and updating behavior baselines.
- **Background jobs** (5) for off-request analysis, SIEM export, scheduled reports, metric processing, and alert delivery.
- **Events** (3) — `SecurityEventOccurred`, `AnomalyDetected`, `SuspiciousActivityDetected` — subscribe to integrate with downstream systems.
- `SecurityAnalytics` Facade + `security_analytics()` helper.

## Installation

```bash
composer require artisanpack-ui/security-analytics
php artisan migrate
```

(Optional) Publish the config:

```bash
php artisan vendor:publish --tag=security-analytics-config
```

## Quick start

Log a security event:

```php
use ArtisanPackUI\SecurityAnalytics\Facades\SecurityAnalytics;

security_analytics()->logger()->log(
    type: 'authentication',
    name: 'login.failed',
    severity: 'warning',
    context: ['username' => $request->input('email')],
);
```

Or react to the auth events Laravel fires:

```php
// The package's LogAuthenticationEvents listener wires this up automatically.
// To opt out, set config('artisanpack.security-analytics.auto_log_auth_events') to false.
```

Mount the dashboard:

```php
// The dashboard routes auto-register under the configured prefix (default: /security).
// Visit /security/dashboard to see the Livewire UI.
```

## Dashboard Blade views

The dashboard views ship as plain HTML + Tailwind by design — the package does not depend on `artisanpack-ui/livewire-ui-components`. To use richer UI components in your app, publish the views and customize:

```bash
# (After publishable views are added — currently override by placing files in
# resources/views/vendor/security-analytics/livewire/*.blade.php)
```

## Documentation

- [Documentation home](docs/home.md)
- [Getting started](docs/getting-started.md)
- [Installation](docs/installation.md)
- [Usage](docs/usage.md)
- [Advanced](docs/advanced.md)
- [FAQ](docs/faq.md)
- [Troubleshooting](docs/troubleshooting.md)
- [Changelog](CHANGELOG.md)

## Requirements

- PHP 8.2+
- Laravel 10 / 11 / 12
- `livewire/livewire` ^3.6 or ^4.0 (only required for the dashboard UI; the rest of the package works without Livewire)

## Sibling packages

| Package | Scope |
|---|---|
| [`artisanpack-ui/security`](https://github.com/ArtisanPack-UI/security) | Core: input sanitization, escaping, CSP, security headers |
| [`artisanpack-ui/security-auth`](https://github.com/ArtisanPack-UI/security-auth) | 2FA, password complexity, account lockout, sessions |
| [`artisanpack-ui/security-advanced-auth`](https://github.com/ArtisanPack-UI/security-advanced-auth) | WebAuthn, SSO, social login |
| [`artisanpack-ui/rbac`](https://github.com/ArtisanPack-UI/rbac) | Roles, permissions, Gate integration |
| [`artisanpack-ui/secure-uploads`](https://github.com/ArtisanPack-UI/secure-uploads) | File validation, malware scanning, signed-URL serving |
| [`artisanpack-ui/compliance`](https://github.com/ArtisanPack-UI/compliance) | GDPR / CCPA / LGPD compliance tools |

## License

MIT — see [LICENSE](LICENSE).

## Contributing

Please read the [contributing guidelines](CONTRIBUTING.md) before opening an issue or PR.
