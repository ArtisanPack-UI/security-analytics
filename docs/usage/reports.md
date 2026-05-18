---
title: Reports
---

# Reports

`ReportGenerator` produces structured reports against the `security_events` and related tables. Six report types ship.

## Shipped report types

| Type | Audience | Contents |
|---|---|---|
| `ExecutiveSummaryReport` | Leadership | Headline metrics, period-over-period delta, incident count |
| `IncidentReport` | Security team | Per-incident detail with timeline + actions taken |
| `ComplianceReport` | Audit / GRC | Access logs, authentication trail, retention compliance |
| `ThreatReport` | Security team | Threat intel matches, top attackers, malicious IP/URL list |
| `TrendReport` | Security team | Time-series breakdown of event volume by type / severity |
| `UserActivityReport` | IT / managers | Per-user activity summary, anomaly history |

## Generating on demand

```php
$report = security_analytics()->reports()->generate(
    type: 'executive_summary',
    from: now()->subMonth(),
    to: now(),
    format: 'pdf',   // pdf | csv | json
);

$report->disk;   // 'local'
$report->path;   // 'security-reports/executive-summary-2026-04-18-to-2026-05-18.pdf'
$report->url();  // pre-signed URL when the disk supports it
```

The format list and storage location are configurable in `config('artisanpack.security-analytics.reports')`.

## Scheduling reports

`ScheduledReport` rows drive recurring generation:

```php
use ArtisanPackUI\SecurityAnalytics\Models\ScheduledReport;

ScheduledReport::create([
    'type'       => 'executive_summary',
    'frequency'  => 'weekly',    // daily | weekly | monthly
    'format'     => 'pdf',
    'recipients' => ['ciso@example.com', 'cto@example.com'],
    'enabled'    => true,
]);
```

The `GenerateScheduledReport` job runs on schedule (`$schedule->command('security:generate-report')` daily) and dispatches each due `ScheduledReport`. The generated file lands on the configured disk; recipients get an email with a download link.

## CLI invocation

```bash
php artisan security:generate-report executive_summary --from=2026-04-01 --to=2026-04-30 --format=pdf
```

Useful for one-off generation outside the scheduled cycle.

## Building a custom report

Implement `ReportInterface` (`generate`, `getName`, `getSupportedFormats`) or subclass `AbstractReport` for the common shape (date range, format selection, file output). Bind your class in a service provider and register via `ReportGenerator::extend('my_report', MyReport::class)`.
