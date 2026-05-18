---
title: Dashboard
---

# Dashboard

Two surfaces under a single configurable prefix:

- **Livewire UI** — 4 components rendering full HTML pages
- **JSON API** — 10 endpoints for headless / external consumers

Both share the same routes file (`routes/dashboard.php`) and the same middleware group.

## Livewire UI routes

| Path | Component | Purpose |
|---|---|---|
| `/security/dashboard` | `SecurityDashboard` | Top-level overview — KPIs, recent anomalies, charts |
| `/security/events` | `SecurityEventList` | Filterable / searchable event browser with export |
| `/security/stats` | `SecurityStats` | Top IPs, top users, time-series chart |
| `/security/suspicious-activity` | `SuspiciousActivityList` | Filterable list of suspicious activity per user / globally |

The `/security` prefix is configurable via `dashboard.routePrefix`.

## JSON API routes

| Method | Path | Method on `SecurityDashboardController` |
|---|---|---|
| GET | `/security/analytics/` | `index` |
| GET | `/security/analytics/summary` | `summary` |
| GET | `/security/analytics/events/live` | `liveEvents` |
| GET | `/security/analytics/metrics` | `metrics` |
| GET | `/security/analytics/threats` | `threats` |
| GET | `/security/analytics/geographic` | `geographic` |
| GET | `/security/analytics/timeline` | `timeline` |
| GET | `/security/analytics/anomalies` | `anomalyStats` |
| GET | `/security/analytics/incidents` | `incidents` |
| POST | `/security/analytics/alerts/{alert}/acknowledge` | `acknowledgeAlert` |

The `/security/analytics` API prefix is configurable via `dashboard.apiPrefix`.

## Authorization

Both the UI and the API check the `view-security-dashboard` ability:

```php
// In your AuthServiceProvider or via RBAC
Gate::define( 'view-security-dashboard', fn ( $user ) => $user->is_admin );
```

The `SecurityDashboard` Livewire component aborts 403 in `mount()` if the user lacks the ability. The API endpoints check it in middleware (default: `web` + `auth`; add your own ability-check middleware for the API too if you skip the standard Gate).

## Customizing the views

The shipped Blade views use plain HTML + Tailwind by design — no `livewire-ui-components` dependency. To customize:

1. Publish the views: (coming — currently override by placing files in `resources/views/vendor/security-analytics/livewire/*.blade.php`)
2. Edit the published copies; Laravel resolves overrides before the package's defaults.

Common customization: swap the chart placeholders for ChartJS / ApexCharts rendering. The Livewire components expose the chart data on public properties (`$eventsByTypeChart`, `$eventsBySeverityChart`, `$eventFrequencyChart`) — wire them up to your charting library of choice.

## Disabling the dashboard

If you don't want the dashboard at all:

```php
'dashboard' => ['enabled' => false],
```

The route file is skipped entirely. The rest of the package (logging, detection, alerting, SIEM, reports) works without the dashboard.
