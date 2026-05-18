---
title: Getting Started
---

# Getting Started

Five minutes from install to logged event + dashboard render.

## 1. Install

```bash
composer require artisanpack-ui/security-analytics
php artisan migrate
```

Creates 10 tables for events, anomalies, profiles, threat indicators, incidents, alerts, etc.

## 2. Log your first event

```php
security_analytics()->logger()->log(
    type: 'authentication',
    name: 'login.failed',
    severity: 'warning',
    context: ['email' => $request->input('email')],
);
```

Or use the Facade:

```php
use ArtisanPackUI\SecurityAnalytics\Facades\SecurityAnalytics;

SecurityAnalytics::logger()->log( type: 'access', name: 'admin.viewed', ... );
```

Laravel's built-in authentication events (`Login`, `Failed`, `Logout`, etc.) are captured automatically by the bundled `LogAuthenticationEvents` listener — no extra wiring needed.

## 3. Visit the dashboard

If you have `livewire/livewire` installed, the dashboard routes register automatically. Sign in as a user with the `view-security-dashboard` ability and visit:

```
/security/dashboard
/security/events
/security/stats
/security/suspicious-activity
```

(The `/security` prefix is configurable via `artisanpack.security-analytics.dashboard.routePrefix`.)

## 4. Wire an alert

Listen for the `SecurityEventOccurred` event and route to your alerting channel of choice:

```php
use ArtisanPackUI\SecurityAnalytics\Events\SecurityEventOccurred;
use ArtisanPackUI\SecurityAnalytics\Facades\SecurityAnalytics;

Event::listen( SecurityEventOccurred::class, function ( SecurityEventOccurred $event ): void {
    if ( $event->securityEvent->severity === 'critical' ) {
        SecurityAnalytics::alerts()->send(
            channel: 'slack',
            message: "Critical security event: {$event->securityEvent->name}",
        );
    }
} );
```

## 5. Run the analytics processor on a schedule

Anomaly detection and behavior baselines aren't free — they batch-process events. Schedule the maintenance commands:

```php
// app/Console/Kernel.php
$schedule->command('security:analytics-process')->everyFiveMinutes();
$schedule->command('security:detect-suspicious')->everyTenMinutes();
$schedule->command('security:update-baselines')->daily();
$schedule->command('security:prune-analytics')->daily();
```

## Next steps

- [Usage](usage.md) — per-subsystem reference
- [Advanced](advanced.md) — extending detectors, channels, exporters, actions
- [Installation](installation.md) — full config reference
