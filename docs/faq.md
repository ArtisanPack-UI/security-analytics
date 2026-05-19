---
title: FAQ
---

# FAQ

## Does this package require `artisanpack-ui/security`?

No. Security Analytics is standalone — it depends only on `artisanpack-ui/core` and standard Laravel packages. The 1.x security toolkit's monitoring features now live here; this package can be used alongside the rest of the ArtisanPack UI security ecosystem or completely on its own.

## How does this compare to running the ELK stack / OpenSearch directly?

This package handles the *application-side* part — capturing structured events from the Laravel app, running detection logic, and pushing to your existing SIEM. It doesn't replace your SIEM — it feeds it (via the SIEM exporters). Use the SIEM for storage, search, and long-term retention; use this package for the in-app detection + automated response.

For small apps without a dedicated SIEM, the package can stand alone — `security_events` in your normal database is the audit trail, the dashboard is the UI.

## Can I use it without Livewire?

Yes. The dashboard UI requires Livewire, but everything else (logging, detection, threat intel, SIEM, alerting, reports, jobs, commands) is independent. Set `dashboard.enabled => false` to skip the route registration entirely.

## How much overhead does event logging add per request?

Negligible for sync mode (one INSERT per event). For high-volume apps (>1k events/sec), enable async mode via:

```php
'logging' => ['async' => true],
```

…which routes logging through a queue worker. The trade-off is a small delay before events appear in the dashboard / SIEM.

## How does the package handle GDPR / right-to-erasure?

Logged events with `user_id` set are tied to that user. When a user requests erasure:

```php
use ArtisanPackUI\SecurityAnalytics\Models\SecurityEvent;

SecurityEvent::where('user_id', $userId)->update(['user_id' => null, 'details' => null]);
```

…drops the personal data while preserving the security signal (you still know an event happened, you just no longer know which user). For full deletion, drop the rows entirely.

A future `artisanpack-ui/compliance` package will provide automated DSR handling.

## What about anomaly detection false positives?

Expected and manageable. Each anomaly carries a confidence score — set your `AlertRule` matchers to filter by confidence threshold. Tune detector thresholds in config over time as you observe your environment.

Anomalies are also marked as "false positive" via the dashboard. The package learns from these labels over time for the statistical / behavioral detectors.

## Can I throttle SIEM exports?

Yes. The `ExportToSiem` job respects Laravel's rate limiting. Configure:

```php
'siem' => [
    'rate_limit' => ['attempts' => 100, 'per_seconds' => 60],
],
```

…to cap to 100 events / minute regardless of source rate. Excess events queue until they can fit.

## How do I add an action that needs DB access (lookup users, write audit rows)?

Inject what you need via the constructor — your action is resolved through the container, so type-hint `EloquentModel`, services, etc., just like any class.

```php
class MyAction extends AbstractAction
{
    public function __construct(
        protected \App\Services\AuditWriter $audit,
    ) {}

    public function execute( array $context ): ActionResult
    {
        $this->audit->record( ... );
        return ActionResult::success();
    }
}
```

## What's the relationship between Anomalies and SuspiciousActivities?

Two separate concepts:

- **Anomaly** is what the `AnomalyDetectionService` produces — a statistical / behavioral signal from a specific detector against the recent event stream. May or may not be actionable.
- **SuspiciousActivity** is a higher-level concept — a curated catalogue of patterns (impossible travel, proxy detected, multiple failures, etc.) tied to a specific user / session. Comes from the `SuspiciousActivityService`, which can be triggered by detectors or by direct application code.

In practice: detectors find low-level signals; the suspicious-activity layer is what shows up on the dashboard and what the playbooks key off of.

## Why so many pluggable pieces?

Every security shop has different SIEMs, different alert channels, different threat intel, different response policies. Hard-coding any of them would force consumers to fork. The pluggable architecture means you wire only the pieces you actually use; the shipped implementations are sensible defaults you can replace as needs evolve.
