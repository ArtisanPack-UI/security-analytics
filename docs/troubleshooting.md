---
title: Troubleshooting
---

# Troubleshooting

## `View [security::livewire.*] not found`

This was a 0.x bug where the Livewire components referenced the wrong view namespace (`security::` from the 1.x days). Fixed in the v1.0 release — the components now use `security-analytics::`.

If you still see this error, you're running a pre-1.0 build. Update to ^1.0.

## Livewire dashboard returns 403

Either:
1. The user isn't authenticated. Add `'auth'` to the `dashboard.middleware` config (it's there by default).
2. The user doesn't have the `view-security-dashboard` ability. Grant via Gate or RBAC.

## `Class [livewire] does not exist` in tests

The package's tests load Livewire's service provider in the base `TestCase`. If you've subclassed `TestCase` in your own tests and overridden `getPackageProviders`, make sure you still include `LivewireServiceProvider::class`.

## SIEM exports are silently failing

Check three things:

1. Is `'siem.enabled' => true` set? Default is false.
2. Is the queue worker running? Async exports require an active worker.
3. Run `php artisan security:test-siem` — it does a synchronous test export and reports the failure cause.

## The dashboard charts are empty

The shipped Blade views render placeholder text rather than actual charts — by design, to avoid forcing a charting library dependency on consumers. The chart data is available on the components' public properties (`$eventsByTypeChart`, etc.); override the views to render with Chart.js / ApexCharts / whatever fits your stack.

## Anomaly detection isn't producing results

1. Has `security:detect-suspicious` actually run? Manual: `php artisan security:detect-suspicious`. Scheduled: check `app/Console/Kernel.php`.
2. Are detectors enabled in config? Default they're all on, but `incident_response.enabled` defaults to false — detection runs but no playbook fires.
3. Is there enough event data? Statistical / behavioral detectors need baseline data — run `security:update-baselines` and wait at least a few days for them to settle.

## Alerts are being deduplicated

`AlertRule::cooldown_minutes` suppresses duplicate fires within the window. Either lower the cooldown or set it to 0 if you want every event to alert.

## `security:prune-analytics` is too slow

For multi-million-row `security_events` tables:

1. Use the `--chunk` option to batch (`php artisan security:prune-analytics --chunk=10000`).
2. Run during off-peak hours.
3. Consider partitioning the table by month at the DB level — the prune command can DROP whole partitions instantly instead of DELETEing rows.

## Threat intel calls are slow on first hit

External APIs (VirusTotal, AbuseIPDB) take ~1-2s per cold-path lookup. The package caches responses (default 1 hour TTL); subsequent calls are sub-millisecond.

For latency-sensitive paths (e.g. inline middleware checks), pre-warm the cache via `security:sync-threat-feeds` for known indicators, or use `CustomFeedProvider` with a local file/DB feed.

## Tests fail with `no such table: security_events`

Add `RefreshDatabase` to your test class:

```php
use Illuminate\Foundation\Testing\RefreshDatabase;

uses( RefreshDatabase::class );
```

The package's migrations run automatically when `RefreshDatabase` (or `DatabaseMigrations`) is in use.

## Migration `2025_12_24_000008_create_suspicious_activities_table` conflicts with `security-advanced-auth`

Both `security-analytics` and `security-advanced-auth` shipped a `suspicious_activities` migration during the extraction. They're the same table.

As of 1.2.0 every `security-analytics` migration is guarded with `Schema::hasTable()`, so on `php artisan migrate` whichever package runs its migration first creates the table and the other is skipped automatically — no manual intervention needed for installation ([#10](https://github.com/ArtisanPack-UI/security-analytics/issues/10)). If you're on an earlier version, skip one of the two migrations manually or upgrade to 1.2.0.

> **Rollback caveat when both packages are installed.** Laravel still records a guarded migration as *applied* even when its `up()` skipped creation, so `php artisan migrate:rollback` will call that migration's `down()`, which drops `suspicious_activities`. If `security-advanced-auth` created the table and you roll back `security-analytics` (or vice versa), the shared table — and its data — is removed even though the other package still relies on it. When both packages are installed, roll back with care: target specific batches, or re-run the surviving package's migration afterward to recreate the table.

## Still stuck?

Open an issue at https://github.com/ArtisanPack-UI/security-analytics/issues with:

- PHP and Laravel versions
- Which subsystem you're using (logging, detection, SIEM, alerting, etc.)
- The exact error / behavior + a minimal reproduction
- Any relevant config (with secrets redacted)
