---
title: Artisan Commands
---

# Artisan Commands

Eleven commands cover processing, querying, exporting, and maintenance.

## Maintenance (schedule these)

| Command | Frequency | Purpose |
|---|---|---|
| `security:analytics-process` | every 5 min | Process queued metric updates, refresh aggregates |
| `security:detect-suspicious` | every 10 min | Run anomaly detectors over recent events |
| `security:update-baselines` | daily | Recompute per-user behavior baselines |
| `security:prune-analytics` | daily | Delete events past the retention window |
| `security:sync-threat-feeds` | daily | Refresh local threat indicator cache from configured feeds |

Add to `app/Console/Kernel.php`:

```php
$schedule->command('security:analytics-process')->everyFiveMinutes();
$schedule->command('security:detect-suspicious')->everyTenMinutes();
$schedule->command('security:update-baselines')->daily();
$schedule->command('security:prune-analytics')->daily();
$schedule->command('security:sync-threat-feeds')->daily();
```

## Querying / inspection

| Command | Purpose |
|---|---|
| `security:list-events` | List recent events with filter flags |
| `security:event-stats` | Aggregate stats (counts by type / severity / day) |

```bash
php artisan security:list-events --type=authentication --severity=warning --limit=20
php artisan security:event-stats --days=7
```

## Reports

| Command | Purpose |
|---|---|
| `security:generate-report {type}` | One-off report generation |

```bash
php artisan security:generate-report executive_summary --from=2026-04-01 --to=2026-04-30 --format=pdf
```

Schedule daily to dispatch any due `ScheduledReport`s:

```php
$schedule->command('security:generate-report')->daily();
```

## SIEM

| Command | Purpose |
|---|---|
| `security:test-siem` | Send a synthetic test event through the configured exporter |
| `security:export-events` | Backfill historical events to SIEM |

```bash
php artisan security:test-siem
php artisan security:export-events --from=2026-01-01 --to=2026-02-01 --rate-limit=100
```

## Cleanup

| Command | Purpose |
|---|---|
| `security:clear-events` | Truncate `security_events` (destructive — use with care) |

```bash
php artisan security:clear-events --confirm
```

## Exit codes

All commands return:
- `0` on success
- `1` on user-facing error (bad input, missing config)
- `2` on system error (DB connection, external API failure)

`security:test-siem` returns `2` if the SIEM is unreachable — useful for monitoring scripts.
