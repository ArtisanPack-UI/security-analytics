---
title: SIEM Export
---

# SIEM Export

`SiemExportService` forwards `security_events` to an external SIEM. Five pluggable exporters ship with the package.

## Shipped exporters

| Exporter | Use case |
|---|---|
| `DatadogExporter` | Datadog Logs API |
| `ElasticsearchExporter` | Direct write to an ES index |
| `SplunkExporter` | Splunk HTTP Event Collector (HEC) |
| `SyslogExporter` | Standard syslog protocol (RFC 5424) |
| `WebhookExporter` | Generic HTTP POST — pair with anything that accepts JSON webhooks |

Pick one via config:

```php
'siem' => [
    'enabled'  => true,
    'exporter' => 'datadog',   // or elasticsearch, splunk, syslog, webhook
],
```

Each exporter has its own config block (API keys, endpoint URLs, etc.) — see [Configuration](../installation/configuration.md#siem).

## Synchronous vs async export

By default, events export asynchronously via the `ExportToSiem` job. The `SecurityEventOccurred` listener dispatches the job; your queue worker handles the actual HTTP call.

To export synchronously (e.g. small-scale apps without a queue worker):

```php
'siem' => [
    'async' => false,
],
```

Synchronous mode blocks the request that triggered the event. Async is strongly preferred.

## Event formatting

`EventFormatter` normalizes `SecurityEvent` rows to the format each SIEM expects:

- Datadog → Datadog Logs JSON
- Elasticsearch → ECS-compliant JSON
- Splunk → HEC event JSON
- Syslog → RFC 5424 structured data
- Webhook → free-form JSON (configurable shape)

To customize formatting, subclass `EventFormatter` and rebind.

## Testing connectivity

```bash
php artisan security:test-siem
```

Sends a synthetic test event through the configured exporter and reports success / failure. Run this immediately after configuring credentials to verify the connection.

## Backfilling

To export historical events that pre-date enabling SIEM:

```bash
php artisan security:export-events --from=2026-01-01 --to=2026-05-17
```

The command batches through the date range, dispatching `ExportToSiem` jobs. Watch the queue depth — high-volume backfills should run with `--rate-limit` to avoid overwhelming the SIEM.

## Building a custom exporter

See [Custom exporters](../advanced/custom-exporters.md).
