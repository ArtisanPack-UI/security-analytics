---
title: Usage
---

# Usage

Per-subsystem reference. Each topic is a self-contained surface — you can use any subset without touching the others.

## Topics

- [Event logging](usage/event-logging.md) — `SecurityEventLogger`, automatic Laravel auth event capture, structured `security_events`
- [Anomaly detection](usage/anomaly-detection.md) — the 8 shipped detectors, baselines, detection service
- [Threat intelligence](usage/threat-intelligence.md) — provider aggregation, IP / URL lookups, indicator caching
- [SIEM export](usage/siem-export.md) — exporter selection, formatters, retry, async export
- [Incident response](usage/incident-response.md) — playbook definitions, the 10 shipped actions
- [Alerting](usage/alerting.md) — channels, alert rules, alert history
- [Reports](usage/reports.md) — on-demand vs scheduled, the 6 report types
- [Dashboard](usage/dashboard.md) — Livewire UI + JSON API endpoints
- [AI features](usage/ai-features.md) — threat triage, anomaly digest, incident-response suggestions (new in 1.1)
- [Artisan commands](usage/artisan-commands.md) — full command reference

## Quick reference

```php
// Logging
security_analytics()->logger()->log( type: '...', name: '...', severity: '...', context: [...] );

// Anomaly detection
security_analytics()->detection()->analyze( $event );

// Threat intel lookup
security_analytics()->threats()->lookupIp( '198.51.100.1' );

// Alerting
security_analytics()->alerts()->send( channel: 'slack', message: '...' );

// Reports
security_analytics()->reports()->generate( type: 'executive_summary', from: ..., to: ... );
```

Or via the Facade — `SecurityAnalytics::logger()`, `SecurityAnalytics::detection()`, etc.
