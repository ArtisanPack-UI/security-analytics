---
title: API Reference
---

# API Reference

The package's public API surface, organized by subsystem.

## Top-level entry points

| Symbol | Notes |
|---|---|
| `SecurityAnalytics` facade | `SecurityAnalytics::logger()`, `::detection()`, `::threats()`, `::alerts()`, `::reports()`, `::responder()` |
| `security_analytics()` helper | Returns the `SecurityAnalytics` instance bound as `'security-analytics'` |

## Subsystem services

| Subsystem | Interface | Default implementation |
|---|---|---|
| Event logging | `SecurityEventLoggerInterface` | `SecurityEventLogger` |
| Anomaly detection | (none — concrete) | `AnomalyDetectionService` |
| Detector contract | `DetectorInterface` | 8 shipped implementations under `Analytics/AnomalyDetection/Detectors/` |
| Threat intel | (none — concrete) | `ThreatIntelligenceService` |
| Threat intel provider contract | `ThreatIntelProviderInterface` | 5 shipped implementations under `Analytics/ThreatIntelligence/Providers/` |
| SIEM export | (none — concrete) | `SiemExportService` |
| SIEM exporter contract | `SiemExporterInterface` | 5 shipped implementations under `Analytics/Siem/Exporters/` |
| Incident response | (none — concrete) | `IncidentResponder` |
| Response action contract | `ResponseActionInterface` | 10 shipped implementations under `Analytics/IncidentResponse/Actions/` |
| Alerting | (none — concrete) | `AlertManager` |
| Alert channel contract | `AlertChannelInterface` | 8 shipped implementations under `Analytics/Alerting/Channels/` |
| Reports | (none — concrete) | `ReportGenerator` |
| Report contract | `ReportInterface` | 6 shipped implementations under `Analytics/Reports/` |
| Suspicious activity | `SuspiciousActivityDetectorInterface` | `SuspiciousActivityService` |
| Dashboard data | (none — concrete) | `DashboardDataProvider` |

All contracts are in `src/Analytics/*/Contracts/` (with two exceptions in `src/Contracts/` and `src/Authentication/Contracts/`).

## AI agents *(new in 1.1)*

3 agents under `src/AI/Agents/`, each extending `ArtisanPackUI\Ai\Agents\ArtisanPackAgent` and implementing `Laravel\Ai\Contracts\Agent` + `Laravel\Ai\Contracts\HasStructuredOutput`:

| Class | Feature key | Livewire tag |
|---|---|---|
| `ThreatTriageAgent` | `security.threat_triage` | `security-analytics.threat-triage-panel` |
| `AnomalySummaryAgent` | `security.anomaly_summary` | `security-analytics.anomaly-summary-panel` |
| `IncidentResponseAgent` | `security.incident_response` | `security-analytics.incident-response-panel` |

Shared wiring lives in the `CallsLaravelAi` trait under `src/AI/Concerns/`. Registered via `SecurityAnalyticsServiceProvider::aiFeatures()` and auto-discovered by `artisanpack-ui/ai`'s boot pass. See [AI features](usage/ai-features.md) for the full usage guide.

## Events

- `SecurityEventOccurred` — fired after every `security_events` row is written
- `AnomalyDetected` — fired for every new `Anomaly` row
- `SuspiciousActivityDetected` — fired by the suspicious activity service
- `Laravel\Ai\Events\AgentUsageRecorded` (via `artisanpack-ui/ai`) — fired after every AI agent run; subscribe to bill tokens back to a per-tenant budget

## Jobs

- `AnalyzeAnomalies` — queue-based anomaly detection
- `ExportToSiem` — queue-based SIEM export
- `GenerateScheduledReport` — queue-based report generation
- `ProcessSecurityMetrics` — queue-based metric aggregation
- `SendSecurityAlert` — queue-based alert delivery

## Models

11 models under `src/Models/`: `SecurityEvent`, `Anomaly`, `UserBehaviorProfile`, `ThreatIndicator`, `ResponsePlaybook`, `SecurityIncident`, `AlertRule`, `AlertHistory`, `ScheduledReport`, `SecurityMetric`, `SuspiciousActivity`.

Each has a factory under `database/factories/`.

## Source as authoritative reference

For the full method signatures, read the source. The class names and namespaces above are stable; method signatures may evolve per minor version (with semver discipline).
