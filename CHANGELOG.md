# ArtisanPack UI — Security Analytics Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.0.0] - 2026-05-18

### Added

- Initial release of the standalone Security Analytics package, extracted from `artisanpack-ui/security` 1.x as part of the Security 2.0 package split.
- **Event logging** — `SecurityEventLogger` service, `SecurityEvent` model, `LogAuthenticationEvents` listener, automatic capture of Laravel authentication events.
- **Anomaly detection** (8 pluggable detectors): `BruteForceDetector`, `CredentialStuffingDetector`, `GeoVelocityDetector`, `PrivilegeEscalationDetector`, `AccessPatternDetector`, `BehavioralDetector`, `StatisticalDetector`, `RuleBasedDetector`. Plus `AnomalyDetectionService` orchestrator and `BaselineManager` for per-user behavior profiles.
- **Threat intelligence** (5 pluggable providers): `AbuseIPDBProvider`, `GoogleSafeBrowsingProvider`, `IpQualityScoreProvider`, `VirusTotalProvider`, `CustomFeedProvider`. Plus `ThreatIntelligenceService` aggregator.
- **SIEM export** (5 pluggable exporters): `DatadogExporter`, `ElasticsearchExporter`, `SplunkExporter`, `SyslogExporter`, `WebhookExporter`. Plus `SiemExportService` and `EventFormatter`.
- **Incident response automation** (11 pluggable actions): `BlockIpAction`, `BlockUserAction`, `EnableEnhancedLoggingAction`, `ForcePasswordResetAction`, `LockAccountAction`, `LogEventAction`, `NotifyAdminAction`, `RateLimitIpAction`, `RequireTwoFactorAction`, `RevokeSessionsAction`, `TerminateSessionAction`. Plus `IncidentResponder` orchestrator and `ResponsePlaybook` model for playbook-driven flows.
- **Alerting** (8 pluggable channels): `DatabaseChannel`, `EmailChannel`, `OpsGenieChannel`, `PagerDutyChannel`, `SlackChannel`, `SmsChannel`, `TeamsChannel`, `WebhookChannel`. Plus `AlertManager`, `AlertRule` model, `AlertHistory` model.
- **Reports** (6 report types): `ExecutiveSummaryReport`, `IncidentReport`, `ComplianceReport`, `ThreatReport`, `TrendReport`, `UserActivityReport`. Plus `ReportGenerator` and `ScheduledReport` model.
- **Dashboard surface**: `SecurityDashboardController` with 10 JSON endpoints (summary, live events, metrics, threats, geographic, timeline, anomalies, incidents, alert acknowledgment) plus 4 Livewire components (`SecurityDashboard`, `SecurityEventList`, `SecurityStats`, `SuspiciousActivityList`). Bundled routes file consolidates both API + UI under a single configurable prefix.
- **Eloquent models** (11): `SecurityEvent`, `Anomaly`, `UserBehaviorProfile`, `ThreatIndicator`, `ResponsePlaybook`, `SecurityIncident`, `AlertRule`, `AlertHistory`, `ScheduledReport`, `SecurityMetric`, `SuspiciousActivity`.
- **Migrations** (10) and database factories (9) for all models.
- **Console commands** (11): `security:analytics-process`, `security:clear-events`, `security:detect-suspicious`, `security:export-events`, `security:generate-report`, `security:list-events`, `security:prune-analytics`, `security:event-stats`, `security:sync-threat-feeds`, `security:test-siem`, `security:update-baselines`.
- **Background jobs** (5): `AnalyzeAnomalies`, `ExportToSiem`, `GenerateScheduledReport`, `ProcessSecurityMetrics`, `SendSecurityAlert`.
- **Events** (3): `AnomalyDetected`, `SecurityEventOccurred`, `SuspiciousActivityDetected`.
- `SecurityAnalytics` Facade and `security_analytics()` helper.
- `SuspiciousActivityService` ported in from the 1.x security package.
- Views published under both `artisanpack-ui-security-analytics::` (long-form) and `security-analytics::` (shorter alias) namespaces.

### Fixed

- Livewire view namespace mismatch — the 4 dashboard components were calling `view('security::livewire.*')` from the 1.x era. Updated to `view('security-analytics::livewire.*')`. Without this fix, every Livewire render threw `View not found` in production.
- `SuspiciousActivityList` referenced model constants that don't exist (`TYPE_UNUSUAL_LOCATION`, `TYPE_UNUSUAL_DEVICE`, etc.). Replaced with the actual constants the `SuspiciousActivity` model defines.
- The missing `suspicious-activity-list.blade.php` view file now ships with the package.
- Consolidated `routes/security-dashboard.php` and `routes/analytics-dashboard.php` into a single `routes/dashboard.php` with clearly-separated UI and API groups. The two-file split caused the API routes to silently not load (their `dashboard.enabled` config flag defaulted to `false` while the UI flag defaulted to `true`).
- All 4 dashboard Blade views rewritten in plain HTML + Tailwind. Previously they pulled in `<x-artisanpack-*>` components from `artisanpack-ui/livewire-ui-components` without declaring the dependency, breaking installs that didn't have that package.
- Author email normalized to `support@artisanpackui.dev`.

### Removed

- This package contains the security event logging / anomaly detection / threat intel / SIEM / incident response / alerting / analytics content previously bundled in `artisanpack-ui/security` 1.x. See the [`artisanpack-ui/security` UPGRADE guide](https://github.com/ArtisanPack-UI/security/blob/main/UPGRADE.md) for migration instructions from 1.x.
