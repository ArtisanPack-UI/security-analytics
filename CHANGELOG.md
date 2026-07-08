# ArtisanPack UI — Security Analytics Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.1.0] - 2026-07-07

### Added

- Three AI-assisted features registered via `artisanpack-ui/ai`:
  - `security.threat_triage` — `ThreatTriageAgent` + `ThreatTriagePanel` Livewire component (default model `claude-sonnet-4-6`). Plain-language severity and recommended actions for a `SecurityEvent`. Closes #20.
  - `security.anomaly_summary` — `AnomalySummaryAgent` + `AnomalySummaryPanel` Livewire component (default model `claude-haiku-4-5-20251001`). Periodic digest of unusual events over a configurable window (1–720 hours). Closes #21.
  - `security.incident_response` — `IncidentResponseAgent` + `IncidentResponsePanel` Livewire component (default model `claude-opus-4-7`). Advisory-only next-step suggestions for open incidents. Closes #22.
- Service provider now exposes an `aiFeatures()` method so the three features are auto-discovered by `artisanpack-ui/ai`'s boot pass — no manual registration required by the host app.
- `CallsLaravelAi` trait wires each agent into `laravel/ai`'s `Promptable` + structured-output pipeline, invalidates cached provider instances so per-tenant credential injection actually lands, and unwraps single-key envelopes some models add around structured tool call arguments.
- Layered prompt overrides now flow through: the resolved `instructions()` string (settings-store override → `artisanpack.ai.features.{key}.instructions` config → class default) is threaded through to `laravel/ai` on every run.
- Three Blade views shipped under `resources/views/livewire/{threat-triage,anomaly-summary,incident-response}-panel.blade.php`, registered as Livewire components under the namespaced tags `security-analytics.{name}-panel`. Overridable via the standard `resources/views/vendor/security-analytics/livewire/*.blade.php` shadow.
- New `docs/usage/ai-features.md` documenting the three AI surfaces, override points, and defaults.

### Changed

- Minimum PHP requirement bumped from 8.2 to 8.3 to align with `artisanpack-ui/ai`'s transitive `laravel/ai` dependency.
- `composer.json` now requires `artisanpack-ui/ai ^1.0.0-alpha.1` and declares a development-only `path` repository against `../ai` for the symlinked dev-app workflow (CI strips this before install so Composer resolves from Packagist, matching the pattern used by `artisanpack-ui/visual-editor`).
- CI test matrix drops PHP 8.2 rows; retains PHP 8.3 / 8.4 × Laravel 12 / 13 × Livewire 3.6 / 4.0.

### Security

- Livewire panel target IDs (`$eventId`, `$incidentId` on `ThreatTriagePanel` and `IncidentResponsePanel`) are now marked `#[Locked]` so a user with the coarse `view-security-events` capability cannot rewire the target via the wire protocol to trigger an agent on records they weren't meant to see.
- `CallsLaravelAi::configureProvider()` invalidates `laravel/ai`'s `MultipleInstanceManager` cache after mutating credentials so a second agent's key actually lands. Without this, the first key seen by the process was silently reused for every subsequent call — a cross-tenant credential leak in multi-tenant deployments.
- The `Throwable` catch on all three Livewire panels now logs the raw exception server-side and surfaces a generic "Check the server logs for details" message; Guzzle/Anthropic exception messages could otherwise leak the upstream URL or, under some debug configs, API-key headers into the browser DOM.
- `ThreatTriageAgent::fetchRelated()` returns `[]` when the event has no correlation keys (`fingerprint`, `ip_address`, `user_id` all null) instead of running an empty closure-`where` that would surface up to 10 arbitrary recent events (including their PII) into the LLM prompt.

### Fixed

- Cache fingerprints now hash observable content instead of thin proxies: `IncidentResponseAgent` hashes the timeline contents (not just `count($timeline)`) so same-length edits / bulk updates invalidate the cache; `AnomalySummaryAgent` hashes per-anomaly (id, severity, detector) tuples so reclassification invalidates the cached digest.
- `hash('sha256', json_encode(...))` calls in all three cache fingerprints now use `JSON_INVALID_UTF8_SUBSTITUTE` and gracefully handle a `false` return, so invalid UTF-8 in user-controlled fields (`SecurityEvent::details`, url, fingerprint) no longer crash the base pipeline with a `TypeError` before `execute()` runs.
- `AnomalySummaryAgent::buildStatistics()` aggregates severity and detector counts entirely in the database via `selectRaw` + `groupBy` — the previous `->get()->groupBy(...)` hydrated every row into memory just to bucket-count it, and was unbounded for busy tenants.
- `AnomalySummaryAgent::payload()` gained an `is_array` guard on `$input['anomalies']` / `$input['statistics']` mirroring `IncidentResponseAgent`; callers passing a Collection or non-array now get the documented `InvalidArgumentException` instead of a raw `TypeError` from `array_values`.
- `AnomalySummaryAgent::$stream` set to `false` — the previous `true` was documented as "streaming on by default" but `execute()` used the non-streaming path, so any `streamTo($cb)` callback silently dropped every chunk.
- `unwrapStructured()` early-return guard removed; `array_intersect` alone correctly handles Opus's double-wrap under the schema's own parameter name.
- `outputSchema()` on each agent is now derived from `schema()` via `ObjectSchema` on the trait, killing the double-source-of-truth between the array-literal and fluent forms.
- `aiFeatures()` labels/descriptions and all `abort(403)` messages wrapped in `__()` for i18n. Panel `render()` methods gained explicit `: View` return types.

## [1.0.1] - 2026-06-14

### Added

- Laravel 13 support. The `illuminate/support` constraint now accepts `^10.0|^11.0|^12.0|^13.0`, and the test toolchain (`orchestra/testbench`, `pestphp/pest`, `pestphp/pest-plugin-laravel`) was widened so the Laravel 13 leg installs cleanly.

### Changed

- CI now runs the test suite as a matrix across Laravel 12 and 13 × PHP 8.2-8.4 × Livewire 3.6 and 4.0 (Laravel 13 / PHP 8.2 excluded — Laravel 13 requires PHP 8.3+). CI also triggers on `release/**` branches and overrides `composer config platform.php` per matrix row so the Laravel 13 leg resolves correctly despite the repo's PHP 8.2 platform pin.

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
