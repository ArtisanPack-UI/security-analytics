# ArtisanPack UI — Security Analytics

Security analytics for Laravel: security event logging, anomaly detection, threat intelligence, SIEM export, incident response automation, alerting, and dashboards.

This package is part of the **ArtisanPack UI Security 2.0** split — the analytics, monitoring, and incident-response features previously bundled inside `artisanpack-ui/security` (1.x) live here in 2.0+.

> **Status:** scaffold. Content is being extracted from `artisanpack-ui/security` 1.x in follow-up PRs. See the package roadmap on the issue tracker.

## Installation

```bash
composer require artisanpack-ui/security-analytics
```

## Scope

Once content extraction lands, this package will provide:

- Security event logging (`SecurityEventLogger`) — structured `security_events` audit trail
- Anomaly detection — pluggable detectors (rule-based, statistical, behavioral, brute-force, credential-stuffing, geo-velocity, privilege-escalation, access-pattern) with baseline management
- SIEM export — Splunk, Datadog, Elasticsearch, syslog, and webhook exporters via the `SiemExporterInterface`
- Threat intelligence — pluggable providers (AbuseIPDB, Google Safe Browsing, IpQualityScore, VirusTotal, custom feeds)
- Incident response automation — playbook-driven actions (block IP, lock account, revoke sessions, force password reset, notify admin, etc.)
- Alerting — multi-channel delivery (database, email, Slack, Teams, PagerDuty, OpsGenie, SMS, webhook)
- Reports — executive summary, threat, trend, user-activity, incident, and compliance views
- Livewire dashboards — `SecurityDashboard`, `SecurityEventList`, `SecurityStats`, `SuspiciousActivityList`
- Console commands — process metrics, prune analytics data, sync threat feeds, test SIEM connectivity, generate reports, update behavior baselines
- Models — `SecurityEvent`, `SecurityIncident`, `Anomaly`, `SuspiciousActivity`, `UserBehaviorProfile`, `AlertHistory`, `ResponsePlaybook`

## Sibling packages

| Package | Scope |
|---|---|
| [`artisanpack-ui/security`](https://github.com/ArtisanPack-UI/security) | Core: input sanitization, output escaping, KSES, CSP, security headers |
| [`artisanpack-ui/security-advanced-auth`](https://github.com/ArtisanPack-UI/security-advanced-auth) | WebAuthn, SSO, social login, biometric, device fingerprinting |
| [`artisanpack-ui/rbac`](https://github.com/ArtisanPack-UI/rbac) | Roles, permissions, hierarchy, Blade directives, Gate integration |
| [`artisanpack-ui/secure-uploads`](https://github.com/ArtisanPack-UI/secure-uploads) | File validation, malware scanning, secure storage |
| [`artisanpack-ui/security-analytics`](https://github.com/ArtisanPack-UI/security-analytics) | Event logging, anomaly detection, SIEM, dashboards |
| [`artisanpack-ui/compliance`](https://github.com/ArtisanPack-UI/compliance) | GDPR / CCPA / LGPD compliance tools |
| [`artisanpack-ui/security-full`](https://github.com/ArtisanPack-UI/security-full) | Meta-package bundling all of the above |

## Contributing

As an open-source project, this package is open to contributions from anyone. Please [read through the contributing guidelines](CONTRIBUTING.md) to learn more about how you can contribute to this project.
