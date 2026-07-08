---
title: ArtisanPack UI Security Analytics Documentation
---

# ArtisanPack UI Security Analytics

Security analytics for Laravel — event logging, anomaly detection, threat intelligence, SIEM export, incident response automation, alerting, reports, and a Livewire dashboard.

This package is part of the **ArtisanPack UI Security 2.0** split.

## What's in this package

- **Event logging** — structured `security_events` audit trail, automatic Laravel auth event capture
- **Anomaly detection** — 8 pluggable detectors orchestrated by a single service, with per-user baselines
- **Threat intelligence** — 5 pluggable providers aggregated into a single threat lookup
- **SIEM export** — 5 pluggable exporters covering the common platforms (Datadog, Elasticsearch, Splunk, Syslog, Webhook)
- **Incident response** — 10 pluggable actions driven by playbook definitions
- **Alerting** — 8 channel implementations + rule + history models
- **Reports** — 6 report types, on-demand or scheduled
- **Dashboard** — controller + 4 Livewire components with shipped Blade views
- **AI features** *(new in 1.1)* — plain-language threat triage, periodic anomaly digest, advisory-only incident-response suggestions

Everything pluggable can be replaced with a custom implementation by binding your class against the corresponding interface in a service provider.

## Documentation map

- [Getting Started](getting-started.md) — 5-minute path
- [Installation](installation.md)
- [Usage](usage.md) — per-subsystem reference
- [API Reference](api.md)
- [Advanced](advanced.md) — building custom detectors / scanners / actions / channels
- [FAQ](faq.md)
- [Troubleshooting](troubleshooting.md)

## Related packages

| Package | Scope |
|---|---|
| [`artisanpack-ui/security`](https://github.com/ArtisanPack-UI/security) | Core: sanitization, escaping, CSP, security headers |
| [`artisanpack-ui/security-auth`](https://github.com/ArtisanPack-UI/security-auth) | 2FA, password complexity, account lockout |
| [`artisanpack-ui/security-advanced-auth`](https://github.com/ArtisanPack-UI/security-advanced-auth) | WebAuthn, SSO, social login |
| [`artisanpack-ui/rbac`](https://github.com/ArtisanPack-UI/rbac) | Roles, permissions, Gate integration |
| [`artisanpack-ui/secure-uploads`](https://github.com/ArtisanPack-UI/secure-uploads) | File validation, malware scanning |
