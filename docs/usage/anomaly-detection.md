---
title: Anomaly Detection
---

# Anomaly Detection

`AnomalyDetectionService` orchestrates 8 pluggable detectors against the `security_events` stream. Each detector implements `DetectorInterface` — replace or extend any of them via the service provider.

## The shipped detectors

| Detector | What it catches |
|---|---|
| `BruteForceDetector` | High volume of failed attempts against a single account within a window |
| `CredentialStuffingDetector` | High volume of failed attempts across many accounts from a single IP / ASN |
| `GeoVelocityDetector` | Logins from geographically distant locations in implausibly short time (impossible travel) |
| `PrivilegeEscalationDetector` | Unusual elevation patterns — granting roles, accessing admin endpoints from non-admin users |
| `AccessPatternDetector` | Sudden shift in URL access patterns vs the user's baseline |
| `BehavioralDetector` | Off-hours activity, unusual session length, device fingerprint changes |
| `StatisticalDetector` | Per-user metric values exceeding N standard deviations from the user's baseline |
| `RuleBasedDetector` | Custom rule definitions stored in config or DB — fully declarative |

Each detector is independently configurable via `config('artisanpack.security-analytics.anomaly_detection.detectors.{slug}')`.

## Running detection

The detection service runs automatically on a schedule:

```bash
php artisan security:detect-suspicious
```

Schedule this command every 5–10 minutes. It batches recent events through every enabled detector and writes `Anomaly` rows for matches.

To run synchronously inline (e.g. from a controller, against a specific event):

```php
security_analytics()->detection()->analyze( $securityEvent );
```

Returns a `Collection<Anomaly>` of matches. Each `Anomaly` row carries the detector's name, severity, confidence, and detection metadata.

## Baselines

Three detectors (`StatisticalDetector`, `BehavioralDetector`, `AccessPatternDetector`) rely on per-user baselines stored in `UserBehaviorProfile`. Update them on a schedule:

```bash
php artisan security:update-baselines
php artisan security:update-baselines --days=30   # baseline window size
```

Daily is appropriate for most apps. Baselines settle in ~7–14 days for typical users.

## Reacting to detections

The `AnomalyDetected` event fires for every new `Anomaly` row. Subscribe to alert, escalate, or trigger an incident response playbook:

```php
use ArtisanPackUI\SecurityAnalytics\Events\AnomalyDetected;

Event::listen( AnomalyDetected::class, function ( AnomalyDetected $event ): void {
    if ( $event->anomaly->severity === 'high' ) {
        security_analytics()->alerts()->sendForAnomaly( $event->anomaly );
    }
} );
```

For automatic playbook-driven response see [Incident response](incident-response.md).

## Tuning sensitivity

Each detector has its own knobs. For example, BruteForce:

```php
'brute_force' => [
    'enabled'        => true,
    'threshold'      => 5,        // failures to trigger
    'window_minutes' => 15,       // observation window
    'lockout_count'  => 3,        // how many lockouts before escalation
],
```

Start with the defaults and tune based on false-positive rate. Track `Anomaly` rows by detector + severity to see which detectors are noisy in your environment.

## Building a custom detector

See [Custom detectors](../advanced/custom-detectors.md).
