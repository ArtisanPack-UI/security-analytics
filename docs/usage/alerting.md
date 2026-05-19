---
title: Alerting
---

# Alerting

`AlertManager` routes alerts to one or more channels based on `AlertRule` definitions. Each alert delivery is captured in `AlertHistory` for audit.

## Shipped channels

| Channel | Use case |
|---|---|
| `DatabaseChannel` | Default — stores in `alert_history`, no external system needed |
| `EmailChannel` | Sends via Laravel's mail layer |
| `SlackChannel` | Slack incoming webhook |
| `TeamsChannel` | Microsoft Teams incoming webhook |
| `PagerDutyChannel` | PagerDuty integration |
| `OpsGenieChannel` | OpsGenie integration |
| `SmsChannel` | SMS via configured driver (Twilio, etc.) |
| `WebhookChannel` | Generic HTTP POST |

Each channel is independently configured and toggled in `config('artisanpack.security-analytics.alerting.channels')`.

## Sending an alert

```php
security_analytics()->alerts()->send(
    channel: 'slack',
    title: 'Suspicious activity detected',
    message: 'User 42 attempted to escalate privileges.',
    severity: 'high',
    context: [ 'user_id' => 42, 'detector' => 'privilege_escalation' ],
);
```

To fan out to multiple channels:

```php
security_analytics()->alerts()->broadcast(
    channels: ['slack', 'email', 'pagerduty'],
    title: '...',
    message: '...',
);
```

## Rule-driven alerts

For typical workflows, you don't send alerts manually — you define `AlertRule` records that fire on matching events:

```php
use ArtisanPackUI\SecurityAnalytics\Models\AlertRule;

AlertRule::create([
    'name'      => 'Critical events to PagerDuty',
    'matcher'   => ['severity' => 'critical'],
    'channels'  => ['pagerduty', 'slack'],
    'cooldown_minutes' => 30,
    'enabled'   => true,
]);
```

The bundled `SendSecurityAlert` job listens to `SecurityEventOccurred` / `AnomalyDetected` events and checks each rule. Matched rules dispatch to their channels (subject to the cooldown).

## Cooldowns

Cooldowns prevent alert storms. If a rule has fired in the last `cooldown_minutes` for the same matcher key (e.g. same IP, same user, same event type), the duplicate fire is suppressed.

## Alert history

`AlertHistory` records every fired alert with the channel, the rule that triggered it, the payload, and the delivery result. Query it via the dashboard at `/security/alerts` or directly:

```php
use ArtisanPackUI\SecurityAnalytics\Models\AlertHistory;

AlertHistory::where('severity', 'critical')->latest()->limit(50)->get();
AlertHistory::where('channel', 'pagerduty')->where('created_at', '>=', now()->subDay())->get();
```

## Acknowledgment

Alerts can be acknowledged (manually or via integration callback):

```php
$alert->acknowledge( actor: $user, note: 'Investigated — false positive.' );
```

Sets `acknowledged_at`, `acknowledged_by_id`, and `acknowledgment_note`. The dashboard surfaces unacknowledged critical alerts prominently.

## Building a custom channel

Implement `AlertChannelInterface` (`send`, `isAvailable`, `getName`) and register your class. See [Custom channels](../advanced/custom-channels.md).
