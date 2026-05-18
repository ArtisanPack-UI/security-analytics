---
title: Incident Response
---

# Incident Response

`IncidentResponder` runs sequences of automated actions when an anomaly or rule matches. Each step is a pluggable action implementing `ResponseActionInterface`.

## Shipped actions

| Action | What it does |
|---|---|
| `BlockIpAction` | Add the IP to a blocklist (via cache / firewall) |
| `BlockUserAction` | Set the user to "blocked" via your blocking trait |
| `EnableEnhancedLoggingAction` | Bump logging verbosity for the affected user/IP |
| `ForcePasswordResetAction` | Invalidate the user's password and email a reset link |
| `LockAccountAction` | Lock the user account for the configured duration |
| `LogEventAction` | Write an audit entry to a custom log channel |
| `NotifyAdminAction` | Send notification to the admin team via alerting channels |
| `RateLimitIpAction` | Apply a stricter rate limit to the IP |
| `RequireTwoFactorAction` | Force the user to set up 2FA on next login |
| `RevokeSessionsAction` | Revoke all of the user's active sessions |
| `TerminateSessionAction` | Terminate just the offending session |

## Defining a playbook

A playbook is a sequence of action definitions. Store them in `response_playbooks` table or declare in config:

```php
'incident_response' => [
    'enabled' => true,
    'playbooks' => [
        'brute_force_response' => [
            'trigger' => ['detector' => 'brute_force', 'severity' => 'high'],
            'actions' => [
                ['action' => 'block_ip', 'duration_minutes' => 60],
                ['action' => 'notify_admin', 'channel' => 'slack'],
                ['action' => 'lock_account', 'duration_minutes' => 30],
            ],
        ],
        'credential_stuffing_response' => [
            'trigger' => ['detector' => 'credential_stuffing'],
            'actions' => [
                ['action' => 'block_ip', 'duration_minutes' => 240],
                ['action' => 'enable_enhanced_logging'],
            ],
        ],
    ],
],
```

Or via the `ResponsePlaybook` model for DB-driven, runtime-editable playbooks:

```php
ResponsePlaybook::create([
    'name'    => 'Critical anomaly auto-block',
    'trigger' => ['severity' => 'critical'],
    'actions' => [...],
    'enabled' => true,
]);
```

## Triggering a playbook

`IncidentResponder` listens for `AnomalyDetected` events automatically (when `incident_response.enabled = true`). For manual triggering:

```php
security_analytics()->responder()->runPlaybook(
    playbookSlug: 'brute_force_response',
    context: ['user' => $user, 'ip' => $ip],
);
```

Each action's result is captured in a `SecurityIncident` record so you have a full audit trail of what was done in response to what trigger.

## Action results

Each `ResponseActionInterface::execute(array $context): ActionResult` returns:

```php
$result->success;   // bool
$result->message;   // human-readable
$result->context;   // array — preserved for downstream actions in the same playbook
```

If an action returns `success: false`, the playbook can be configured to either continue or abort. Default is continue — partial response is usually better than no response.

## Building a custom action

Implement `ResponseActionInterface` (`execute`, `getName`) and register your class. The package's `AbstractAction` base class handles common boilerplate (logging, error capture, context merging). See [Custom actions](../advanced/custom-actions.md).
