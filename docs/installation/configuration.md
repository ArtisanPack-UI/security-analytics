---
title: Configuration
---

# Configuration

Publish the shipped config:

```bash
php artisan vendor:publish --tag=security-analytics-config
```

Lives at `config/artisanpack/security-analytics.php`. The major sections:

## `dashboard`

```php
'dashboard' => [
    'enabled'     => env('SECURITY_ANALYTICS_DASHBOARD_ENABLED', true),
    'routePrefix' => env('SECURITY_ANALYTICS_DASHBOARD_PREFIX', 'security'),
    'apiPrefix'   => env('SECURITY_ANALYTICS_API_PREFIX', 'security/analytics'),
    'middleware'  => ['web', 'auth'],
],
```

- `enabled` — flag the whole dashboard surface on/off (route file is skipped entirely when false).
- `routePrefix` — URL prefix for the Livewire UI routes.
- `apiPrefix` — URL prefix for the JSON API endpoints.
- `middleware` — applied to both route groups. Add `auth` (default) plus any RBAC / Gate-checking middleware you use.

## `logging`

```php
'logging' => [
    'auto_log_auth_events' => env('SECURITY_ANALYTICS_AUTO_LOG_AUTH', true),
    'retention_days'       => env('SECURITY_ANALYTICS_RETENTION_DAYS', 90),
],
```

`auto_log_auth_events` controls whether the bundled `LogAuthenticationEvents` listener attaches. `retention_days` is consumed by `security:prune-analytics`.

## `anomaly_detection`

```php
'anomaly_detection' => [
    'detectors' => [
        'brute_force'          => ['enabled' => true, 'threshold' => 5, 'window_minutes' => 15],
        'credential_stuffing'  => ['enabled' => true, 'threshold' => 10, 'window_minutes' => 30],
        'geo_velocity'         => ['enabled' => true, 'max_kmh' => 800],
        'privilege_escalation' => ['enabled' => true],
        'access_pattern'       => ['enabled' => true],
        'behavioral'           => ['enabled' => true, 'sensitivity' => 'medium'],
        'statistical'          => ['enabled' => true, 'stddev_threshold' => 3],
        'rule_based'           => ['enabled' => true],
    ],
],
```

Detectors can be individually toggled. Custom detectors register via the service provider — see [Custom detectors](../advanced/custom-detectors.md).

## `threat_intelligence`

```php
'threat_intelligence' => [
    'providers' => [
        'abuse_ipdb'           => ['enabled' => false, 'api_key' => env('ABUSE_IPDB_API_KEY')],
        'google_safe_browsing' => ['enabled' => false, 'api_key' => env('GOOGLE_SAFE_BROWSING_KEY')],
        'ip_quality_score'     => ['enabled' => false, 'api_key' => env('IP_QUALITY_SCORE_KEY')],
        'virus_total'          => ['enabled' => false, 'api_key' => env('VIRUSTOTAL_API_KEY')],
        'custom_feed'          => ['enabled' => false, 'url' => env('CUSTOM_FEED_URL')],
    ],
],
```

All providers default to off — enable individually as you wire up credentials.

## `siem`

```php
'siem' => [
    'enabled'  => env('SECURITY_ANALYTICS_SIEM_ENABLED', false),
    'exporter' => env('SECURITY_ANALYTICS_SIEM_EXPORTER', 'webhook'),
    'datadog'       => [ 'api_key' => env('DATADOG_API_KEY'), 'site' => env('DATADOG_SITE', 'datadoghq.com') ],
    'elasticsearch' => [ 'url' => env('ELASTICSEARCH_URL'), 'username' => env('ELASTIC_USERNAME'), 'password' => env('ELASTIC_PASSWORD') ],
    'splunk'        => [ 'url' => env('SPLUNK_HEC_URL'), 'token' => env('SPLUNK_HEC_TOKEN') ],
    'syslog'        => [ 'host' => env('SYSLOG_HOST'), 'port' => env('SYSLOG_PORT', 514) ],
    'webhook'       => [ 'url' => env('SIEM_WEBHOOK_URL') ],
],
```

Single active exporter at a time. Run `php artisan security:test-siem` after configuring to verify connectivity.

## `alerting`

```php
'alerting' => [
    'channels' => [
        'database'   => ['enabled' => true],
        'email'      => ['enabled' => true, 'to' => env('SECURITY_ALERT_EMAIL')],
        'slack'      => ['enabled' => false, 'webhook' => env('SLACK_WEBHOOK')],
        'teams'      => ['enabled' => false, 'webhook' => env('TEAMS_WEBHOOK')],
        'pagerduty'  => ['enabled' => false, 'integration_key' => env('PAGERDUTY_KEY')],
        'opsgenie'   => ['enabled' => false, 'api_key' => env('OPSGENIE_KEY')],
        'sms'        => ['enabled' => false, 'to' => env('SECURITY_ALERT_SMS')],
        'webhook'    => ['enabled' => false, 'url' => env('SECURITY_ALERT_WEBHOOK')],
    ],
],
```

Multiple channels can be active simultaneously — alerts fan out to every enabled channel matched by the routing rules.

## `incident_response`

```php
'incident_response' => [
    'enabled'   => env('SECURITY_ANALYTICS_INCIDENT_RESPONSE_ENABLED', false),
    'playbooks' => [
        // playbook ID => array of action definitions
    ],
],
```

Default off — incident response automation runs only when explicitly enabled and a playbook is defined. See [Usage → Incident response](../usage/incident-response.md).

## `reports`

```php
'reports' => [
    'storage_disk' => env('SECURITY_ANALYTICS_REPORT_DISK', 'local'),
    'storage_path' => 'security-reports',
    'formats'      => ['pdf', 'csv', 'json'],
],
```

`ScheduledReport` rows drive generation; the generated artifacts land on the configured disk.
