---
title: Installation
---

# Installation

## Install via Composer

```bash
composer require artisanpack-ui/security-analytics
```

Auto-registers via Laravel's package discovery.

## Run migrations

```bash
php artisan migrate
```

Creates the 10 tables: `security_events`, `security_metrics`, `anomalies`, `user_behavior_profiles`, `threat_indicators`, `response_playbooks`, `security_incidents`, `alert_rules`, `alert_history`, `suspicious_activities`.

## (Optional) Publish the config

```bash
php artisan vendor:publish --tag=security-analytics-config
```

Publishes `config/artisanpack/security-analytics.php`.

## Schedule the maintenance commands

```php
// app/Console/Kernel.php
protected function schedule( Schedule $schedule ): void
{
    $schedule->command('security:analytics-process')->everyFiveMinutes();
    $schedule->command('security:detect-suspicious')->everyTenMinutes();
    $schedule->command('security:update-baselines')->daily();
    $schedule->command('security:prune-analytics')->daily();
}
```

## Dashboard access

The dashboard is opt-in via the `view-security-dashboard` ability. Grant it via your authorization layer (Gate, policy, RBAC):

```php
// app/Providers/AuthServiceProvider.php
Gate::define( 'view-security-dashboard', fn ( $user ) => $user->is_admin );
```

Or use `artisanpack-ui/rbac` and grant a `view-security-dashboard` permission to the appropriate roles.

## Deeper topics

- [Requirements](installation/requirements.md)
- [Configuration](installation/configuration.md)
