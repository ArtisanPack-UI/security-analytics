---
title: Event Logging
---

# Event Logging

`SecurityEventLogger` writes structured rows to the `security_events` table. Every other subsystem in the package consumes that table — detection, alerting, reports, SIEM export.

## Logging an event

```php
security_analytics()->logger()->log(
    type: 'authentication',          // free-form bucket
    name: 'login.failed',            // free-form specific event name
    severity: 'warning',             // info | notice | warning | error | critical
    context: [                       // serialized as JSON
        'email'    => $request->input('email'),
        'user_id'  => $user?->id,
    ],
    request: $request,               // optional — captures IP, UA, URL, session
);
```

Every field except `name` is optional. The shipped severities follow PSR-3.

## Fields written

| Column | Source |
|---|---|
| `event_type` | `type` arg |
| `event_name` | `name` arg |
| `severity` | `severity` arg |
| `user_id` | `request->user()->id` or `context['user_id']` |
| `ip_address` | `request->ip()` or `context['ip_address']` |
| `user_agent` | `request->userAgent()` |
| `url` | `request->fullUrl()` |
| `session_id` | `request->session()->getId()` |
| `details` | the `context` array, JSON-encoded |
| `created_at` | automatic |

The `SecurityEvent` model exposes a `user()` relationship that resolves against `config('auth.providers.users.model')`.

## Automatic Laravel auth event capture

The bundled `LogAuthenticationEvents` listener auto-attaches to:

- `Illuminate\Auth\Events\Login`
- `Illuminate\Auth\Events\Logout`
- `Illuminate\Auth\Events\Failed`
- `Illuminate\Auth\Events\Lockout`
- `Illuminate\Auth\Events\PasswordReset`
- `Illuminate\Auth\Events\Verified`

…and writes a corresponding `security_events` row. To opt out, set:

```php
'logging' => ['auto_log_auth_events' => false],
```

To extend (capture more event types), implement your own listener in your app and call `security_analytics()->logger()->log(...)` from it. The package doesn't try to be exhaustive — only the auth events are auto-captured.

## The `SecurityEventOccurred` event

After a row is written, the package dispatches a `SecurityEventOccurred` event with the new `SecurityEvent` model. Subscribe to it to trigger alerting, SIEM export, or custom downstream behavior:

```php
use ArtisanPackUI\SecurityAnalytics\Events\SecurityEventOccurred;
use Illuminate\Support\Facades\Event;

Event::listen( SecurityEventOccurred::class, function ( SecurityEventOccurred $event ): void {
    // $event->securityEvent — the new row
} );
```

## Querying events

The `SecurityEvent` model is a standard Eloquent model. Common queries:

```php
use ArtisanPackUI\SecurityAnalytics\Models\SecurityEvent;

// Recent failed logins
SecurityEvent::where('event_name', 'login.failed')
    ->where('created_at', '>=', now()->subDay())
    ->latest()->get();

// Events for a user
SecurityEvent::where('user_id', $user->id)->latest()->limit(100)->get();

// Critical events in the last hour
SecurityEvent::where('severity', 'critical')
    ->where('created_at', '>=', now()->subHour())
    ->get();
```

## Pruning

Old events accumulate fast. The `security:prune-analytics` command drops rows past the configured retention window:

```bash
php artisan security:prune-analytics
php artisan security:prune-analytics --older-than=30  # override default
```

Schedule daily.
