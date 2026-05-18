---
title: Custom Alert Channels
---

# Custom Alert Channels

`AlertChannelInterface` is the contract:

```php
interface AlertChannelInterface
{
    public function send( SecurityAlert $alert ): bool;
    public function isAvailable(): bool;
    public function getName(): string;
}
```

`SecurityAlert` is a value object carrying title, message, severity, context, and the rule that fired (if any).

## Example: Discord channel

```php
namespace App\SecurityAnalytics\Channels;

use ArtisanPackUI\SecurityAnalytics\Analytics\Alerting\Channels\AbstractChannel;
use ArtisanPackUI\SecurityAnalytics\Analytics\Alerting\Contracts\AlertChannelInterface;
use ArtisanPackUI\SecurityAnalytics\Analytics\Alerting\SecurityAlert;
use Illuminate\Support\Facades\Http;

class DiscordChannel implements AlertChannelInterface
{
    public function __construct(
        protected string $webhookUrl,
    ) {}

    public function send( SecurityAlert $alert ): bool
    {
        return Http::post( $this->webhookUrl, [
            'content' => "**[{$alert->severity}]** {$alert->title}\n{$alert->message}",
        ] )->successful();
    }

    public function isAvailable(): bool
    {
        return ! empty( $this->webhookUrl );
    }

    public function getName(): string
    {
        return 'discord';
    }
}
```

## Registering the channel

```php
use ArtisanPackUI\SecurityAnalytics\Analytics\Alerting\AlertManager;
use App\SecurityAnalytics\Channels\DiscordChannel;

$this->app->afterResolving( AlertManager::class, function ( AlertManager $manager ): void {
    $manager->extend( new DiscordChannel(
        webhookUrl: config('services.discord.security_webhook'),
    ) );
} );
```

You can now use `'discord'` as a channel name in `send()` calls and `AlertRule` definitions.

## Conventions

- **Return bool from `send`.** True for delivery confirmed (or accepted by the upstream), false for any error. The framework writes a corresponding `AlertHistory` row with `delivered_at` set on true, or `error_message` on false.
- **Don't throw.** Errors during delivery should be caught inside `send()` and returned as false. Throwing breaks the alert-fanout loop and a single broken channel kills delivery to all others.
- **Idempotent where possible.** Some platforms support deduplication keys (PagerDuty, OpsGenie). Use the `alert->fingerprint` when available to avoid duplicate pages for the same underlying event.
