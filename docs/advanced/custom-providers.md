---
title: Custom Threat Intel Providers
---

# Custom Threat Intel Providers

`ThreatIntelProviderInterface`:

```php
interface ThreatIntelProviderInterface
{
    public function lookup( string $indicator, string $type ): ?ThreatLookupResult;
    public function isAvailable(): bool;
    public function getName(): string;
}
```

`$type` is one of `ip`, `url`, `hash`. Return `null` when your provider doesn't support that indicator type — the aggregator skips it and moves on.

`AbstractProvider` handles HTTP boilerplate, caching, and rate limiting. Subclass it for the common shape.

## Example: internal allowlist provider

```php
namespace App\SecurityAnalytics\Providers;

use ArtisanPackUI\SecurityAnalytics\Analytics\ThreatIntelligence\Contracts\ThreatIntelProviderInterface;
use ArtisanPackUI\SecurityAnalytics\Analytics\ThreatIntelligence\ThreatLookupResult;

class InternalAllowlistProvider implements ThreatIntelProviderInterface
{
    public function __construct(
        protected array $allowlist,
    ) {}

    public function lookup( string $indicator, string $type ): ?ThreatLookupResult
    {
        if ( $type !== 'ip' ) {
            return null;
        }

        if ( in_array( $indicator, $this->allowlist, true ) ) {
            return ThreatLookupResult::clean(
                indicator: $indicator,
                provider: $this->getName(),
                note: 'Internal allowlist match.',
            );
        }

        return null;
    }

    public function isAvailable(): bool
    {
        return true;
    }

    public function getName(): string
    {
        return 'internal_allowlist';
    }
}
```

A clean result short-circuits the aggregator — once any provider explicitly clears an indicator, others don't get queried.

## Registering

```php
use ArtisanPackUI\SecurityAnalytics\Analytics\ThreatIntelligence\ThreatIntelligenceService;
use App\SecurityAnalytics\Providers\InternalAllowlistProvider;

$this->app->afterResolving( ThreatIntelligenceService::class, function ( ThreatIntelligenceService $service ): void {
    $service->extend( new InternalAllowlistProvider(
        allowlist: config('security.internal_ips', []),
    ) );
} );
```

## Lookup order

Providers run in registration order. Use this to your advantage:

1. Cheap providers first (in-memory allowlists, local DB lookups)
2. Cached external providers next
3. Live external API providers last

Once any provider returns a definitive result (clean or malicious), the aggregator stops. Slow / expensive providers only fire when the cheaper ones don't have an answer.

## Conventions

- **Null vs clean vs malicious.** Null means "I have no opinion." Clean means "I checked and this is safe." Malicious means "I checked and this is bad." The three are different — the aggregator treats them differently.
- **Cache externally.** The aggregator caches the *aggregate* result. If your provider hits an external API, cache that response too inside your provider implementation — the aggregator cache may miss in scenarios your local cache catches.
- **Handle network failures gracefully.** Return null on timeout / connection error; don't throw. Other providers in the chain can still succeed.
