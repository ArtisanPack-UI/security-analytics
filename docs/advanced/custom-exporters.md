---
title: Custom SIEM Exporters
---

# Custom SIEM Exporters

`SiemExporterInterface`:

```php
interface SiemExporterInterface
{
    public function export( array $events ): bool;
    public function isAvailable(): bool;
    public function getName(): string;
}
```

`$events` is an array of `SecurityEvent` model rows, already formatted by `EventFormatter` for the exporter's target shape.

## Example: Sumo Logic exporter

```php
namespace App\SecurityAnalytics\Exporters;

use ArtisanPackUI\SecurityAnalytics\Analytics\Siem\Contracts\SiemExporterInterface;
use Illuminate\Support\Facades\Http;

class SumoLogicExporter implements SiemExporterInterface
{
    public function __construct(
        protected string $collectorUrl,
    ) {}

    public function export( array $events ): bool
    {
        $payload = implode( "\n", array_map( fn ( $event ) => json_encode( $event ), $events ) );

        $response = Http::withBody( $payload, 'application/json' )
            ->post( $this->collectorUrl );

        return $response->successful();
    }

    public function isAvailable(): bool
    {
        return rescue(
            fn () => Http::timeout(2)->get( $this->collectorUrl . '/ping' )->successful(),
            false,
        );
    }

    public function getName(): string
    {
        return 'sumologic';
    }
}
```

## Registering

```php
$this->app->bind(
    \ArtisanPackUI\SecurityAnalytics\Analytics\Siem\Contracts\SiemExporterInterface::class,
    fn () => new \App\SecurityAnalytics\Exporters\SumoLogicExporter(
        collectorUrl: config('services.sumologic.collector_url'),
    ),
);
```

Single active exporter — bind your class to override the default.

## Conventions

- **Batch where possible.** Most SIEMs prefer fewer larger requests. The framework batches events before calling `export()` — your exporter receives the whole batch in one call.
- **Don't throw.** Same as channels — return false for failures, throw only for truly unrecoverable errors (auth misconfiguration, etc.).
- **Handle rate limits.** Many SIEMs return 429. Use Laravel's `Http::retry()` with exponential backoff in your exporter for resilience.
