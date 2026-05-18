---
title: Custom Detectors
---

# Custom Detectors

`DetectorInterface` has three methods:

```php
namespace ArtisanPackUI\SecurityAnalytics\Analytics\AnomalyDetection\Contracts;

use ArtisanPackUI\SecurityAnalytics\Models\Anomaly;
use ArtisanPackUI\SecurityAnalytics\Models\SecurityEvent;
use Illuminate\Support\Collection;

interface DetectorInterface
{
    /**
     * Inspect an event (or batch) and return any anomalies detected.
     *
     * @param Collection<int, SecurityEvent> $events
     * @return Collection<int, Anomaly>
     */
    public function detect( Collection $events ): Collection;

    public function getName(): string;

    public function getDescription(): string;
}
```

The `AbstractDetector` base class handles common boilerplate (config lookup, anomaly creation, severity calculation). Subclass it for most use cases.

## Example: detecting weekend admin access

```php
namespace App\SecurityAnalytics\Detectors;

use ArtisanPackUI\SecurityAnalytics\Analytics\AnomalyDetection\Detectors\AbstractDetector;
use ArtisanPackUI\SecurityAnalytics\Models\Anomaly;
use ArtisanPackUI\SecurityAnalytics\Models\SecurityEvent;
use Illuminate\Support\Collection;

class WeekendAdminAccessDetector extends AbstractDetector
{
    public function detect( Collection $events ): Collection
    {
        return $events
            ->filter( fn ( SecurityEvent $event ) => $event->event_type === 'access'
                && str_starts_with( $event->event_name, 'admin.' )
                && in_array( $event->created_at->dayOfWeek, [0, 6], true ) )
            ->map( fn ( SecurityEvent $event ) => $this->createAnomaly(
                event: $event,
                severity: 'medium',
                confidence: 70,
                metadata: [ 'reason' => 'admin access on weekend' ],
            ) );
    }

    public function getName(): string
    {
        return 'weekend_admin_access';
    }

    public function getDescription(): string
    {
        return 'Flags admin-area access during weekends';
    }
}
```

## Registering your detector

In a service provider's `boot()`:

```php
use ArtisanPackUI\SecurityAnalytics\Analytics\AnomalyDetection\AnomalyDetectionService;
use App\SecurityAnalytics\Detectors\WeekendAdminAccessDetector;

$this->app->afterResolving( AnomalyDetectionService::class, function ( AnomalyDetectionService $service ): void {
    $service->extend( new WeekendAdminAccessDetector() );
} );
```

Your detector now runs alongside the 8 shipped ones every time `security:detect-suspicious` runs (or `security_analytics()->detection()->analyze()` is called inline).

## Replacing a shipped detector

To swap your implementation in for a shipped one (e.g. a smarter geo-velocity check), use the same `extend()` call but match the existing name:

```php
$service->extend( new SmarterGeoVelocityDetector() );
// Replaces the shipped GeoVelocityDetector since both call themselves 'geo_velocity'.
```

## Disabling a shipped detector entirely

```php
'anomaly_detection' => [
    'detectors' => [
        'geo_velocity' => ['enabled' => false],
    ],
],
```

The detection service skips disabled detectors without instantiating them.

## Conventions

- **Fast is better than complete.** The detector runs against potentially thousands of events per batch. Use database queries that exploit indexes; avoid N+1.
- **Confidence scoring.** Use a 0..100 scale. Below 30 = noise, 30–70 = signal worth surfacing, 70+ = high confidence (gets surfaced more prominently).
- **Idempotent.** Running the detector twice over the same events should produce the same anomalies — the framework deduplicates by event_id + detector_name when writing rows.
