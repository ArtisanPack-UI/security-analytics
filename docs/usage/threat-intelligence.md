---
title: Threat Intelligence
---

# Threat Intelligence

`ThreatIntelligenceService` aggregates 5 pluggable providers into a single reputation lookup against IPs, URLs, and hashes.

## Shipped providers

| Provider | Lookup types |
|---|---|
| `AbuseIPDBProvider` | IP reputation, abuse confidence score |
| `GoogleSafeBrowsingProvider` | URL reputation (malware / phishing) |
| `IpQualityScoreProvider` | IP reputation, proxy / VPN / Tor detection |
| `VirusTotalProvider` | File hash lookup, URL scan, IP relation |
| `CustomFeedProvider` | Local / private feeds — STIX, MISP, or your own JSON list |

Each provider is independently enabled and configured in `config('artisanpack.security-analytics.threat_intelligence.providers')`. Enable only the ones you'll use.

## Looking up an IP

```php
$result = security_analytics()->threats()->lookupIp( '198.51.100.1' );

$result->isMalicious;     // bool — true if any enabled provider flagged
$result->confidence;      // 0..100 aggregate score
$result->matchedSources;  // ['abuse_ipdb', 'ip_quality_score']
$result->raw;             // array — full per-provider responses
```

The aggregation policy is configurable — by default, any single positive flags the IP. Switch to majority-vote or quorum modes via config.

## Looking up a URL

```php
$result = security_analytics()->threats()->lookupUrl( 'http://example.com/malware' );
```

Only providers that support URL lookups (`GoogleSafeBrowsingProvider`, `VirusTotalProvider`) participate.

## Looking up a file hash

```php
$result = security_analytics()->threats()->lookupHash( $sha256Hash );
```

Only `VirusTotalProvider` supports hash lookups today.

## Caching

Provider responses are cached per-indicator for the configured TTL (default 1 hour). Cache hits skip the API call entirely. Tune in config:

```php
'threat_intelligence' => [
    'cache' => [
        'enabled' => true,
        'ttl_minutes' => 60,
    ],
],
```

## Syncing local indicators

For private feeds and bulk import, the `security:sync-threat-feeds` command pulls indicators from the configured `CustomFeedProvider` URLs into the `threat_indicators` table:

```bash
php artisan security:sync-threat-feeds
```

Schedule daily. Local indicators are checked first on lookup — they short-circuit the API calls.

## Building a custom provider

Implement `ThreatIntelProviderInterface` (3 methods: `lookup`, `isAvailable`, `getName`) and bind your class. The interface and worked example are in [Custom providers](../advanced/custom-providers.md).
