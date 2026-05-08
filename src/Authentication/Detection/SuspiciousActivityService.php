<?php

declare( strict_types=1 );

namespace ArtisanPackUI\SecurityAnalytics\Authentication\Detection;

use ArtisanPackUI\SecurityAnalytics\Authentication\Contracts\SuspiciousActivityDetectorInterface;
use ArtisanPackUI\SecurityAnalytics\Models\SuspiciousActivity;
use DateTime;
use DateTimeInterface;
use DateTimeZone;
use Exception;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Http\Request;
use Illuminate\Support\Collection;
use Illuminate\Support\Facades\Cache;
use InvalidArgumentException;

class SuspiciousActivityService implements SuspiciousActivityDetectorInterface
{
    /**
     * Analyze a request for suspicious activity.
     */
    public function analyze( Request $request, ?Authenticatable $user = null, array $context = [] ): array
    {
        $detections = [];
        $config     = config( 'artisanpack.security-analytics.suspicious_activity.detectors', [] );

        // Brute force detection
        if ( $config['brute_force']['enabled'] ?? true ) {
            $bruteForce = $this->detectBruteForce( $request );
            if ( $bruteForce ) {
                $detections[] = $bruteForce;
            }
        }

        // Impossible travel detection
        if ( ( $config['impossible_travel']['enabled'] ?? true ) && $user ) {
            $impossibleTravel = $this->detectImpossibleTravelFromHistory( $user, $request );
            if ( $impossibleTravel ) {
                $detections[] = $impossibleTravel;
            }
        }

        // Proxy/VPN detection
        if ( $config['proxy_detection']['enabled'] ?? true ) {
            $proxy = $this->detectProxy( $request );
            if ( $proxy ) {
                $detections[] = $proxy;
            }
        }

        // Anomalous login time detection
        if ( ( $config['anomalous_login']['enabled'] ?? true ) && $user && ( $config['anomalous_login']['check_time'] ?? true ) ) {
            $timeAnomaly = $this->detectTimeAnomaly( $user );
            if ( $timeAnomaly ) {
                $detections[] = $timeAnomaly;
            }
        }

        // Calculate overall risk score
        $riskScore = $this->calculateRiskScore( $detections );

        return [
            'suspicious' => ! empty( $detections ),
            'risk_score' => $riskScore,
            'detections' => $detections,
        ];
    }

    /**
     * Detect impossible travel.
     *
     * Compares two login locations and determines if travel between them
     * would require superhuman speed. Very old logins (30+ days) are ignored
     * to prevent stale data from triggering false positives when a user
     * legitimately relocates.
     */
    public function detectImpossibleTravel( array $previousLogin, array $currentLogin ): bool
    {
        // Need location data for both logins
        if ( empty( $previousLogin['location'] ) || empty( $currentLogin['location'] ) ) {
            return false;
        }

        // Calculate time difference in hours
        $timeDiffHours = abs( $currentLogin['time'] - $previousLogin['time'] ) / 3600;

        // Skip very old comparisons (30+ days / 720 hours) to avoid false positives
        // when users legitimately relocate. This threshold is intentionally long
        // to still catch impossible travel over reasonable time periods.
        $maxComparisonHours = config( 'artisanpack.security-analytics.suspicious_activity.detectors.impossible_travel.max_comparison_hours', 720 );
        if ( $timeDiffHours > $maxComparisonHours ) {
            return false;
        }

        // Get coordinates
        $prevLat = $previousLogin['location']['latitude'] ?? null;
        $prevLon = $previousLogin['location']['longitude'] ?? null;
        $currLat = $currentLogin['location']['latitude'] ?? null;
        $currLon = $currentLogin['location']['longitude'] ?? null;

        // Use explicit null checks so coordinates of exactly 0 (the
        // equator / prime meridian) aren't treated as missing data.
        if ( null === $prevLat || null === $prevLon || null === $currLat || null === $currLon ) {
            return false;
        }

        // Calculate distance using Haversine formula
        $distanceKm = $this->haversineDistance( $prevLat, $prevLon, $currLat, $currLon );

        // Calculate required speed
        $requiredSpeedKmh = $timeDiffHours > 0 ? $distanceKm / $timeDiffHours : PHP_INT_MAX;

        // Get max allowed speed (default 1000 km/h - faster than commercial aircraft)
        $maxSpeedKmh = config( 'artisanpack.security-analytics.suspicious_activity.detectors.impossible_travel.max_speed_kmh', 1000 );

        return $requiredSpeedKmh > $maxSpeedKmh;
    }

    /**
     * Record a suspicious activity.
     */
    public function record(
        Request $request,
        string $type,
        string $severity,
        float $riskScore,
        array $details,
        ?Authenticatable $user = null,
    ): SuspiciousActivity {
        return SuspiciousActivity::create( [
            'user_id'      => $user?->getAuthIdentifier(),
            'type'         => $type,
            'severity'     => $severity,
            'risk_score'   => $riskScore,
            'ip_address'   => $request->ip(),
            'location'     => $this->getLocationFromIp( $request->ip() ),
            'details'      => $details,
            'action_taken' => $this->getRecommendedAction( $severity ),
        ] );
    }

    /**
     * Get recommended action based on severity.
     */
    public function getRecommendedAction( string $severity ): string
    {
        $actions = config( 'artisanpack.security-analytics.suspicious_activity.response_actions', [
            SuspiciousActivity::SEVERITY_LOW      => SuspiciousActivity::ACTION_NOTIFY,
            SuspiciousActivity::SEVERITY_MEDIUM   => SuspiciousActivity::ACTION_CAPTCHA,
            SuspiciousActivity::SEVERITY_HIGH     => SuspiciousActivity::ACTION_STEP_UP,
            SuspiciousActivity::SEVERITY_CRITICAL => SuspiciousActivity::ACTION_BLOCK,
        ] );

        return $actions[ $severity ] ?? SuspiciousActivity::ACTION_NONE;
    }

    /**
     * Check if an IP is known to be malicious.
     */
    public function isKnownMaliciousIp( string $ipAddress ): bool
    {
        // In production, integrate with threat intelligence services
        return false;
    }

    /**
     * Check if an IP is a Tor exit node.
     */
    public function isTorExitNode( string $ipAddress ): bool
    {
        // In production, check against Tor exit node list
        return false;
    }

    /**
     * Check if an IP is from a VPN or proxy.
     */
    public function isProxyOrVpn( string $ipAddress ): bool
    {
        // In production, use IP reputation service
        return false;
    }

    /**
     * Check if an IP is from a datacenter.
     */
    public function isDatacenterIp( string $ipAddress ): bool
    {
        // In production, check against known datacenter IP ranges
        return false;
    }

    /**
     * Calculate risk score (0-100 scale).
     */
    public function calculateRiskScore( array $factors ): int
    {
        if ( empty( $factors ) ) {
            return 0;
        }

        $severityWeights = [
            SuspiciousActivity::SEVERITY_LOW      => 10,
            SuspiciousActivity::SEVERITY_MEDIUM   => 30,
            SuspiciousActivity::SEVERITY_HIGH     => 60,
            SuspiciousActivity::SEVERITY_CRITICAL => 100,
        ];

        $totalScore = 0;
        foreach ( $factors as $factor ) {
            $severity = $factor['severity'] ?? SuspiciousActivity::SEVERITY_LOW;
            $weight   = $factor['weight'] ?? $severityWeights[ $severity ];
            $totalScore += $weight;
        }

        return min( 100, $totalScore );
    }

    /**
     * Determine severity from risk score.
     */
    public function determineSeverity( int $riskScore ): string
    {
        if ( $riskScore >= 80 ) {
            return SuspiciousActivity::SEVERITY_CRITICAL;
        }
        if ( $riskScore >= 50 ) {
            return SuspiciousActivity::SEVERITY_HIGH;
        }
        if ( $riskScore >= 25 ) {
            return SuspiciousActivity::SEVERITY_MEDIUM;
        }

        return SuspiciousActivity::SEVERITY_LOW;
    }

    /**
     * Get unresolved suspicious activities.
     */
    public function getUnresolvedActivities( ?Authenticatable $user = null ): Collection
    {
        $query = SuspiciousActivity::unresolved()->orderByDesc( 'created_at' );

        if ( $user ) {
            $query->where( 'user_id', $user->getAuthIdentifier() );
        }

        return $query->get();
    }

    /**
     * Resolve a suspicious activity.
     */
    public function resolve( SuspiciousActivity $activity, ?Authenticatable $resolvedBy = null ): void
    {
        $activity->resolve( $resolvedBy?->getAuthIdentifier() );
    }

    /**
     * Prune old records.
     */
    public function pruneOldRecords( int $retentionDays ): int
    {
        if ( $retentionDays < 1 ) {
            // Zero/negative retention would push the cutoff to now() or
            // the future and delete *current* records — refuse loudly
            // rather than silently mass-deleting active activity rows.
            throw new InvalidArgumentException(
                "Retention days must be a positive integer; got {$retentionDays}.",
            );
        }

        return SuspiciousActivity::where( 'created_at', '<', now()->subDays( $retentionDays ) )->delete();
    }

    /**
     * Increment login attempts for rate limiting using atomic operations.
     *
     * Uses Cache::increment() for atomic operations when supported by the cache driver.
     * Falls back to a locking mechanism for drivers that don't support atomic increments.
     */
    public function incrementLoginAttempts( string $ip ): void
    {
        $windowMinutes = config( 'artisanpack.security-analytics.suspicious_activity.detectors.brute_force.window_minutes', 15 );
        $cacheKey      = "login_attempts_{$ip}";
        $ttlSeconds    = $windowMinutes * 60;

        // Use add-if-not-exists to establish the key with TTL for new entries.
        // Cache::add() returns true if key was added, false if it already exists.
        // This ensures the TTL is set atomically with the initial value.
        $added = Cache::add( $cacheKey, 0, now()->addSeconds( $ttlSeconds ) );

        // Now atomically increment. For drivers that support it (Redis, Memcached),
        // this is a single atomic operation. For file/array drivers, Laravel handles locking.
        $result = Cache::increment( $cacheKey );

        // If increment failed (driver doesn't support it), fall back to locked increment
        if ( false === $result ) {
            Cache::lock( "lock_{$cacheKey}", 10 )->block( 5, function () use ( $cacheKey, $ttlSeconds ): void {
                $attempts = Cache::get( $cacheKey, 0 );
                Cache::put( $cacheKey, $attempts + 1, now()->addSeconds( $ttlSeconds ) );
            } );
        }
    }

    /**
     * Clear login attempts.
     */
    public function clearLoginAttempts( string $ip ): void
    {
        Cache::forget( "login_attempts_{$ip}" );
    }

    /**
     * Detect brute force attacks.
     *
     * Note: For this detection to work, incrementLoginAttempts() must be called
     * on each failed login attempt (typically in your authentication controller
     * or middleware before this detection runs).
     *
     * @return array{type: string, severity: string, details: array}|null
     */
    protected function detectBruteForce( Request $request ): ?array
    {
        $config        = config( 'artisanpack.security-analytics.suspicious_activity.detectors.brute_force', [] );
        $threshold     = $config['threshold'] ?? 5;
        $windowMinutes = $config['window_minutes'] ?? 15;

        $ip       = $request->ip();
        $cacheKey = "login_attempts_{$ip}";

        $attempts = Cache::get( $cacheKey, 0 );

        if ( $attempts >= $threshold ) {
            return [
                'type'     => SuspiciousActivity::TYPE_BRUTE_FORCE,
                'severity' => SuspiciousActivity::SEVERITY_HIGH,
                'details'  => [
                    'ip'             => $ip,
                    'attempts'       => $attempts,
                    'threshold'      => $threshold,
                    'window_minutes' => $windowMinutes,
                ],
            ];
        }

        return null;
    }

    /**
     * Detect impossible travel from user's login history.
     *
     * This method checks the user's last successful login to detect impossible travel.
     * It uses the user model's last_login_at and last_login_ip fields, or falls back
     * to a dedicated login_history table if configured.
     *
     * @return array{type: string, severity: string, details: array}|null
     */
    protected function detectImpossibleTravelFromHistory( Authenticatable $user, Request $request ): ?array
    {
        // Get last successful login from user model or login history
        $previousLogin = $this->getLastSuccessfulLogin( $user );

        if ( null === $previousLogin ) {
            return null;
        }

        $currentLogin = [
            'time'     => time(),
            'ip'       => $request->ip(),
            'location' => $this->getLocationFromIp( $request->ip() ),
        ];

        if ( $this->detectImpossibleTravel( $previousLogin, $currentLogin ) ) {
            return [
                'type'     => SuspiciousActivity::TYPE_IMPOSSIBLE_TRAVEL,
                'severity' => SuspiciousActivity::SEVERITY_CRITICAL,
                'details'  => [
                    'previous_location'     => $previousLogin['location'],
                    'current_location'      => $currentLogin['location'],
                    'time_difference_hours' => ( $currentLogin['time'] - $previousLogin['time'] ) / 3600,
                ],
            ];
        }

        return null;
    }

    /**
     * Get the user's last successful login information.
     *
     * Attempts to get last login data from:
     * 1. User model fields (last_login_at, last_login_ip)
     * 2. UserSession table (most recent active/expired session)
     * 3. Falls back to null if no login history available
     *
     * @return array{time: int, ip: string, location: array}|null
     */
    protected function getLastSuccessfulLogin( Authenticatable $user ): ?array
    {
        // Try to get from user model fields first
        if ( method_exists( $user, 'getAttribute' ) ) {
            $lastLoginAt = $user->getAttribute( 'last_login_at' );
            $lastLoginIp = $user->getAttribute( 'last_login_ip' );

            if ( $lastLoginAt && $lastLoginIp ) {
                $timestamp = $lastLoginAt instanceof DateTimeInterface
                    ? $lastLoginAt->getTimestamp()
                    : strtotime( $lastLoginAt );

                return [
                    'time'     => $timestamp,
                    'ip'       => $lastLoginIp,
                    'location' => $this->getLocationFromIp( $lastLoginIp ),
                ];
            }
        }

        // Try to get from UserSession table
        $userSessionClass = \ArtisanPackUI\SecurityAnalytics\Models\UserSession::class;
        if ( class_exists( $userSessionClass ) ) {
            $lastSession = $userSessionClass::where( 'user_id', $user->getAuthIdentifier() )
                ->whereNotNull( 'ip_address' )
                ->orderByDesc( 'created_at' )
                ->first();

            if ( $lastSession && $lastSession->ip_address ) {
                $timestamp = $lastSession->created_at instanceof DateTimeInterface
                    ? $lastSession->created_at->getTimestamp()
                    : strtotime( $lastSession->created_at );

                return [
                    'time'     => $timestamp,
                    'ip'       => $lastSession->ip_address,
                    'location' => $lastSession->location ?? $this->getLocationFromIp( $lastSession->ip_address ),
                ];
            }
        }

        return null;
    }

    /**
     * Calculate distance using Haversine formula.
     */
    protected function haversineDistance( float $lat1, float $lon1, float $lat2, float $lon2 ): float
    {
        $earthRadiusKm = 6371;

        $dLat = deg2rad( $lat2 - $lat1 );
        $dLon = deg2rad( $lon2 - $lon1 );

        $a = sin( $dLat / 2 ) * sin( $dLat / 2 )
            + cos( deg2rad( $lat1 ) ) * cos( deg2rad( $lat2 ) )
            * sin( $dLon / 2 ) * sin( $dLon / 2 );

        $c = 2 * atan2( sqrt( $a ), sqrt( 1 - $a ) );

        return $earthRadiusKm * $c;
    }

    /**
     * Get location from IP address (placeholder).
     *
     * @return array<string, mixed>|null
     */
    protected function getLocationFromIp( string $ip ): ?array
    {
        // Default placeholder — apps in production should override this
        // method (or bind a custom subclass) to plug in MaxMind / IPinfo /
        // Cloudflare GeoIP. We surface lat/long as nulls *and* a flag so
        // detectImpossibleTravel() can decide to skip rather than evaluate
        // against unusable data.
        return [
            'ip'           => $ip,
            'latitude'     => null,
            'longitude'    => null,
            'country'      => null,
            'city'         => null,
            'lookup_ready' => false,
        ];
    }

    /**
     * Detect proxy/VPN usage.
     *
     * This method uses a multi-layered approach to avoid false positives:
     * 1. Checks IP reputation via isProxyOrVpn() (integrate with commercial API in production)
     * 2. Detects IP mismatch when request comes through untrusted proxies
     * 3. Ignores standard load balancer/CDN headers from trusted proxies
     *
     * @return array{type: string, severity: string, details: array}|null
     */
    protected function detectProxy( Request $request ): ?array
    {
        $ip         = $request->ip();
        $indicators = [];

        // Get trusted proxy IPs from config (load balancers, CDNs, etc.)
        $trustedProxies = config( 'artisanpack.security-analytics.suspicious_activity.detectors.proxy_detection.trusted_proxies', [] );

        // If request is from a trusted proxy, don't flag it
        if ( in_array( $ip, $trustedProxies, true ) ) {
            return null;
        }

        // Check 1: IP reputation service (integrate with commercial API in production)
        if ( $this->isProxyOrVpn( $ip ) ) {
            $indicators[] = 'ip_reputation_flagged';
        }

        // Check 2: Detect IP mismatch - only suspicious if there's a discrepancy
        // between the request IP and the forwarded IP chain from untrusted sources
        $forwardedFor = $request->server( 'HTTP_X_FORWARDED_FOR' );
        if ( $forwardedFor ) {
            // Parse the X-Forwarded-For chain
            $forwardedIps  = array_map( 'trim', explode( ',', $forwardedFor ) );
            $originatingIp = $forwardedIps[0] ?? null; // Client's original IP

            // Only flag if originating IP differs from request IP AND
            // the request didn't come from a trusted proxy
            if ( $originatingIp && $originatingIp !== $ip ) {
                // This could be legitimate (load balancer) or suspicious (proxy)
                // Only flag if not from a known trusted proxy
                $lastProxy = end( $forwardedIps );
                if ( ! in_array( $lastProxy, $trustedProxies, true ) ) {
                    $indicators[] = 'ip_mismatch_untrusted';
                }
            }
        }

        // Check 3: Suspicious proxy-specific headers (not standard load balancer headers)
        $suspiciousHeaders = [
            'HTTP_VIA',                  // Explicit proxy declaration
            'HTTP_PROXY_CONNECTION',     // Proxy-specific connection header
        ];

        foreach ( $suspiciousHeaders as $header ) {
            if ( $request->server( $header ) ) {
                $indicators[] = $header;
            }
        }

        // Only flag if we have actual suspicious indicators
        if ( ! empty( $indicators ) ) {
            return [
                'type'     => SuspiciousActivity::TYPE_PROXY_DETECTED,
                'severity' => SuspiciousActivity::SEVERITY_MEDIUM,
                'details'  => [
                    'indicators' => $indicators,
                    'ip'         => $ip,
                ],
            ];
        }

        return null;
    }

    /**
     * Detect unusual login time.
     *
     * Uses the user's timezone when available (from user profile or session),
     * falls back to application timezone or UTC. Unusual hours are configurable
     * via config('artisanpack.security-analytics.suspicious_activity.detectors.anomalous_login').
     *
     * @return array{type: string, severity: string, details: array}|null
     */
    protected function detectTimeAnomaly( Authenticatable $user ): ?array
    {
        // Get configurable unusual hours
        $config            = config( 'artisanpack.security-analytics.suspicious_activity.detectors.anomalous_login', [] );
        $unusualHoursStart = $config['unusual_hours_start'] ?? 2;
        $unusualHoursEnd   = $config['unusual_hours_end'] ?? 5;

        // Try to get user's timezone
        $userTimezone = $this->getUserTimezone( $user );

        if ( null === $userTimezone ) {
            // Skip time-based detection when no reliable timezone is available
            // to avoid false positives
            return null;
        }

        try {
            $userTime    = new DateTime( 'now', new DateTimeZone( $userTimezone ) );
            $currentHour = (int) $userTime->format( 'G' );
        } catch ( Exception $e ) {
            // Invalid timezone, skip detection
            return null;
        }

        // Same-day window (e.g. 1:00 → 5:00): fall inside the half-open
        // [start, end) interval. Overnight wrap-around windows (e.g.
        // 22:00 → 6:00) split into "from start to midnight" OR "from
        // midnight to end" — without this branch, ranges where
        // start >= end would never match.
        $isUnusual = $unusualHoursStart < $unusualHoursEnd
            ? ( $currentHour >= $unusualHoursStart && $currentHour < $unusualHoursEnd )
            : ( $currentHour >= $unusualHoursStart || $currentHour < $unusualHoursEnd );

        if ( $isUnusual ) {
            return [
                'type'     => SuspiciousActivity::TYPE_UNUSUAL_TIME,
                'severity' => SuspiciousActivity::SEVERITY_LOW,
                'details'  => [
                    'login_hour'    => $currentHour,
                    'timezone'      => $userTimezone,
                    'unusual_range' => "{$unusualHoursStart}:00 - {$unusualHoursEnd}:00",
                ],
            ];
        }

        return null;
    }

    /**
     * Get the user's timezone.
     *
     * Attempts to retrieve timezone from:
     * 1. User model 'timezone' attribute
     * 2. Application default timezone
     *
     * Returns null if no reliable timezone can be determined.
     */
    protected function getUserTimezone( Authenticatable $user ): ?string
    {
        // Try to get timezone from user model
        if ( method_exists( $user, 'getAttribute' ) ) {
            $userTimezone = $user->getAttribute( 'timezone' );
            if ( $userTimezone && $this->isValidTimezone( $userTimezone ) ) {
                return $userTimezone;
            }
        }

        // Fall back to application timezone if explicitly set
        $appTimezone = config( 'app.timezone' );
        if ( $appTimezone && 'UTC' !== $appTimezone && $this->isValidTimezone( $appTimezone ) ) {
            return $appTimezone;
        }

        // Return null to skip detection when timezone is uncertain
        return null;
    }

    /**
     * Check if a timezone string is valid.
     */
    protected function isValidTimezone( string $timezone ): bool
    {
        try {
            new DateTimeZone( $timezone );

            return true;
        } catch ( Exception $e) {
            return false;
        }
    }
}
