<?php

declare( strict_types=1 );

namespace ArtisanPackUI\SecurityAnalytics\Analytics\AnomalyDetection\Detectors;

use ArtisanPackUI\SecurityAnalytics\Models\Anomaly;
use ArtisanPackUI\SecurityAnalytics\Models\SecurityMetric;
use Illuminate\Support\Collection;

class StatisticalDetector extends AbstractDetector
{
    /**
     * {@inheritdoc}
     */
    public function getName(): string
    {
        return 'statistical';
    }

    /**
     * {@inheritdoc}
     */
    public function detect( array $data ): Collection
    {
        $anomalies = collect();

        if ( ! $this->isEnabled() ) {
            return $anomalies;
        }

        // Detect anomalies in authentication metrics
        $anomalies = $anomalies->merge( $this->detectAuthAnomalies() );

        // Detect anomalies in access patterns
        $anomalies = $anomalies->merge( $this->detectAccessAnomalies() );

        // Detect anomalies in threat metrics
        $anomalies = $anomalies->merge( $this->detectThreatAnomalies() );

        return $anomalies;
    }

    /**
     * {@inheritdoc}
     */
    protected function getDefaultConfig(): array
    {
        return [
            'enabled'              => true,
            'threshold_multiplier' => 3.0,
            'min_data_points'      => 30,
            'lookback_hours'       => 24,
        ];
    }

    /**
     * Detect authentication-related anomalies.
     *
     * @return Collection<int, Anomaly>
     */
    protected function detectAuthAnomalies(): Collection
    {
        $anomalies     = collect();
        $lookbackHours = $this->config['lookback_hours'];

        // Get recent failed login metrics
        $failedLogins = SecurityMetric::category( SecurityMetric::CATEGORY_AUTHENTICATION )
            ->metricName( 'auth.failed' )
            ->where( 'recorded_at', '>=', now()->subHours( $lookbackHours ) )
            ->pluck( 'value' )
            ->toArray();

        if ( count( $failedLogins ) >= $this->config['min_data_points'] ) {
            $anomaly = $this->analyzeMetricSeries( 'failed_logins', $failedLogins );
            if ( $anomaly ) {
                $anomalies->push( $anomaly );
            }
        }

        // Get recent lockout metrics
        $lockouts = SecurityMetric::category( SecurityMetric::CATEGORY_THREAT )
            ->metricName( 'security.account_locks' )
            ->where( 'recorded_at', '>=', now()->subHours( $lookbackHours ) )
            ->pluck( 'value' )
            ->toArray();

        if ( count( $lockouts ) >= $this->config['min_data_points'] ) {
            $anomaly = $this->analyzeMetricSeries( 'account_lockouts', $lockouts );
            if ( $anomaly ) {
                $anomalies->push( $anomaly );
            }
        }

        return $anomalies;
    }

    /**
     * Detect access-related anomalies.
     *
     * @return Collection<int, Anomaly>
     */
    protected function detectAccessAnomalies(): Collection
    {
        $anomalies     = collect();
        $lookbackHours = $this->config['lookback_hours'];

        // Get access denied metrics
        $accessDenied = SecurityMetric::category( SecurityMetric::CATEGORY_ACCESS )
            ->where( 'metric_name', 'like', 'access.%' )
            ->where( 'recorded_at', '>=', now()->subHours( $lookbackHours ) )
            ->whereJsonContains( 'tags->allowed', false )
            ->pluck( 'value' )
            ->toArray();

        if ( count( $accessDenied ) >= $this->config['min_data_points'] ) {
            $anomaly = $this->analyzeMetricSeries( 'access_denied', $accessDenied );
            if ( $anomaly ) {
                $anomalies->push( $anomaly );
            }
        }

        return $anomalies;
    }

    /**
     * Detect threat-related anomalies.
     *
     * @return Collection<int, Anomaly>
     */
    protected function detectThreatAnomalies(): Collection
    {
        $anomalies     = collect();
        $lookbackHours = $this->config['lookback_hours'];

        // Get suspicious activity metrics
        $suspiciousActivity = SecurityMetric::category( SecurityMetric::CATEGORY_THREAT )
            ->where( 'metric_name', 'like', 'security.suspicious.%' )
            ->where( 'recorded_at', '>=', now()->subHours( $lookbackHours ) )
            ->pluck( 'value' )
            ->toArray();

        if ( count( $suspiciousActivity ) >= $this->config['min_data_points'] ) {
            $anomaly = $this->analyzeMetricSeries( 'suspicious_activity', $suspiciousActivity );
            if ( $anomaly ) {
                $anomalies->push( $anomaly );
            }
        }

        return $anomalies;
    }

    /**
     * Analyze a metric series for anomalies.
     *
     * @param  array<int, float>  $values
     */
    protected function analyzeMetricSeries( string $metricKey, array $values ): ?Anomaly
    {
        if ( empty( $values ) ) {
            return null;
        }

        // Ensure all values are floats for calculation
        $values      = array_map( 'floatval', $values );
        $mean        = array_sum( $values ) / count( $values );
        $stdDev      = $this->standardDeviation( $values );
        $latestValue = (float) end( $values );
        $threshold   = $this->config['threshold_multiplier'];

        // Check if the latest value is an outlier
        $zScore = $this->zScore( $latestValue, $mean, $stdDev );

        if ( abs( $zScore ) < $threshold ) {
            return null;
        }

        // Suppress if we've already alerted on this recently
        if ( $this->shouldSuppress( $metricKey ) ) {
            return null;
        }

        // Calculate anomaly score (0-100)
        $score = min( 100, ( abs( $zScore ) / ( $threshold * 2 ) ) * 100 );

        if ( $score < $this->getMinConfidence() ) {
            return null;
        }

        $this->startCooldown( $metricKey );

        $direction = $zScore > 0 ? 'above' : 'below';

        return $this->createAnomaly(
            $this->getCategoryForMetric( $metricKey ),
            "Unusual {$metricKey} detected: value is {$direction} normal range",
            $this->determineSeverity( $score ),
            $score,
            [
                'metric'        => $metricKey,
                'current_value' => $latestValue,
                'mean'          => round( $mean, 2 ),
                'std_dev'       => round( $stdDev, 2 ),
                'z_score'       => round( $zScore, 2 ),
                'threshold'     => $threshold,
                'sample_count'  => count( $values ),
            ],
        );
    }

    /**
     * Get the category for a metric key.
     */
    protected function getCategoryForMetric( string $metricKey ): string
    {
        return match ( $metricKey ) {
            'failed_logins', 'account_lockouts' => Anomaly::CATEGORY_AUTHENTICATION,
            'access_denied'                     => Anomaly::CATEGORY_ACCESS,
            'suspicious_activity'               => Anomaly::CATEGORY_THREAT,
            default                             => Anomaly::CATEGORY_BEHAVIORAL,
        };
    }
}
