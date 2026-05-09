<?php

declare(strict_types=1);

return [
    /*
    |--------------------------------------------------------------------------
    | Analytics Enabled
    |--------------------------------------------------------------------------
    |
    | This option controls whether security analytics collection is enabled.
    | When disabled, no metrics will be recorded.
    |
    */
    'enabled' => env('SECURITY_ANALYTICS_ENABLED', true),

    /*
    |--------------------------------------------------------------------------
    | Metrics Configuration
    |--------------------------------------------------------------------------
    |
    | Configure how security metrics are collected and stored.
    |
    */
    'metrics' => [
        // Enable batch mode for better performance
        'batch_mode' => env('SECURITY_METRICS_BATCH', false),

        // Maximum buffer size before auto-flush in batch mode
        'batch_size' => env('SECURITY_METRICS_BATCH_SIZE', 100),

        // Retention period for metrics data (in days)
        'retention_days' => env('SECURITY_METRICS_RETENTION', 90),

        // Categories to collect (leave empty for all)
        'categories' => [
            'authentication',
            'access',
            'threat',
            'compliance',
            'performance',
            'system',
        ],
    ],

    /*
    |--------------------------------------------------------------------------
    | Anomaly Detection
    |--------------------------------------------------------------------------
    |
    | Configure anomaly detection settings.
    |
    */
    'anomaly_detection' => [
        // Enable automatic anomaly detection
        'enabled' => env('SECURITY_ANOMALY_DETECTION', true),

        // Minimum confidence score to create an anomaly (0-100)
        'min_confidence' => env('SECURITY_ANOMALY_MIN_CONFIDENCE', 70),

        // Detectors to enable
        'detectors' => [
            'statistical' => [
                'enabled' => true,
                'threshold_multiplier' => 3.0, // Standard deviations
            ],
            'behavioral' => [
                'enabled' => true,
                'baseline_period_days' => 30,
                'min_samples' => 100,
            ],
            'rule_based' => [
                'enabled' => true,
            ],
            'ml' => [
                'enabled' => false, // Requires external ML service
                'endpoint' => env('SECURITY_ML_ENDPOINT'),
                'api_key' => env('SECURITY_ML_API_KEY'),
            ],
        ],

        // Detection schedule (cron expression)
        'schedule' => env('SECURITY_ANOMALY_SCHEDULE', '*/5 * * * *'),

        // Auto-resolve anomalies after this many hours if no action taken
        'auto_resolve_hours' => env('SECURITY_ANOMALY_AUTO_RESOLVE', 72),
    ],

    /*
    |--------------------------------------------------------------------------
    | Threat Intelligence
    |--------------------------------------------------------------------------
    |
    | Configure threat intelligence feeds and providers.
    |
    */
    'threat_intelligence' => [
        // Enable threat intelligence integration
        'enabled' => env('SECURITY_THREAT_INTEL_ENABLED', true),

        // Cache duration for threat lookups (in minutes)
        'cache_ttl' => env('SECURITY_THREAT_INTEL_CACHE', 60),

        // Providers configuration
        'providers' => [
            'abuseipdb' => [
                'enabled' => env('ABUSEIPDB_ENABLED', false),
                'api_key' => env('ABUSEIPDB_API_KEY'),
                'min_confidence' => 80,
            ],
            'virustotal' => [
                'enabled' => env('VIRUSTOTAL_ENABLED', false),
                'api_key' => env('VIRUSTOTAL_API_KEY'),
            ],
            'shodan' => [
                'enabled' => env('SHODAN_ENABLED', false),
                'api_key' => env('SHODAN_API_KEY'),
            ],
            'greynoise' => [
                'enabled' => env('GREYNOISE_ENABLED', false),
                'api_key' => env('GREYNOISE_API_KEY'),
            ],
        ],

        // Sync schedule for threat feeds (cron expression)
        'sync_schedule' => env('SECURITY_THREAT_SYNC_SCHEDULE', '0 */4 * * *'),

        // Auto-block IPs above this threat score (0-100, null to disable)
        'auto_block_threshold' => env('SECURITY_THREAT_AUTO_BLOCK', null),
    ],

    /*
    |--------------------------------------------------------------------------
    | Incident Response
    |--------------------------------------------------------------------------
    |
    | Configure automated incident response settings.
    |
    */
    'incident_response' => [
        // Enable automated incident response
        'enabled' => env('SECURITY_INCIDENT_RESPONSE', true),

        // Require approval for high-risk actions
        'require_approval_for' => [
            'block_user',
            'block_ip_range',
            'disable_service',
        ],

        // Available response actions
        'actions' => [
            'block_ip' => \ArtisanPackUI\Security\Analytics\IncidentResponse\Actions\BlockIpAction::class,
            'block_user' => \ArtisanPackUI\Security\Analytics\IncidentResponse\Actions\BlockUserAction::class,
            'notify_admin' => \ArtisanPackUI\Security\Analytics\IncidentResponse\Actions\NotifyAdminAction::class,
            'log_event' => \ArtisanPackUI\Security\Analytics\IncidentResponse\Actions\LogEventAction::class,
            'revoke_sessions' => \ArtisanPackUI\Security\Analytics\IncidentResponse\Actions\RevokeSessionsAction::class,
            'require_2fa' => \ArtisanPackUI\Security\Analytics\IncidentResponse\Actions\RequireTwoFactorAction::class,
        ],

        // Notification channels for incidents
        'notification_channels' => [
            'mail',
            'slack',
        ],
    ],

    /*
    |--------------------------------------------------------------------------
    | Alerting
    |--------------------------------------------------------------------------
    |
    | Configure security alert settings.
    |
    */
    'alerting' => [
        // Enable alerting system
        'enabled' => env('SECURITY_ALERTING_ENABLED', true),

        // Default cooldown between alerts (in minutes)
        'default_cooldown' => env('SECURITY_ALERT_COOLDOWN', 15),

        // Alert channels
        'channels' => [
            'email' => [
                'enabled' => true,
                'from' => env('SECURITY_ALERT_FROM', env('MAIL_FROM_ADDRESS')),
                'default_recipients' => array_filter(explode(',', env('SECURITY_ALERT_RECIPIENTS', ''))),
            ],
            'slack' => [
                'enabled' => env('SECURITY_SLACK_ENABLED', false),
                'webhook_url' => env('SECURITY_SLACK_WEBHOOK'),
                'channel' => env('SECURITY_SLACK_CHANNEL', '#security-alerts'),
            ],
            'pagerduty' => [
                'enabled' => env('SECURITY_PAGERDUTY_ENABLED', false),
                'routing_key' => env('SECURITY_PAGERDUTY_KEY'),
                'severity_mapping' => [
                    'info' => 'info',
                    'low' => 'warning',
                    'medium' => 'error',
                    'high' => 'error',
                    'critical' => 'critical',
                ],
            ],
            'webhook' => [
                'enabled' => env('SECURITY_WEBHOOK_ENABLED', false),
                'url' => env('SECURITY_WEBHOOK_URL'),
                'secret' => env('SECURITY_WEBHOOK_SECRET'),
            ],
        ],

        // Escalation settings
        'escalation' => [
            'enabled' => env('SECURITY_ESCALATION_ENABLED', true),
            'levels' => [
                1 => ['after_minutes' => 15, 'channels' => ['email']],
                2 => ['after_minutes' => 30, 'channels' => ['email', 'slack']],
                3 => ['after_minutes' => 60, 'channels' => ['email', 'slack', 'pagerduty']],
            ],
        ],
    ],

    /*
    |--------------------------------------------------------------------------
    | Dashboard & Reporting
    |--------------------------------------------------------------------------
    |
    | Configure dashboard and reporting settings.
    |
    */
    'dashboard' => [
        // Enable real-time dashboard updates
        'realtime' => env('SECURITY_DASHBOARD_REALTIME', true),

        // Broadcast channel for real-time updates
        'broadcast_channel' => 'security-dashboard',

        // Dashboard refresh interval (in seconds)
        'refresh_interval' => env('SECURITY_DASHBOARD_REFRESH', 30),

        // Widget configurations
        'widgets' => [
            'threat_overview' => true,
            'auth_activity' => true,
            'anomaly_feed' => true,
            'incident_status' => true,
            'compliance_score' => true,
            'geographic_map' => true,
        ],
    ],

    'reporting' => [
        // Enable scheduled reports
        'enabled' => env('SECURITY_REPORTS_ENABLED', true),

        // Report storage path
        'storage_path' => storage_path('app/security-reports'),

        // Available report formats
        'formats' => ['pdf', 'html', 'csv', 'json'],

        // Default format
        'default_format' => 'pdf',

        // Report templates
        'templates' => [
            'executive_summary' => \ArtisanPackUI\Security\Analytics\Reports\ExecutiveSummaryReport::class,
            'threat_report' => \ArtisanPackUI\Security\Analytics\Reports\ThreatReport::class,
            'compliance_report' => \ArtisanPackUI\Security\Analytics\Reports\ComplianceReport::class,
            'incident_report' => \ArtisanPackUI\Security\Analytics\Reports\IncidentReport::class,
            'user_activity' => \ArtisanPackUI\Security\Analytics\Reports\UserActivityReport::class,
            'trend_report' => \ArtisanPackUI\Security\Analytics\Reports\TrendReport::class,
        ],
    ],

    /*
    |--------------------------------------------------------------------------
    | SIEM Integration
    |--------------------------------------------------------------------------
    |
    | Configure integration with external SIEM systems.
    |
    */
    'siem' => [
        // Enable SIEM integration
        'enabled' => env('SECURITY_SIEM_ENABLED', false),

        // Default log format
        'format' => env('SECURITY_SIEM_FORMAT', 'cef'), // cef, leef, json, syslog

        // SIEM providers
        'providers' => [
            'splunk' => [
                'enabled' => env('SPLUNK_ENABLED', false),
                'hec_url' => env('SPLUNK_HEC_URL'),
                'hec_token' => env('SPLUNK_HEC_TOKEN'),
                'index' => env('SPLUNK_INDEX', 'security'),
                'source' => env('SPLUNK_SOURCE', 'artisanpack-security'),
            ],
            'elasticsearch' => [
                'enabled' => env('ELASTICSEARCH_ENABLED', false),
                'hosts' => explode(',', env('ELASTICSEARCH_HOSTS', 'localhost:9200')),
                'index_prefix' => env('ELASTICSEARCH_INDEX', 'security-'),
                'username' => env('ELASTICSEARCH_USERNAME'),
                'password' => env('ELASTICSEARCH_PASSWORD'),
            ],
            'syslog' => [
                'enabled' => env('SYSLOG_ENABLED', false),
                'host' => env('SYSLOG_HOST', '127.0.0.1'),
                'port' => env('SYSLOG_PORT', 514),
                'protocol' => env('SYSLOG_PROTOCOL', 'udp'), // udp, tcp, tls
                'facility' => env('SYSLOG_FACILITY', 'local0'),
            ],
        ],

        // Event types to export
        'export_events' => [
            'authentication',
            'authorization',
            'threat',
            'anomaly',
            'incident',
            'compliance',
        ],

        // Batch export settings
        'batch' => [
            'enabled' => env('SECURITY_SIEM_BATCH', true),
            'size' => env('SECURITY_SIEM_BATCH_SIZE', 100),
            'interval_seconds' => env('SECURITY_SIEM_BATCH_INTERVAL', 30),
        ],
    ],

    /*
    |--------------------------------------------------------------------------
    | User Behavior Analytics
    |--------------------------------------------------------------------------
    |
    | Configure user behavior analytics and profiling.
    |
    */
    'user_behavior' => [
        // Enable user behavior profiling
        'enabled' => env('SECURITY_UBA_ENABLED', true),

        // Profile types to build
        'profiles' => [
            'login_patterns' => true,
            'access_patterns' => true,
            'session_patterns' => true,
            'geolocation' => true,
            'device_fingerprints' => true,
        ],

        // Baseline calculation period (in days)
        'baseline_period' => env('SECURITY_UBA_BASELINE_DAYS', 30),

        // Minimum data points for reliable baseline
        'min_data_points' => env('SECURITY_UBA_MIN_POINTS', 50),

        // Deviation threshold for anomaly flagging
        'deviation_threshold' => env('SECURITY_UBA_THRESHOLD', 2.5),

        // Risk score weights
        'risk_weights' => [
            'new_device' => 0.3,
            'new_location' => 0.25,
            'unusual_time' => 0.15,
            'velocity_anomaly' => 0.2,
            'failed_attempts' => 0.1,
        ],
    ],

    /*
    |--------------------------------------------------------------------------
    | Security Event Logging
    |--------------------------------------------------------------------------
    |
    | Configure the security event audit trail. Lifted out of the
    | `eventLogging` block in `config/security.php` (1.x) when this package
    | was extracted.
    |
    */
    'storage' => [
        // Store events in the database.
        'database' => env('SECURITY_EVENTS_STORE_DB', true),

        // Log channel to use for event logging. Null = default channel.
        'logChannel' => env('SECURITY_LOG_CHANNEL', null),
    ],

    'events' => [
        'authentication' => [
            'enabled' => true,
            'logLevel' => 'info',
            'events' => [
                'loginSuccess' => true,
                'loginFailed' => true,
                'logout' => true,
                'lockout' => true,
                'passwordReset' => true,
                'registered' => true,
                'emailVerified' => true,
                'otherDeviceLogout' => true,
                'twoFactorSuccess' => true,
                'twoFactorFailed' => true,
            ],
        ],
        'authorization' => [
            'enabled' => true,
            'logLevel' => 'warning',
            'events' => [
                'permissionDenied' => true,
                'roleCheckFailed' => true,
            ],
        ],
        'apiAccess' => [
            'enabled' => true,
            'logLevel' => 'info',
            'events' => [
                'tokenCreated' => true,
                'tokenRevoked' => true,
                'tokenExpiredAccess' => true,
                'invalidToken' => true,
                'abilityDenied' => true,
            ],
        ],
        'securityViolations' => [
            'enabled' => true,
            'logLevel' => 'error',
            'events' => [
                'cspViolation' => true,
                'rateLimitExceeded' => true,
                'invalidSignature' => true,
            ],
        ],
        'roleChanges' => [
            'enabled' => true,
            'logLevel' => 'info',
        ],
        'permissionChanges' => [
            'enabled' => true,
            'logLevel' => 'info',
        ],
        'tokenManagement' => [
            'enabled' => true,
            'logLevel' => 'info',
        ],
    ],

    'retention' => [
        'enabled' => env('SECURITY_EVENTS_RETENTION_ENABLED', true),
        'days' => env('SECURITY_EVENTS_RETENTION_DAYS', 90),
        'keepCritical' => true,
    ],

    'suspiciousActivity' => [
        'enabled' => env('SECURITY_SUSPICIOUS_DETECTION_ENABLED', true),
        'thresholds' => [
            'failedLoginsPerIp' => 5,
            'failedLoginsPerUser' => 3,
            'apiErrorsPerToken' => 10,
            'permissionDenialsPerUser' => 5,
        ],
        'windowMinutes' => 15,
    ],

    'alerting' => [
        'enabled' => env('SECURITY_ALERTS_ENABLED', false),
        'channels' => ['mail'],
        'recipients' => env('SECURITY_ALERT_RECIPIENTS', ''),
        'throttleMinutes' => 15,
    ],

    /*
    |--------------------------------------------------------------------------
    | Security Dashboard
    |--------------------------------------------------------------------------
    |
    | The dashboard requires the 'viewSecurityDashboard' gate by default.
    | Define this gate in your app's AuthServiceProvider or change the
    | middleware below.
    |
    | Example:
    |   Gate::define('viewSecurityDashboard', fn ($user) => $user->hasRole('admin'));
    */
    'dashboard' => [
        'enabled' => env('SECURITY_DASHBOARD_ENABLED', true),
        'routePrefix' => 'security',
        'middleware' => ['web', 'auth', 'can:viewSecurityDashboard'],
    ],
];
