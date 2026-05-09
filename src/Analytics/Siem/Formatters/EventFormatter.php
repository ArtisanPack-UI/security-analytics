<?php

declare( strict_types=1 );

namespace ArtisanPackUI\SecurityAnalytics\Analytics\Siem\Formatters;

use ArtisanPackUI\SecurityAnalytics\Models\Anomaly;
use ArtisanPackUI\SecurityAnalytics\Models\SecurityIncident;

class EventFormatter
{
    /**
     * Format an anomaly as a SIEM event.
     *
     * @return array<string, mixed>
     */
    public static function fromAnomaly( Anomaly $anomaly ): array
    {
        return [
            'event_type'    => 'security_anomaly',
            'event_id'      => 'anomaly_' . $anomaly->id,
            'timestamp'     => $anomaly->detected_at->toIso8601String(),
            'severity'      => self::mapSeverity( $anomaly->severity ),
            'severity_name' => $anomaly->severity,
            'category'      => $anomaly->category,
            'description'   => $anomaly->description,
            'score'         => $anomaly->score,
            'detector'      => $anomaly->detector,
            'user_id'       => $anomaly->user_id,
            'source_ip'     => $anomaly->metadata['ip'] ?? null,
            'metadata'      => $anomaly->metadata,
            'is_resolved'   => $anomaly->isResolved(),
            'application'   => config( 'app.name' ),
        ];
    }

    /**
     * Format an incident as a SIEM event.
     *
     * @return array<string, mixed>
     */
    public static function fromIncident( SecurityIncident $incident ): array
    {
        return [
            'event_type'      => 'security_incident',
            'event_id'        => 'incident_' . $incident->id,
            'incident_number' => $incident->incident_number,
            'timestamp'       => $incident->opened_at?->toIso8601String(),
            'severity'        => self::mapSeverity( $incident->severity ),
            'severity_name'   => $incident->severity,
            'category'        => $incident->category,
            'title'           => $incident->title,
            'description'     => $incident->description,
            'status'          => $incident->status,
            'assigned_to'     => $incident->assigned_to,
            'affected_users'  => $incident->affected_users,
            'affected_ips'    => $incident->affected_ips,
            'application'     => config( 'app.name' ),
        ];
    }

    /**
     * Format a generic security event.
     *
     * @param  array<string, mixed>  $data
     *
     * @return array<string, mixed>
     */
    public static function fromArray( string $eventType, array $data ): array
    {
        return [
            'event_type'    => $eventType,
            'event_id'      => $data['id'] ?? uniqid( 'event_' ),
            'timestamp'     => $data['timestamp'] ?? now()->toIso8601String(),
            'severity'      => $data['severity'] ?? 5,
            'severity_name' => $data['severity_name'] ?? 'info',
            'category'      => $data['category'] ?? 'general',
            'description'   => $data['description'] ?? '',
            'metadata'      => $data,
            'application'   => config( 'app.name' ),
        ];
    }

    /**
     * Format event to CEF (Common Event Format).
     *
     * @param  array<string, mixed>  $event
     */
    public static function toCef( array $event ): string
    {
        $vendor      = 'ArtisanPackUI';
        $product     = 'Security';
        $version     = '1.0';
        $signatureId = $event['event_type'] ?? 'unknown';
        $name        = $event['description'] ?? 'Security Event';
        $severity    = $event['severity'] ?? 5;

        $cefHeader = "CEF:0|{$vendor}|{$product}|{$version}|{$signatureId}|{$name}|{$severity}|";

        // Build extension fields
        $extensions = [];
        $mappings   = [
            'timestamp'   => 'rt',
            'source_ip'   => 'src',
            'user_id'     => 'duid',
            'category'    => 'cat',
            'detector'    => 'deviceProcessName',
            'event_id'    => 'externalId',
            'application' => 'dvchost',
        ];

        foreach ( $mappings as $key => $cefKey ) {
            if ( isset( $event[ $key ] ) && null !== $event[ $key ] ) {
                $value        = self::escapeCefValue( $event[ $key ] );
                $extensions[] = "{$cefKey}={$value}";
            }
        }

        // Add custom fields
        if ( isset( $event['score'] ) ) {
            $extensions[] = 'cs1=' . $event['score'];
            $extensions[] = 'cs1Label=Anomaly Score';
        }

        return $cefHeader . implode( ' ', $extensions );
    }

    /**
     * Format event to LEEF (Log Event Extended Format).
     *
     * @param  array<string, mixed>  $event
     */
    public static function toLeef( array $event ): string
    {
        $version        = '2.0';
        $vendor         = 'ArtisanPackUI';
        $product        = 'Security';
        $productVersion = '1.0';
        $eventId        = $event['event_type'] ?? 'unknown';

        $leefHeader = "LEEF:{$version}|{$vendor}|{$product}|{$productVersion}|{$eventId}|";

        // Build attributes
        $attributes = [];
        $mappings   = [
            'timestamp'   => 'devTime',
            'source_ip'   => 'src',
            'user_id'     => 'usrName',
            'severity'    => 'sev',
            'category'    => 'cat',
            'description' => 'msg',
        ];

        foreach ( $mappings as $key => $leefKey ) {
            if ( isset( $event[ $key ] ) && null !== $event[ $key ] ) {
                $value        = self::escapeLeefValue( $event[ $key ] );
                $attributes[] = "{$leefKey}={$value}";
            }
        }

        return $leefHeader . implode( "\t", $attributes );
    }

    /**
     * Format event to Syslog format.
     *
     * @param  array<string, mixed>  $event
     */
    public static function toSyslog( array $event, string $facility = 'local0' ): string
    {
        $facilityMap = [
            'kern'   => 0, 'user' => 1, 'mail' => 2, 'daemon' => 3,
            'auth'   => 4, 'syslog' => 5, 'lpr' => 6, 'news' => 7,
            'local0' => 16, 'local1' => 17, 'local2' => 18, 'local3' => 19,
            'local4' => 20, 'local5' => 21, 'local6' => 22, 'local7' => 23,
        ];

        $severityMap = [
            10 => 0, // critical -> emergency
            9  => 1,  // -> alert
            8  => 2,  // -> critical
            7  => 3,  // high -> error
            5  => 4,  // medium -> warning
            3  => 5,  // low -> notice
            1  => 6,  // info -> informational
            0  => 7,  // -> debug
        ];

        $facilityNum = $facilityMap[ $facility ] ?? 16;
        $severityNum = $severityMap[ $event['severity'] ?? 5 ] ?? 5;
        $priority    = ( $facilityNum * 8 ) + $severityNum;

        // RFC 5424 requires ISO-8601 timestamp with timezone
        $timestamp = now()->utc()->format( 'Y-m-d\TH:i:s.v\Z' );
        $hostname  = gethostname() ?: 'localhost';
        $appName   = 'security';
        $procId    = getmypid() ?: '-';
        $msgId     = $event['event_id'] ?? '-';

        $message = json_encode( [
            'event_type'  => $event['event_type'] ?? 'security_event',
            'category'    => $event['category'] ?? 'general',
            'description' => $event['description'] ?? '',
            'severity'    => $event['severity_name'] ?? 'info',
        ] );

        // RFC 5424 format: <priority>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID STRUCTURED-DATA MSG
        return "<{$priority}>1 {$timestamp} {$hostname} {$appName} {$procId} {$msgId} - {$message}";
    }

    /**
     * Map severity name to numeric value.
     */
    protected static function mapSeverity( string $severity ): int
    {
        return match ( $severity ) {
            'critical' => 10,
            'high'     => 7,
            'medium'   => 5,
            'low'      => 3,
            'info'     => 1,
            default    => 5,
        };
    }

    /**
     * Escape value for CEF format.
     */
    protected static function escapeCefValue( mixed $value ): string
    {
        if ( is_array( $value ) ) {
            $value = json_encode( $value );
        }

        $value = (string) $value;

        // CEF escaping: backslash, equals, pipe, newline
        return str_replace(
            ['\\', '=', '|', "\n", "\r"],
            ['\\\\', '\\=', '\\|', '\\n', '\\r'],
            $value,
        );
    }

    /**
     * Escape value for LEEF format.
     */
    protected static function escapeLeefValue( mixed $value ): string
    {
        if ( is_array( $value ) ) {
            $value = json_encode( $value );
        }

        $value = (string) $value;

        // LEEF escaping: tab, newline
        return str_replace(
            ["\t", "\n", "\r"],
            ['\\t', '\\n', '\\r'],
            $value,
        );
    }
}
