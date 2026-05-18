<?php

/**
 * SyslogExporter SIEM exporter.
 *
 * @package    ArtisanPack_UI
 * @subpackage SecurityAnalytics
 *
 * @author     Jacob Martella <support@artisanpackui.dev>
 *
 * @since      1.0.0
 */

declare( strict_types=1 );

namespace ArtisanPackUI\SecurityAnalytics\Analytics\Siem\Exporters;

use ArtisanPackUI\SecurityAnalytics\Analytics\Siem\Contracts\SiemExporterInterface;
use ArtisanPackUI\SecurityAnalytics\Analytics\Siem\Formatters\EventFormatter;
use Exception;

class SyslogExporter implements SiemExporterInterface
{
    /**
     * @var array<string, mixed>
     */
    protected array $config;

    /**
     * Socket resource for UDP/TCP connections.
     *
     * @var resource|null
     */
    protected $socket = null;

    /**
     * @param  array<string, mixed>  $config
     */
    public function __construct( array $config = [] )
    {
        $this->config = array_merge( [
            'enabled'  => false,
            'host'     => '127.0.0.1',
            'port'     => 514,
            'protocol' => 'udp', // udp, tcp
            'facility' => 'local0',
            'format'   => 'cef', // cef, leef, json, syslog
        ], $config );
    }

    /**
     * {@inheritdoc}
     */
    public function getName(): string
    {
        return 'syslog';
    }

    /**
     * {@inheritdoc}
     */
    public function isEnabled(): bool
    {
        return ( $this->config['enabled'] ?? false ) && ! empty( $this->config['host'] );
    }

    /**
     * {@inheritdoc}
     */
    public function getConfig(): array
    {
        return $this->config;
    }

    /**
     * {@inheritdoc}
     */
    public function export( array $event ): array
    {
        if ( ! $this->isEnabled() ) {
            return ['success' => false, 'error' => 'Syslog exporter is not configured'];
        }

        $message = $this->formatMessage( $event );

        return $this->send( $message );
    }

    /**
     * {@inheritdoc}
     */
    public function exportBatch( array $events ): array
    {
        if ( ! $this->isEnabled() ) {
            return ['success' => false, 'error' => 'Syslog exporter is not configured'];
        }

        $results = [
            'success'  => true,
            'exported' => 0,
            'failed'   => 0,
        ];

        foreach ( $events as $event ) {
            $message = $this->formatMessage( $event );
            $result  = $this->send( $message );

            if ( $result['success'] ) {
                $results['exported']++;
            } else {
                $results['failed']++;
                $results['success'] = false;
            }
        }

        return $results;
    }

    /**
     * Format the message based on configured format.
     *
     * @param  array<string, mixed>  $event
     */
    protected function formatMessage( array $event ): string
    {
        $format = $this->config['format'];

        return match ( $format ) {
            'cef'   => EventFormatter::toCef( $event ),
            'leef'  => EventFormatter::toLeef( $event ),
            'json'  => $this->encodeJson( $event ),
            default => EventFormatter::toSyslog( $event, $this->config['facility'] ),
        };
    }

    /**
     * Safely encode event to JSON with fallback.
     *
     * @param  array<string, mixed>  $event
     */
    protected function encodeJson( array $event ): string
    {
        $json = json_encode( $event );

        if ( false === $json ) {
            // Fallback to syslog format if JSON encoding fails
            return EventFormatter::toSyslog( $event, $this->config['facility'] );
        }

        return $json;
    }

    /**
     * Send message to syslog server.
     *
     * @return array<string, mixed>
     */
    protected function send( string $message ): array
    {
        $protocol = strtolower( $this->config['protocol'] );

        try {
            if ( 'udp' === $protocol ) {
                return $this->sendUdp( $message );
            } else {
                return $this->sendTcp( $message );
            }
        } catch ( Exception $e ) {
            return [
                'success' => false,
                'error'   => $e->getMessage(),
            ];
        }
    }

    /**
     * Send message via UDP.
     *
     * @return array<string, mixed>
     */
    protected function sendUdp( string $message ): array
    {
        $socket = socket_create( AF_INET, SOCK_DGRAM, SOL_UDP );

        if ( false === $socket ) {
            return [
                'success' => false,
                'error'   => 'Failed to create UDP socket',
            ];
        }

        $result = socket_sendto(
            $socket,
            $message,
            strlen( $message ),
            0,
            $this->config['host'],
            (int) $this->config['port'],
        );

        socket_close( $socket );

        if ( false === $result ) {
            return [
                'success' => false,
                'error'   => 'Failed to send UDP message',
            ];
        }

        return [
            'success'    => true,
            'bytes_sent' => $result,
        ];
    }

    /**
     * Send message via TCP.
     *
     * @return array<string, mixed>
     */
    protected function sendTcp( string $message ): array
    {
        $socket = @fsockopen(
            $this->config['host'],
            (int) $this->config['port'],
            $errno,
            $errstr,
            5, // 5 second timeout
        );

        if ( false === $socket ) {
            return [
                'success' => false,
                'error'   => "Failed to connect: {$errstr} ({$errno})",
            ];
        }

        // Add newline for TCP framing
        $message .= "\n";

        $result = fwrite( $socket, $message );
        fclose( $socket );

        if ( false === $result ) {
            return [
                'success' => false,
                'error'   => 'Failed to send TCP message',
            ];
        }

        return [
            'success'    => true,
            'bytes_sent' => $result,
        ];
    }
}
