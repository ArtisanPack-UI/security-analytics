<?php

declare( strict_types=1 );

namespace ArtisanPackUI\SecurityAnalytics\Events;

use Illuminate\Broadcasting\InteractsWithSockets;
use Illuminate\Broadcasting\PrivateChannel;
use Illuminate\Contracts\Broadcasting\ShouldBroadcast;
use Illuminate\Foundation\Events\Dispatchable;
use Illuminate\Queue\SerializesModels;

class SecurityEventOccurred implements ShouldBroadcast
{
    use Dispatchable;use InteractsWithSockets;use SerializesModels;

    public const TYPE_AUTHENTICATION = 'authentication';

    public const TYPE_AUTHORIZATION = 'authorization';

    public const TYPE_ACCESS = 'access';

    public const TYPE_THREAT = 'threat';

    public const TYPE_COMPLIANCE = 'compliance';

    public const TYPE_SYSTEM = 'system';

    public const SEVERITY_INFO = 'info';

    public const SEVERITY_LOW = 'low';

    public const SEVERITY_MEDIUM = 'medium';

    public const SEVERITY_HIGH = 'high';

    public const SEVERITY_CRITICAL = 'critical';

    /**
     * Create a new event instance.
     *
     * @param  array<string, mixed>  $metadata
     */
    public function __construct(
        public string $eventType,
        public string $category,
        public string $severity,
        public string $message,
        public array $metadata = [],
        public ?int $userId = null,
        public ?string $ipAddress = null,
    ) {
    }

    /**
     * Get the channels the event should broadcast on.
     *
     * @return array<int, \Illuminate\Broadcasting\Channel>
     */
    public function broadcastOn(): array
    {
        return [
            new PrivateChannel( 'security.dashboard' ),
            new PrivateChannel( 'security.events' ),
        ];
    }

    /**
     * Get the data to broadcast.
     *
     * @return array<string, mixed>
     */
    public function broadcastWith(): array
    {
        return [
            'event_type' => $this->eventType,
            'category'   => $this->category,
            'severity'   => $this->severity,
            'message'    => $this->message,
            'metadata'   => $this->metadata,
            'user_id'    => $this->userId,
            'ip_address' => $this->ipAddress,
            'timestamp'  => now()->toIso8601String(),
        ];
    }

    /**
     * The event's broadcast name.
     */
    public function broadcastAs(): string
    {
        return 'security.event';
    }

    /**
     * Create an authentication event.
     *
     * @param  array<string, mixed>  $metadata
     */
    public static function authentication(
        string $action,
        string $message,
        string $severity = self::SEVERITY_INFO,
        array $metadata = [],
        ?int $userId = null,
        ?string $ipAddress = null,
    ): self {
        return new self(
            eventType: $action,
            category: self::TYPE_AUTHENTICATION,
            severity: $severity,
            message: $message,
            metadata: $metadata,
            userId: $userId,
            ipAddress: $ipAddress,
        );
    }

    /**
     * Create an authorization event.
     *
     * @param  array<string, mixed>  $metadata
     */
    public static function authorization(
        string $action,
        string $message,
        string $severity = self::SEVERITY_INFO,
        array $metadata = [],
        ?int $userId = null,
        ?string $ipAddress = null,
    ): self {
        return new self(
            eventType: $action,
            category: self::TYPE_AUTHORIZATION,
            severity: $severity,
            message: $message,
            metadata: $metadata,
            userId: $userId,
            ipAddress: $ipAddress,
        );
    }

    /**
     * Create a threat event.
     *
     * @param  array<string, mixed>  $metadata
     */
    public static function threat(
        string $threatType,
        string $message,
        string $severity = self::SEVERITY_HIGH,
        array $metadata = [],
        ?int $userId = null,
        ?string $ipAddress = null,
    ): self {
        return new self(
            eventType: $threatType,
            category: self::TYPE_THREAT,
            severity: $severity,
            message: $message,
            metadata: $metadata,
            userId: $userId,
            ipAddress: $ipAddress,
        );
    }

    /**
     * Create an access event.
     *
     * @param  array<string, mixed>  $metadata
     */
    public static function access(
        string $action,
        string $message,
        string $severity = self::SEVERITY_INFO,
        array $metadata = [],
        ?int $userId = null,
        ?string $ipAddress = null,
    ): self {
        return new self(
            eventType: $action,
            category: self::TYPE_ACCESS,
            severity: $severity,
            message: $message,
            metadata: $metadata,
            userId: $userId,
            ipAddress: $ipAddress,
        );
    }

    /**
     * Create a compliance event.
     *
     * @param  array<string, mixed>  $metadata
     */
    public static function compliance(
        string $control,
        string $message,
        string $severity = self::SEVERITY_INFO,
        array $metadata = [],
        ?int $userId = null,
        ?string $ipAddress = null,
    ): self {
        return new self(
            eventType: $control,
            category: self::TYPE_COMPLIANCE,
            severity: $severity,
            message: $message,
            metadata: $metadata,
            userId: $userId,
            ipAddress: $ipAddress,
        );
    }

    /**
     * Create a system event.
     *
     * @param  array<string, mixed>  $metadata
     */
    public static function system(
        string $eventType,
        string $message,
        string $severity = self::SEVERITY_INFO,
        array $metadata = [],
    ): self {
        return new self(
            eventType: $eventType,
            category: self::TYPE_SYSTEM,
            severity: $severity,
            message: $message,
            metadata: $metadata,
        );
    }
}
