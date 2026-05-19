<?php

/**
 * SecurityAlert alerting class.
 *
 * @package    ArtisanPack_UI
 * @subpackage SecurityAnalytics
 *
 * @author     Jacob Martella <support@artisanpackui.dev>
 *
 * @since      1.0.0
 */

declare( strict_types=1 );

namespace ArtisanPackUI\SecurityAnalytics\Analytics\Alerting;

class SecurityAlert
{
    /**
     * @var array<int, string>
     */
    protected array $channels = [];

    /**
     * @param  array<string, mixed>  $metadata
     */
    public function __construct(
        protected string $title,
        protected string $message,
        protected string $severity = 'medium',
        protected string $category = 'security',
        protected array $metadata = [],
    ) {
    }

    /**
     * Get the alert title.
     */
    public function getTitle(): string
    {
        return $this->title;
    }

    /**
     * Get the alert message.
     */
    public function getMessage(): string
    {
        return $this->message;
    }

    /**
     * Get the alert severity.
     */
    public function getSeverity(): string
    {
        return $this->severity;
    }

    /**
     * Get the alert category.
     */
    public function getCategory(): string
    {
        return $this->category;
    }

    /**
     * Get the alert metadata.
     *
     * @return array<string, mixed>
     */
    public function getMetadata(): array
    {
        return $this->metadata;
    }

    /**
     * Set specific channels for this alert.
     *
     * @param  array<int, string>  $channels
     */
    public function setChannels( array $channels ): self
    {
        $this->channels = $channels;

        return $this;
    }

    /**
     * Get the channels for this alert.
     *
     * @return array<int, string>
     */
    public function getChannels(): array
    {
        return $this->channels;
    }

    /**
     * Check if this alert has specific channels set.
     */
    public function hasSpecificChannels(): bool
    {
        return ! empty( $this->channels );
    }

    /**
     * Convert to array.
     *
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        return [
            'title'    => $this->title,
            'message'  => $this->message,
            'severity' => $this->severity,
            'category' => $this->category,
            'metadata' => $this->metadata,
            'channels' => $this->channels,
        ];
    }
}
