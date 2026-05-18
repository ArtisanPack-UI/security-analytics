<?php

/**
 * SiemExporterInterface contract.
 *
 * @package    ArtisanPack_UI
 * @subpackage SecurityAnalytics
 *
 * @author     Jacob Martella <support@artisanpackui.dev>
 *
 * @since      1.0.0
 */

declare( strict_types=1 );

namespace ArtisanPackUI\SecurityAnalytics\Analytics\Siem\Contracts;

interface SiemExporterInterface
{
    /**
     * Get the exporter name.
     */
    public function getName(): string;

    /**
     * Check if the exporter is enabled.
     */
    public function isEnabled(): bool;

    /**
     * Export a single event.
     *
     * @param  array<string, mixed>  $event
     *
     * @return array<string, mixed>
     */
    public function export( array $event ): array;

    /**
     * Export multiple events in batch.
     *
     * @param  array<int, array<string, mixed>>  $events
     *
     * @return array<string, mixed>
     */
    public function exportBatch( array $events ): array;

    /**
     * Get exporter configuration.
     *
     * @return array<string, mixed>
     */
    public function getConfig(): array;
}
