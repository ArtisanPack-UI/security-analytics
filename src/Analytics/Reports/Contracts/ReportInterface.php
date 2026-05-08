<?php

declare( strict_types=1 );

namespace ArtisanPackUI\SecurityAnalytics\Analytics\Reports\Contracts;

interface ReportInterface
{
    /**
     * Generate the report data.
     *
     * @return array<string, mixed>
     */
    public function generate(): array;

    /**
     * Convert report to HTML format.
     *
     * @param  array<string, mixed>  $data
     */
    public function toHtml( array $data ): string;

    /**
     * Convert report to CSV format.
     *
     * @param  array<string, mixed>  $data
     */
    public function toCsv( array $data ): string;

    /**
     * Convert report to PDF format.
     *
     * @param  array<string, mixed>  $data
     */
    public function toPdf( array $data ): string;
}
