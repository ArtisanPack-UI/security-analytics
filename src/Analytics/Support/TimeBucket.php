<?php

declare( strict_types=1 );

namespace ArtisanPackUI\SecurityAnalytics\Analytics\Support;

use Illuminate\Database\Query\Expression;
use Illuminate\Support\Facades\DB;

/**
 * Cross-database time-bucket SQL helper.
 *
 * Returns a `SELECT` expression that buckets a timestamp column into
 * minute / hour / day / month periods, working identically on MySQL,
 * PostgreSQL, SQLite, and MariaDB.
 *
 * MySQL uses DATE_FORMAT, PostgreSQL uses to_char, SQLite uses strftime.
 * Keeping the bucketing SQL-side (rather than hydrating every row to
 * PHP and grouping with Carbon) preserves the indexes + LIMIT semantics
 * those analytics queries depend on.
 */
final class TimeBucket
{
    /**
     * Build a SELECT expression that buckets `$column` to the given
     * `$interval`, aliased as `period`.
     */
    public static function periodExpression( string $column, string $interval ): Expression
    {
        $driver = DB::connection()->getDriverName();

        $format = match ( $driver ) {
            'sqlite' => match ( $interval ) {
                'minute' => '%Y-%m-%d %H:%M',
                'day'    => '%Y-%m-%d',
                'month'  => '%Y-%m',
                default  => '%Y-%m-%d %H:00',
            },
            'pgsql' => match ( $interval ) {
                'minute' => 'YYYY-MM-DD HH24:MI',
                'day'    => 'YYYY-MM-DD',
                'month'  => 'YYYY-MM',
                default  => 'YYYY-MM-DD HH24:"00"',
            },
            // mysql, mariadb, default
            default => match ( $interval ) {
                'minute' => '%Y-%m-%d %H:%i',
                'day'    => '%Y-%m-%d',
                'month'  => '%Y-%m',
                default  => '%Y-%m-%d %H:00',
            },
        };

        return match ( $driver ) {
            'sqlite' => DB::raw( "strftime('{$format}', {$column}) as period" ),
            'pgsql'  => DB::raw( "to_char({$column}, '{$format}') as period" ),
            default  => DB::raw( "DATE_FORMAT({$column}, '{$format}') as period" ),
        };
    }
}
