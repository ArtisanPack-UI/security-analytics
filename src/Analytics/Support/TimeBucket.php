<?php

declare( strict_types=1 );

namespace ArtisanPackUI\SecurityAnalytics\Analytics\Support;

use Illuminate\Database\Query\Expression;
use Illuminate\Support\Facades\DB;
use InvalidArgumentException;

/**
 * Cross-database time-bucket SQL helper.
 *
 * Returns a `SELECT` expression that buckets a timestamp column into
 * minute / hour / day / month periods, working identically on MySQL,
 * MariaDB, PostgreSQL, and SQLite.
 *
 * MySQL/MariaDB use DATE_FORMAT, PostgreSQL uses to_char, SQLite uses
 * strftime. Keeping the bucketing SQL-side (rather than hydrating every
 * row to PHP and grouping with Carbon) preserves the indexes + LIMIT
 * semantics those analytics queries depend on.
 */
final class TimeBucket
{
    /**
     * Build a SELECT expression that buckets `$column` to the given
     * `$interval`, aliased as `period`.
     *
     * @throws InvalidArgumentException on an invalid column name, an
     *   unsupported interval, or an unsupported database driver.
     */
    public static function periodExpression( string $column, string $interval ): Expression
    {
        // Reject anything that isn't a plain identifier (optionally
        // dot-qualified) — the value gets interpolated into a raw query
        // string, so an unsanitized caller-supplied column would be a
        // SQL-injection vector.
        if ( ! preg_match( '/^[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*$/', $column ) ) {
            throw new InvalidArgumentException( "Invalid time bucket column [{$column}]." );
        }

        $connection    = DB::connection();
        $driver        = $connection->getDriverName();
        $wrappedColumn = $connection->getQueryGrammar()->wrap( $column );

        $format = match ( $driver ) {
            'sqlite' => match ( $interval ) {
                'minute' => '%Y-%m-%d %H:%M',
                'hour'   => '%Y-%m-%d %H:00',
                'day'    => '%Y-%m-%d',
                'month'  => '%Y-%m',
                default  => throw new InvalidArgumentException( "Unsupported interval [{$interval}]." ),
            },
            'pgsql' => match ( $interval ) {
                'minute' => 'YYYY-MM-DD HH24:MI',
                'hour'   => 'YYYY-MM-DD HH24:"00"',
                'day'    => 'YYYY-MM-DD',
                'month'  => 'YYYY-MM',
                default  => throw new InvalidArgumentException( "Unsupported interval [{$interval}]." ),
            },
            'mysql', 'mariadb' => match ( $interval ) {
                'minute' => '%Y-%m-%d %H:%i',
                'hour'   => '%Y-%m-%d %H:00',
                'day'    => '%Y-%m-%d',
                'month'  => '%Y-%m',
                default  => throw new InvalidArgumentException( "Unsupported interval [{$interval}]." ),
            },
            default => throw new InvalidArgumentException( "Unsupported database driver [{$driver}]." ),
        };

        return match ( $driver ) {
            'sqlite'           => DB::raw( "strftime('{$format}', {$wrappedColumn}) as period" ),
            'pgsql'            => DB::raw( "to_char({$wrappedColumn}, '{$format}') as period" ),
            'mysql', 'mariadb' => DB::raw( "DATE_FORMAT({$wrappedColumn}, '{$format}') as period" ),
        };
    }
}
