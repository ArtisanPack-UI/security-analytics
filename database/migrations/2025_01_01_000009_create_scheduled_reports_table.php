<?php

declare( strict_types=1 );

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration {
    /**
     * Run the migrations.
     */
    public function up(): void
    {
        if ( ! Schema::hasTable( 'scheduled_reports' ) ) {
            Schema::create( 'scheduled_reports', function ( Blueprint $table ): void {
                $table->id();
                $table->string( 'report_type', 50 );
                $table->string( 'name', 150 );
                $table->string( 'cron_expression', 100 );
                $table->json( 'recipients' );
                $table->json( 'options' )->nullable();
                $table->string( 'format', 20 )->default( 'pdf' );
                $table->boolean( 'is_active' )->default( true );
                $table->timestamp( 'last_run_at' )->nullable();
                $table->timestamp( 'next_run_at' )->nullable();
                $table->timestamps();

                $table->index( 'report_type' );
                $table->index( ['is_active', 'next_run_at'], 'idx_scheduled_reports_due' );
            } );
        }
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists( 'scheduled_reports' );
    }
};
