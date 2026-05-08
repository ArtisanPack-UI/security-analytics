<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    /**
     * Run the migrations.
     */
    public function up(): void
    {
        Schema::create('anomalies', function (Blueprint $table) {
            $table->id();
            $table->string('detector', 100);
            $table->string('category', 50);
            $table->enum('severity', ['info', 'low', 'medium', 'high', 'critical']);
            $table->decimal('score', 5, 2);
            $table->text('description');
            $table->unsignedBigInteger('event_id')->nullable();
            $table->unsignedBigInteger('user_id')->nullable();
            $table->string('ip_address', 45)->nullable();
            $table->json('metadata')->nullable();
            $table->timestamp('detected_at')->nullable();
            $table->timestamp('resolved_at')->nullable();
            $table->unsignedBigInteger('resolved_by')->nullable();
            $table->text('resolution_notes')->nullable();
            $table->timestamps();

            $table->index(['severity', 'detected_at'], 'idx_severity_detected');
            $table->index('user_id', 'idx_user');
            $table->index('detector', 'idx_detector');
            $table->index(['resolved_at', 'severity'], 'idx_unresolved');
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('anomalies');
    }
};
