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
        Schema::create('security_incidents', function (Blueprint $table) {
            $table->id();
            $table->string('incident_number', 20)->unique();
            $table->string('title', 255);
            $table->text('description')->nullable();
            $table->enum('severity', ['info', 'low', 'medium', 'high', 'critical']);
            $table->enum('status', ['open', 'investigating', 'contained', 'resolved', 'closed'])->default('open');
            $table->string('category', 50)->nullable();
            $table->unsignedBigInteger('source_anomaly_id')->nullable();
            $table->json('affected_users')->nullable();
            $table->json('affected_ips')->nullable();
            $table->json('actions_taken')->nullable();
            $table->unsignedBigInteger('assigned_to')->nullable();
            $table->timestamp('opened_at');
            $table->timestamp('contained_at')->nullable();
            $table->timestamp('resolved_at')->nullable();
            $table->timestamp('closed_at')->nullable();
            $table->text('root_cause')->nullable();
            $table->text('lessons_learned')->nullable();
            $table->timestamps();

            $table->index(['status', 'severity'], 'idx_status_severity');
            $table->index('opened_at', 'idx_opened');
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('security_incidents');
    }
};
