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
        Schema::create('alert_history', function (Blueprint $table) {
            $table->id();
            $table->unsignedBigInteger('rule_id')->nullable();
            $table->unsignedBigInteger('anomaly_id')->nullable();
            $table->unsignedBigInteger('incident_id')->nullable();
            $table->enum('severity', ['info', 'low', 'medium', 'high', 'critical']);
            $table->string('channel', 50);
            $table->string('recipient', 255)->nullable();
            $table->enum('status', ['pending', 'sent', 'failed', 'acknowledged'])->default('pending');
            $table->text('message')->nullable();
            $table->timestamp('sent_at')->nullable();
            $table->timestamp('acknowledged_at')->nullable();
            $table->unsignedBigInteger('acknowledged_by')->nullable();
            $table->text('error_message')->nullable();
            $table->timestamps();

            $table->index('status', 'idx_status');
            $table->index(['rule_id', 'created_at'], 'idx_rule_created');
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('alert_history');
    }
};
