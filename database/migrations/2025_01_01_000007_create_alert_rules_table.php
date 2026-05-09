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
        Schema::create('alert_rules', function (Blueprint $table) {
            $table->id();
            $table->string('name', 100);
            $table->text('description')->nullable();
            $table->json('conditions');
            $table->enum('severity', ['info', 'low', 'medium', 'high', 'critical']);
            $table->json('channels');
            $table->json('recipients');
            $table->boolean('is_active')->default(true);
            $table->unsignedInteger('cooldown_minutes')->default(5);
            $table->json('escalation_policy')->nullable();
            $table->timestamps();
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('alert_rules');
    }
};
