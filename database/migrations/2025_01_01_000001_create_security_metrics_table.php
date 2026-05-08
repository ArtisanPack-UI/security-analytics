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
        Schema::create('security_metrics', function (Blueprint $table) {
            $table->id();
            $table->string('category', 50);
            $table->string('metric_name', 100);
            $table->enum('metric_type', ['counter', 'gauge', 'timing', 'histogram']);
            $table->decimal('value', 20, 6);
            $table->json('tags')->nullable();
            $table->timestamp('recorded_at');
            $table->timestamps();

            $table->index(['category', 'metric_name'], 'idx_category_metric');
            $table->index('recorded_at', 'idx_recorded_at');
            $table->index(['category', 'recorded_at'], 'idx_category_recorded');
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('security_metrics');
    }
};
