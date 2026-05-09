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
        Schema::create('threat_indicators', function (Blueprint $table) {
            $table->id();
            $table->enum('type', ['ip', 'domain', 'url', 'hash', 'email']);
            $table->string('value', 500);
            $table->string('source', 100);
            $table->string('threat_type', 50)->nullable();
            $table->enum('severity', ['info', 'low', 'medium', 'high', 'critical']);
            $table->unsignedTinyInteger('confidence');
            $table->timestamp('first_seen_at');
            $table->timestamp('last_seen_at');
            $table->timestamp('expires_at')->nullable();
            $table->json('metadata')->nullable();
            $table->timestamps();

            $table->unique(['type', 'value'], 'idx_type_value');
            $table->index('expires_at', 'idx_expires');
            $table->index('severity', 'idx_severity');
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('threat_indicators');
    }
};
