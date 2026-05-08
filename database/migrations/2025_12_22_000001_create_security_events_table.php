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
        if (! Schema::hasTable('security_events')) {
            Schema::create('security_events', function (Blueprint $table): void {
                $table->id();
                $table->string('event_type', 50)->index();
                $table->string('event_name', 100)->index();
                $table->enum('severity', ['debug', 'info', 'warning', 'error', 'critical'])->default('info')->index();
                $table->unsignedBigInteger('user_id')->nullable()->index();
                $table->string('ip_address', 45)->index();
                $table->text('user_agent')->nullable();
                $table->string('url', 2048)->nullable();
                $table->string('method', 10)->nullable();
                $table->smallInteger('status_code')->nullable();
                $table->json('details')->nullable();
                $table->string('fingerprint', 64)->nullable()->index();
                $table->timestamp('created_at')->index();

                $table->index(['event_type', 'created_at']);
                $table->index(['user_id', 'event_type']);
                $table->index(['ip_address', 'event_type']);
            });
        }
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('security_events');
    }
};
