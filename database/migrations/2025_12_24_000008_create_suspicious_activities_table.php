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
        $userModel = config('artisanpack.security-analytics.user_model')
            ?? config('artisanpack.security.user_model')
            ?? config('auth.providers.users.model', 'App\\Models\\User');
        $userTable = (new $userModel())->getTable();


        Schema::create('suspicious_activities', function (Blueprint $table) use ($userTable) {
            $table->id();
            $table->foreignId('user_id')->nullable()->constrained($userTable)->nullOnDelete();
            $table->string('session_id', 255)->nullable();
            $table->string('type', 50);
            $table->enum('severity', ['low', 'medium', 'high', 'critical'])->default('medium');
            $table->decimal('risk_score', 5, 2)->default(0);
            $table->string('ip_address', 45);
            $table->json('location')->nullable();
            $table->string('device_fingerprint', 64)->nullable();
            $table->json('details');
            $table->enum('action_taken', ['none', 'captcha', 'step_up', 'block', 'lockout', 'notify'])->default('none');
            $table->boolean('resolved')->default(false);
            $table->timestamp('resolved_at')->nullable();
            $table->foreignId('resolved_by')->nullable()->constrained($userTable)->nullOnDelete();
            $table->timestamp('created_at')->nullable();

            $table->index(['user_id', 'type'], 'idx_suspicious_user_type');
            $table->index('severity', 'idx_suspicious_severity');
            $table->index(['resolved', 'created_at'], 'idx_suspicious_unresolved');
            $table->index('ip_address', 'idx_suspicious_ip');
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('suspicious_activities');
    }
};
