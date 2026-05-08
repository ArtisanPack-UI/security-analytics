<div>
    <div class="flex justify-between items-center mb-6">
        <h1 class="text-2xl font-bold">Security Statistics</h1>
        <x-artisanpack-select
            :options="[
                7 => 'Last 7 days',
                14 => 'Last 14 days',
                30 => 'Last 30 days',
                90 => 'Last 90 days',
            ]"
            wire:model.live="days"
        />
    </div>

    <div class="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-6">
        {{-- Top IPs --}}
        <x-artisanpack-card>
            <x-slot:header>
                <h3 class="text-lg font-bold">Top IPs by Event Count</h3>
            </x-slot:header>
            @if(count($topIps) > 0)
                <x-artisanpack-table :headers="$ipHeaders" :rows="$topIps" />
            @else
                <p class="text-gray-500 p-4">No data available.</p>
            @endif
        </x-artisanpack-card>

        {{-- Top Users --}}
        <x-artisanpack-card>
            <x-slot:header>
                <h3 class="text-lg font-bold">Top Users by Event Count</h3>
            </x-slot:header>
            @if(count($topUsers) > 0)
                <x-artisanpack-table :headers="$userHeaders" :rows="$topUsers" />
            @else
                <p class="text-gray-500 p-4">No data available.</p>
            @endif
        </x-artisanpack-card>
    </div>

    {{-- Event Frequency Chart --}}
    <x-artisanpack-card>
        <x-slot:header>
            <h3 class="text-lg font-bold">Event Frequency Over Time</h3>
        </x-slot:header>
        <x-artisanpack-chart wire:model="eventFrequencyChart" class="h-64" />
    </x-artisanpack-card>

    {{-- Back to Dashboard --}}
    <div class="mt-6">
        <x-artisanpack-button href="{{ route('security.dashboard') }}" color="primary" outline>
            Back to Dashboard
        </x-artisanpack-button>
    </div>
</div>
