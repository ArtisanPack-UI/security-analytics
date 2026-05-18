---
title: Custom Incident Response Actions
---

# Custom Incident Response Actions

`ResponseActionInterface`:

```php
interface ResponseActionInterface
{
    public function execute( array $context ): ActionResult;
    public function getName(): string;
}
```

`$context` is the cumulative context built up across a playbook's actions. Each action can read from and write to it — earlier actions' side effects are visible to later ones.

Subclass `AbstractAction` for the common boilerplate (logging, error capture, context merging).

## Example: webhook-to-external-system action

```php
namespace App\SecurityAnalytics\Actions;

use ArtisanPackUI\SecurityAnalytics\Analytics\IncidentResponse\Actions\AbstractAction;
use ArtisanPackUI\SecurityAnalytics\Analytics\IncidentResponse\ActionResult;
use Illuminate\Support\Facades\Http;

class FreezeStripeAccountAction extends AbstractAction
{
    public function execute( array $context ): ActionResult
    {
        $user = $context['user'] ?? null;

        if ( ! $user || ! $user->stripe_customer_id ) {
            return ActionResult::failure( 'No Stripe customer to freeze.' );
        }

        $response = Http::withToken( config('services.stripe.secret') )
            ->post( "https://api.stripe.com/v1/customers/{$user->stripe_customer_id}", [
                'metadata' => ['frozen_by_security_analytics' => now()->toIso8601String()],
            ] );

        return $response->successful()
            ? ActionResult::success( "Stripe account {$user->stripe_customer_id} frozen." )
            : ActionResult::failure( 'Stripe API rejected the freeze request.' );
    }

    public function getName(): string
    {
        return 'freeze_stripe_account';
    }
}
```

## Registering

```php
use ArtisanPackUI\SecurityAnalytics\Analytics\IncidentResponse\IncidentResponder;
use App\SecurityAnalytics\Actions\FreezeStripeAccountAction;

$this->app->afterResolving( IncidentResponder::class, function ( IncidentResponder $responder ): void {
    $responder->extend( new FreezeStripeAccountAction() );
} );
```

Reference your action by name in playbook definitions:

```php
'high_value_account_compromise' => [
    'trigger' => ['detector' => 'credential_stuffing', 'severity' => 'critical'],
    'actions' => [
        ['action' => 'lock_account'],
        ['action' => 'freeze_stripe_account'],
        ['action' => 'notify_admin', 'channel' => 'pagerduty'],
    ],
],
```

## Conventions

- **Idempotent.** Actions may run multiple times if a playbook retries. Make freeze / block operations safe to repeat.
- **`ActionResult::success()` vs `failure()`.** Use success for "the action ran and did what it was supposed to do" — including no-op cases where the state was already correct. Use failure for "I tried but couldn't" (API errors, missing context, business-rule rejection).
- **Read carefully from context.** Don't assume `$context['user']` exists — playbooks differ in what they pass.
- **Write meaningfully to context.** Later actions in the same playbook see your additions. Use them to chain ("`block_ip` writes `blocked_ip` so `log_event` can include it").
