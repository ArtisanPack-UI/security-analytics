<?php

declare( strict_types=1 );

namespace ArtisanPackUI\SecurityAnalytics\Analytics\IncidentResponse;

use ArtisanPackUI\SecurityAnalytics\Analytics\IncidentResponse\Actions\BlockIpAction;
use ArtisanPackUI\SecurityAnalytics\Analytics\IncidentResponse\Actions\BlockUserAction;
use ArtisanPackUI\SecurityAnalytics\Analytics\IncidentResponse\Actions\LogEventAction;
use ArtisanPackUI\SecurityAnalytics\Analytics\IncidentResponse\Actions\NotifyAdminAction;
use ArtisanPackUI\SecurityAnalytics\Analytics\IncidentResponse\Actions\RequireTwoFactorAction;
use ArtisanPackUI\SecurityAnalytics\Analytics\IncidentResponse\Actions\RevokeSessionsAction;
use ArtisanPackUI\SecurityAnalytics\Analytics\IncidentResponse\Contracts\ResponseActionInterface;
use ArtisanPackUI\SecurityAnalytics\Models\Anomaly;
use ArtisanPackUI\SecurityAnalytics\Models\ResponsePlaybook;
use ArtisanPackUI\SecurityAnalytics\Models\SecurityIncident;
use Exception;
use RuntimeException;

class IncidentResponder
{
    /**
     * @var array<string, ResponseActionInterface>
     */
    protected array $actions = [];

    /**
     * @var array<string, mixed>
     */
    protected array $config;

    /**
     * @var array<string, array<string, mixed>>
     */
    protected array $pendingApprovals = [];

    /**
     * @param  array<string, mixed>  $config
     */
    public function __construct( array $config = [] )
    {
        $this->config = array_merge( $this->getDefaultConfig(), $config );
        $this->registerDefaultActions();
    }

    /**
     * Register a response action.
     */
    public function registerAction( ResponseActionInterface $action ): self
    {
        $this->actions[ $action->getName() ] = $action;

        return $this;
    }

    /**
     * Get a registered action.
     */
    public function getAction( string $name ): ?ResponseActionInterface
    {
        return $this->actions[ $name ] ?? null;
    }

    /**
     * Respond to an anomaly.
     *
     * @param  array<int, string>|null  $actions
     *
     * @return array<string, mixed>
     */
    public function respond( Anomaly $anomaly, ?array $actions = null ): array
    {
        if ( ! $this->config['enabled'] ) {
            return ['skipped' => true, 'reason' => 'Incident response is disabled'];
        }

        $incident = null;
        $results  = [];

        // Create incident if warranted
        if ( $this->shouldCreateIncident( $anomaly ) ) {
            $incident = $this->createIncident( $anomaly );
        }

        // Determine which actions to take
        $actionsToExecute = $actions ?? $this->determineActions( $anomaly );

        foreach ( $actionsToExecute as $actionName ) {
            $results[ $actionName ] = $this->executeAction( $actionName, $anomaly, $incident );
        }

        // Check for matching playbooks
        $playbookResults = $this->executeMatchingPlaybooks( $anomaly, $incident );
        $results         = array_merge( $results, $playbookResults );

        return [
            'anomaly_id'       => $anomaly->id,
            'incident_id'      => $incident?->id,
            'incident_number'  => $incident?->incident_number,
            'actions_executed' => $results,
        ];
    }

    /**
     * Execute a specific action.
     *
     * @param  array<string, mixed>  $config
     *
     * @return array<string, mixed>
     */
    public function executeAction(
        string $actionName,
        Anomaly $anomaly,
        ?SecurityIncident $incident = null,
        array $config = [],
    ): array {
        $action = $this->getAction( $actionName );

        if ( ! $action ) {
            return ['success' => false, 'message' => "Unknown action: {$actionName}"];
        }

        // Validate configuration
        $errors = $action->validate( $config );
        if ( ! empty( $errors ) ) {
            return ['success' => false, 'message' => 'Validation failed', 'errors' => $errors];
        }

        // Check if approval is required
        if ( $this->requiresApproval( $action ) ) {
            return $this->queueForApproval( $actionName, $anomaly, $incident, $config );
        }

        return $action->execute( $anomaly, $incident, $config );
    }

    /**
     * Execute a playbook.
     *
     * @return array<string, mixed>
     */
    public function executePlaybook(
        ResponsePlaybook $playbook,
        Anomaly $anomaly,
        ?SecurityIncident $incident = null,
    ): array {
        $results = [];

        foreach ( $playbook->getActionNames() as $actionName ) {
            $actionConfig = $playbook->getActionConfig( $actionName ) ?? [];

            // Check approval for playbook actions
            if ( $playbook->requires_approval ) {
                $results[ $actionName ] = $this->queueForApproval(
                    $actionName,
                    $anomaly,
                    $incident,
                    $actionConfig,
                    $playbook->id,
                );
            } else {
                $results[ $actionName ] = $this->executeAction( $actionName, $anomaly, $incident, $actionConfig );
            }
        }

        return [
            'playbook_id'    => $playbook->id,
            'playbook_name'  => $playbook->name,
            'action_results' => $results,
        ];
    }

    /**
     * Approve a pending action.
     *
     * @return array<string, mixed>
     */
    public function approve( string $approvalId, ?int $approvedBy = null ): array
    {
        $pending = cache()->get( "incident_response_approval:{$approvalId}" );

        if ( ! $pending ) {
            return ['success' => false, 'message' => 'Approval not found or expired'];
        }

        $anomaly  = Anomaly::find( $pending['anomaly_id'] );
        $incident = $pending['incident_id'] ? SecurityIncident::find( $pending['incident_id'] ) : null;

        if ( ! $anomaly ) {
            return ['success' => false, 'message' => 'Anomaly not found'];
        }

        $action = $this->getAction( $pending['action'] );
        if ( ! $action ) {
            return ['success' => false, 'message' => 'Action not found'];
        }

        // Execute the action
        $result = $action->execute( $anomaly, $incident, $pending['config'] ?? [] );

        // Clear the approval
        cache()->forget( "incident_response_approval:{$approvalId}" );
        unset( $this->pendingApprovals[ $approvalId ] );

        return array_merge( $result, [
            'approved_by' => $approvedBy,
            'approved_at' => now()->toIso8601String(),
        ] );
    }

    /**
     * Reject a pending action.
     *
     * @return array<string, mixed>
     */
    public function reject( string $approvalId, ?int $rejectedBy = null, ?string $reason = null ): array
    {
        $pending = cache()->get( "incident_response_approval:{$approvalId}" );

        if ( ! $pending ) {
            return ['success' => false, 'message' => 'Approval not found or expired'];
        }

        cache()->forget( "incident_response_approval:{$approvalId}" );
        unset( $this->pendingApprovals[ $approvalId ] );

        return [
            'success'     => true,
            'rejected'    => true,
            'rejected_by' => $rejectedBy,
            'rejected_at' => now()->toIso8601String(),
            'reason'      => $reason,
        ];
    }

    /**
     * Get pending approvals.
     *
     * @return array<string, array<string, mixed>>
     */
    public function getPendingApprovals(): array
    {
        return $this->pendingApprovals;
    }

    /**
     * Get default configuration.
     *
     * @return array<string, mixed>
     */
    protected function getDefaultConfig(): array
    {
        return [
            'enabled'                   => true,
            'require_approval_for'      => [],
            'auto_create_incident'      => true,
            'min_severity_for_incident' => 'medium',
        ];
    }

    /**
     * Register default actions.
     */
    protected function registerDefaultActions(): void
    {
        $this->registerAction( new BlockIpAction );
        $this->registerAction( new BlockUserAction );
        $this->registerAction( new NotifyAdminAction );
        $this->registerAction( new LogEventAction );
        $this->registerAction( new RevokeSessionsAction );
        $this->registerAction( new RequireTwoFactorAction );
    }

    /**
     * Determine which actions to take based on anomaly.
     *
     * @return array<int, string>
     */
    protected function determineActions( Anomaly $anomaly ): array
    {
        $actions = ['log_event'];

        // Add notification for medium+ severity
        if ( in_array( $anomaly->severity, ['medium', 'high', 'critical'], true ) ) {
            $actions[] = 'notify_admin';
        }

        // Add blocking for critical/high authentication anomalies
        if (
            Anomaly::CATEGORY_AUTHENTICATION === $anomaly->category
            && in_array( $anomaly->severity, ['high', 'critical'], true )
        ) {
            if ( isset( $anomaly->metadata['ip'] ) ) {
                $actions[] = 'block_ip';
            }
        }

        // Add session revocation for critical behavioral anomalies
        if (
            Anomaly::CATEGORY_BEHAVIORAL === $anomaly->category
            && 'critical' === $anomaly->severity
            && $anomaly->user_id
        ) {
            $actions[] = 'revoke_sessions';
        }

        return $actions;
    }

    /**
     * Check if an incident should be created.
     */
    protected function shouldCreateIncident( Anomaly $anomaly ): bool
    {
        if ( ! $this->config['auto_create_incident'] ) {
            return false;
        }

        $severityOrder = ['info' => 0, 'low' => 1, 'medium' => 2, 'high' => 3, 'critical' => 4];
        $minSeverity   = $this->config['min_severity_for_incident'];

        return ( $severityOrder[ $anomaly->severity ] ?? 0 ) >= ( $severityOrder[ $minSeverity ] ?? 2 );
    }

    /**
     * Create a security incident from an anomaly.
     */
    protected function createIncident( Anomaly $anomaly ): SecurityIncident
    {
        $incident = SecurityIncident::create( [
            'title'             => "Security Incident: {$anomaly->category}",
            'description'       => $anomaly->description,
            'severity'          => $anomaly->severity,
            'status'            => SecurityIncident::STATUS_OPEN,
            'category'          => $anomaly->category,
            'source_anomaly_id' => $anomaly->id,
            'opened_at'         => now(),
        ] );

        // Add affected entities
        if ( $anomaly->user_id ) {
            $incident->addAffectedUser( $anomaly->user_id );
        }

        if ( isset( $anomaly->metadata['ip'] ) ) {
            $incident->addAffectedIp( $anomaly->metadata['ip'] );
        }

        return $incident;
    }

    /**
     * Execute matching playbooks for an anomaly.
     *
     * @return array<string, array<string, mixed>>
     */
    protected function executeMatchingPlaybooks( Anomaly $anomaly, ?SecurityIncident $incident ): array
    {
        $results = [];

        $playbooks = ResponsePlaybook::findMatchingPlaybooks( $anomaly );

        foreach ( $playbooks as $playbook ) {
            if ( $playbook->isOnCooldown( $this->getPlaybookContextKey( $anomaly ) ) ) {
                continue;
            }

            $playbookResults                         = $this->executePlaybook( $playbook, $anomaly, $incident );
            $results[ "playbook:{$playbook->name}" ] = $playbookResults;

            $playbook->startCooldown( $this->getPlaybookContextKey( $anomaly ) );
        }

        return $results;
    }

    /**
     * Check if an action requires approval.
     */
    protected function requiresApproval( ResponseActionInterface $action ): bool
    {
        // Check if action inherently requires approval
        if ( $action->requiresApproval() ) {
            return true;
        }

        // Check configuration
        $requireApprovalFor = $this->config['require_approval_for'] ?? [];

        return in_array( $action->getName(), $requireApprovalFor, true );
    }

    /**
     * Queue an action for approval.
     *
     * @param  array<string, mixed>  $config
     *
     * @return array<string, mixed>
     */
    protected function queueForApproval(
        string $actionName,
        Anomaly $anomaly,
        ?SecurityIncident $incident,
        array $config = [],
        ?int $playbookId = null,
    ): array {
        // Use cryptographically secure random token for approval ID
        try {
            $approvalId = 'approval_' . bin2hex( random_bytes( 16 ) );
        } catch ( Exception $e ) {
            // Fallback if random_bytes fails (should be rare)
            throw new RuntimeException( 'Unable to generate secure approval token: ' . $e->getMessage() );
        }

        $this->pendingApprovals[ $approvalId ] = [
            'action'      => $actionName,
            'anomaly_id'  => $anomaly->id,
            'incident_id' => $incident?->id,
            'playbook_id' => $playbookId,
            'config'      => $config,
            'queued_at'   => now()->toIso8601String(),
        ];

        // Store in cache for persistence
        cache()->put(
            "incident_response_approval:{$approvalId}",
            $this->pendingApprovals[ $approvalId ],
            now()->addHours( 24 ),
        );

        return [
            'success'          => false,
            'pending_approval' => true,
            'approval_id'      => $approvalId,
            'message'          => "Action '{$actionName}' requires approval",
        ];
    }

    /**
     * Get playbook context key for cooldown.
     */
    protected function getPlaybookContextKey( Anomaly $anomaly ): string
    {
        return "{$anomaly->category}:{$anomaly->user_id}";
    }
}
