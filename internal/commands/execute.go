package commands

import (
	"fmt"
	"log"
	"time"

	"github.com/z4ce/cci-migrator/internal/database"
	"github.com/z4ce/cci-migrator/internal/snyk"
)

// ExecuteCommand handles the execution phase of the migration
type ExecuteCommand struct {
	db     DatabaseInterface
	client ClientInterface
	orgID  string
}

// NewExecuteCommand creates a new execute command
func NewExecuteCommand(db DatabaseInterface, client ClientInterface, orgID string) *ExecuteCommand {
	return &ExecuteCommand{
		db:     db,
		client: client,
		orgID:  orgID,
	}
}

// Execute runs the execute command
func (c *ExecuteCommand) Execute() error {
	log.Printf("Starting policy creation for organization: %s", c.orgID)

	// Get all planned policies that haven't been created yet
	policyResult, err := c.db.Query(`
		SELECT * FROM policies 
		WHERE org_id = ? AND external_id IS NULL
	`, c.orgID)
	if err != nil {
		return fmt.Errorf("failed to get planned policies: %w", err)
	}

	// Type assertion for the rows
	rows, ok := policyResult.(interface {
		Next() bool
		Scan(dest ...interface{}) error
		Close() error
	})
	if !ok {
		return fmt.Errorf("unexpected query result type")
	}
	defer rows.Close()

	var totalPolicies, createdPolicies int
	var failedPolicies int

	for rows.Next() {
		policy := &database.Policy{}
		err := rows.Scan(
			&policy.InternalID, &policy.OrgID, &policy.AssetKey, &policy.PolicyType,
			&policy.Reason, &policy.ExpiresAt, &policy.SourceIgnores, &policy.ExternalID,
			&policy.CreatedAt,
		)
		if err != nil {
			return fmt.Errorf("failed to scan policy: %w", err)
		}

		totalPolicies++
		log.Printf("Creating policy %d for asset key %s", totalPolicies, policy.AssetKey)

		// Create policy attributes
		policyAttributes := snyk.CreatePolicyAttributes{
			Name:       fmt.Sprintf("Migrated policy for %s", policy.AssetKey),
			ActionType: "ignore",
			Action: snyk.Action{
				Data: snyk.ActionData{
					IgnoreType: policy.PolicyType,
					Reason:     policy.Reason,
					Expires:    policy.ExpiresAt,
				},
			},
			ConditionsGroup: snyk.ConditionsGroup{
				LogicalOperator: "and",
				Conditions: []snyk.Condition{
					{
						Field:    "assetKey",
						Operator: "equals",
						Value:    policy.AssetKey,
					},
				},
			},
		}

		// Create the policy using the Policy API
		createdPolicy, err := c.client.CreatePolicy(
			c.orgID,
			policyAttributes,
			nil, // No additional metadata
		)
		if err != nil {
			log.Printf("Warning: failed to create policy for asset key %s: %v", policy.AssetKey, err)
			failedPolicies++
			continue
		}

		externalID := createdPolicy.ID

		// Update policy with external ID and creation time
		now := time.Now()
		_, err = c.db.Exec(`
			UPDATE policies
			SET external_id = ?, created_at = ?
			WHERE internal_id = ?
		`, externalID, now, policy.InternalID)
		if err != nil {
			log.Printf("Warning: failed to update policy with external ID: %v", err)
			continue
		}

		// Update all ignores linked to this policy to mark them as migrated
		_, err = c.db.Exec(`
			UPDATE ignores
			SET migrated_at = ?, policy_id = ?
			WHERE internal_policy_id = ?
		`, now, externalID, policy.InternalID)
		if err != nil {
			log.Printf("Warning: failed to update ignores as migrated: %v", err)
			continue
		}

		createdPolicies++
		log.Printf("Successfully created policy for asset key %s with external ID %s", policy.AssetKey, externalID)
	}

	log.Printf("Execution summary:")
	log.Printf("  Total policies planned: %d", totalPolicies)
	log.Printf("  Policies successfully created: %d", createdPolicies)
	log.Printf("  Policies failed to create: %d", failedPolicies)

	// Count migrated ignores
	var migratedIgnores int
	countResult := c.db.QueryRow(`
		SELECT COUNT(*) FROM ignores
		WHERE org_id = ? AND migrated_at IS NOT NULL
	`, c.orgID)

	err = countResult.Scan(&migratedIgnores)
	if err != nil {
		log.Printf("Warning: failed to count migrated ignores: %v", err)
	} else {
		log.Printf("  Total ignores migrated: %d", migratedIgnores)
	}

	return nil
}
