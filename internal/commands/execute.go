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
	debug  bool
}

// NewExecuteCommand creates a new execute command
func NewExecuteCommand(db DatabaseInterface, client ClientInterface, orgID string, debug bool) *ExecuteCommand {
	return &ExecuteCommand{
		db:     db,
		client: client,
		orgID:  orgID,
		debug:  debug,
	}
}

// debugLog logs a message only when debug mode is enabled
func (c *ExecuteCommand) debugLog(format string, args ...interface{}) {
	if c.debug {
		log.Printf("Debug: "+format, args...)
	}
}

// Execute runs the execute command
func (c *ExecuteCommand) Execute() error {
	log.Printf("Starting policy creation for organization: %s", c.orgID)

	// Check if the policies table exists
	tableCheckResult, err := c.db.Query("SELECT name FROM sqlite_master WHERE type='table' AND name='policies'")
	if err != nil {
		c.debugLog("Error checking tables: %v", err)
	} else {
		tableRows, ok := tableCheckResult.(interface {
			Next() bool
			Close() error
		})
		if ok {
			tableExists := tableRows.Next()
			tableRows.Close()
			if tableExists {
				c.debugLog("'policies' table exists in database")
			} else {
				c.debugLog("'policies' table DOES NOT exist in database!")
			}
		}
	}

	// Check table structure
	if c.debug {
		tableInfoResult, err := c.db.Query("PRAGMA table_info(policies)")
		if err != nil {
			c.debugLog("Error getting table info: %v", err)
		} else {
			tableInfoRows, ok := tableInfoResult.(interface {
				Next() bool
				Scan(dest ...interface{}) error
				Close() error
			})
			if ok {
				c.debugLog("Columns in 'policies' table:")
				for tableInfoRows.Next() {
					var cid int
					var name, type_ string
					var notnull, dflt_value, pk interface{}
					if err := tableInfoRows.Scan(&cid, &name, &type_, &notnull, &dflt_value, &pk); err != nil {
						c.debugLog("Error scanning column info: %v", err)
					} else {
						c.debugLog("  Column %d: %s (%s)", cid, name, type_)
					}
				}
				tableInfoRows.Close()
			}
		}
	}

	// Diagnostic query to check for any policies
	diagResult := c.db.QueryRow(`SELECT COUNT(*) FROM policies WHERE org_id = ?`, c.orgID)
	var totalCount int
	if err := diagResult.Scan(&totalCount); err != nil {
		log.Printf("Warning: Failed to run diagnostic query: %v", err)
	} else {
		c.debugLog("Found %d total policies for org_id=%s", totalCount, c.orgID)
	}

	// Also check for any policies without external_id
	diagNullResult := c.db.QueryRow(`SELECT COUNT(*) FROM policies WHERE org_id = ? AND (external_id IS NULL OR external_id = '')`, c.orgID)
	var nullIdCount int
	if err := diagNullResult.Scan(&nullIdCount); err != nil {
		log.Printf("Warning: Failed to run null external_id diagnostic query: %v", err)
	} else {
		c.debugLog("Found %d policies with empty external_id for org_id=%s", nullIdCount, c.orgID)
	}

	// Dump all policies for debugging
	if c.debug {
		allPoliciesResult, err := c.db.Query("SELECT * FROM policies")
		if err != nil {
			c.debugLog("Error querying all policies: %v", err)
		} else {
			allPoliciesRows, ok := allPoliciesResult.(interface {
				Next() bool
				Scan(dest ...interface{}) error
				Close() error
			})
			if ok {
				defer allPoliciesRows.Close()
				c.debugLog("All policies in database:")
				policyCount := 0
				for allPoliciesRows.Next() {
					policy := &database.Policy{}
					if err := allPoliciesRows.Scan(
						&policy.InternalID, &policy.OrgID, &policy.AssetKey, &policy.PolicyType,
						&policy.Reason, &policy.ExpiresAt, &policy.SourceIgnores, &policy.ExternalID,
						&policy.CreatedAt,
					); err != nil {
						c.debugLog("Error scanning policy: %v", err)
					} else {
						c.debugLog("Policy %d: InternalID=%s, OrgID=%s, AssetKey=%s, ExternalID=%v",
							policyCount+1, policy.InternalID, policy.OrgID, policy.AssetKey, policy.ExternalID)
						policyCount++
					}
				}
				if policyCount == 0 {
					c.debugLog("No policies found in the database at all!")
				} else {
					c.debugLog("Total policies found: %d", policyCount)
				}
			}
		}
	}

	// Get all planned policies that haven't been created yet
	queryStr := "SELECT * FROM policies WHERE org_id = ? AND (external_id IS NULL OR external_id = '')"
	c.debugLog("Executing query: %s with org_id=%s", queryStr, c.orgID)
	policyResult, err := c.db.Query(queryStr, c.orgID)
	if err != nil {
		c.debugLog("Error executing query: %v", err)
		return fmt.Errorf("failed to get planned policies: %w", err)
	}

	// Log the query parameters for debugging
	c.debugLog("Querying for policies with org_id=%s and external_id IS NULL", c.orgID)

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

		c.debugLog("Found policy: InternalID=%s, OrgID=%s, AssetKey=%s, ExternalID=%v",
			policy.InternalID, policy.OrgID, policy.AssetKey, policy.ExternalID)

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
