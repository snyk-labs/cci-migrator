package commands

import (
	"fmt"
	"log"
	"strings"
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

	// Add timeout handling for the entire operation
	executionTimeout := time.NewTimer(10 * time.Minute)
	done := make(chan bool)

	// Launch the execution in a goroutine
	go func() {
		defer func() { done <- true }()

		log.Printf("Getting planned policies...")
		// Get all planned policies that haven't been created yet
		queryStr := "SELECT * FROM policies WHERE org_id = ? AND (external_id IS NULL OR external_id = '')"
		c.debugLog("Executing query: %s with org_id=%s", queryStr, c.orgID)
		policyResult, err := c.db.Query(queryStr, c.orgID)
		if err != nil {
			c.debugLog("Error executing query: %v", err)
			log.Printf("Failed to get planned policies: %v", err)
			return
		}

		// Type assertion for the rows
		rows, ok := policyResult.(interface {
			Next() bool
			Scan(dest ...interface{}) error
			Close() error
		})
		if !ok {
			log.Printf("Unexpected query result type")
			return
		}

		// Collect all policies in memory first to avoid holding open cursor during updates
		var policies []*database.Policy
		for rows.Next() {
			policy := &database.Policy{}
			err := rows.Scan(
				&policy.InternalID, &policy.OrgID, &policy.AssetKey, &policy.PolicyType,
				&policy.Reason, &policy.ExpiresAt, &policy.SourceIgnores, &policy.ExternalID,
				&policy.CreatedAt,
			)
			if err != nil {
				log.Printf("Failed to scan policy: %v", err)
				rows.Close()
				return
			}
			policies = append(policies, policy)
		}
		// Close cursor before starting updates
		rows.Close()

		var totalPolicies, createdPolicies int
		var failedPolicies int

		totalPolicies = len(policies)
		log.Printf("Processing %d policies...", totalPolicies)

		// Now process all policies
		for i, policy := range policies {
			c.debugLog("Processing policy: InternalID=%s, OrgID=%s, AssetKey=%s, ExternalID=%v",
				policy.InternalID, policy.OrgID, policy.AssetKey, policy.ExternalID)

			log.Printf("Creating policy %d of %d for asset key %s", i+1, totalPolicies, policy.AssetKey)

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
							Field:    "snyk/asset/finding/v1",
							Operator: "includes",
							Value:    policy.AssetKey,
						},
					},
				},
			}

			log.Printf("Calling API to create policy for %s...", policy.AssetKey)
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
			now := time.Now()

			// Retry transaction a few times if it fails with a lock error
			var transactionError error
			for retryCount := 0; retryCount < 3; retryCount++ {
				if retryCount > 0 {
					log.Printf("Retrying transaction (attempt %d/3)...", retryCount+1)
					// Add a small delay before retrying to allow locks to clear
					time.Sleep(time.Duration(retryCount) * 500 * time.Millisecond)
				}

				// Begin a transaction for database updates
				txResult, err := c.db.Begin()
				if err != nil {
					log.Printf("Warning: failed to begin transaction: %v", err)
					transactionError = err
					continue // Try again
				}

				tx, ok := txResult.(interface {
					Exec(query string, args ...interface{}) (interface{}, error)
					Commit() error
					Rollback() error
				})
				if !ok {
					log.Printf("Warning: unexpected transaction type")
					transactionError = fmt.Errorf("unexpected transaction type")
					continue // Try again
				}

				// Ensure transaction gets rolled back if not explicitly committed
				var txError error
				defer func() {
					// Only rollback if not already committed and there was an error
					if txError != nil {
						if err := tx.Rollback(); err != nil {
							log.Printf("Warning: failed to rollback transaction: %v", err)
						}
					}
				}()

				// Update policy with external ID and creation time within the transaction
				_, err = tx.Exec(`
					UPDATE policies
					SET external_id = ?, created_at = ?
					WHERE internal_id = ?
				`, externalID, now, policy.InternalID)
				if err != nil {
					log.Printf("Warning: failed to update policy with external ID: %v", err)
					txError = err
					// If this is a locking error, try again
					if strings.Contains(err.Error(), "locked") {
						continue
					}
					failedPolicies++
					break // Permanent error, don't retry
				}

				// Update all ignores linked to this policy to mark them as migrated within the transaction
				_, err = tx.Exec(`
					UPDATE ignores
					SET migrated_at = ?, policy_id = ?
					WHERE internal_policy_id = ?
				`, now, externalID, policy.InternalID)
				if err != nil {
					log.Printf("Warning: failed to update ignores as migrated: %v", err)
					txError = err
					// If this is a locking error, try again
					if strings.Contains(err.Error(), "locked") {
						continue
					}
					failedPolicies++
					break // Permanent error, don't retry
				}

				// Commit the transaction
				if err := tx.Commit(); err != nil {
					log.Printf("Warning: failed to commit transaction: %v", err)
					txError = err
					// If this is a locking error, try again
					if strings.Contains(err.Error(), "locked") {
						continue
					}
					failedPolicies++
					break // Permanent error, don't retry
				}

				// Transaction was successful
				txError = nil
				transactionError = nil
				break // Exit retry loop on success
			}

			// Check if all retries failed
			if transactionError != nil {
				log.Printf("Warning: all transaction attempts failed for policy %s: %v", policy.InternalID, transactionError)
				failedPolicies++
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
	}()

	// Wait for either execution to complete or timeout
	select {
	case <-done:
		log.Printf("Execution completed successfully")
		return nil
	case <-executionTimeout.C:
		log.Printf("ERROR: Execution timed out after 10 minutes")
		return fmt.Errorf("execution timed out")
	}
}
