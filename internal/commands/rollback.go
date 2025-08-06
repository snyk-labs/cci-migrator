package commands

import (
	"encoding/json"
	"fmt"
	"log"

	"github.com/z4ce/cci-migrator/internal/snyk"
)

// RollbackCommand handles rollback operations
// It deletes all created Snyk policies and recreates ignores via the v1 API.
type RollbackCommand struct {
	db     DatabaseInterface
	client ClientInterface
	orgID  string
	debug  bool
}

// NewRollbackCommand creates a new rollback command
func NewRollbackCommand(db DatabaseInterface, client ClientInterface, orgID string, debug bool) *RollbackCommand {
	return &RollbackCommand{
		db:     db,
		client: client,
		orgID:  orgID,
		debug:  debug,
	}
}

// Execute runs the rollback command
func (c *RollbackCommand) Execute() error {
	log.Printf("Starting rollback for organization: %s", c.orgID)

	// Delete all created policies via API
	policies, err := c.db.GetPoliciesByOrgID(c.orgID)
	if err != nil {
		return fmt.Errorf("failed to get policies: %w", err)
	}
	for _, policy := range policies {
		if policy.ExternalID != "" {
			log.Printf("Deleting policy: %s", policy.ExternalID)
			if err := c.client.DeletePolicy(c.orgID, policy.ExternalID); err != nil {
				log.Printf("Warning: failed to delete policy %s: %v", policy.ExternalID, err)
			}
		}
	}

	// Recreate ignores via v1 ignore API
	ignores, err := c.db.GetIgnoresByOrgID(c.orgID)
	if err != nil {
		return fmt.Errorf("failed to get ignores: %w", err)
	}
	for _, ignoreRow := range ignores {
		var original snyk.Ignore
		if err := json.Unmarshal([]byte(ignoreRow.OriginalState), &original); err != nil {
			log.Printf("Warning: failed to parse original state for ignore %s: %v", ignoreRow.ID, err)
			continue
		}
		log.Printf("Recreating ignore: %s on project %s", ignoreRow.ID, ignoreRow.ProjectID)
		if err := c.client.CreateIgnore(c.orgID, ignoreRow.ProjectID, original); err != nil {
			log.Printf("Warning: failed to recreate ignore %s: %v", ignoreRow.ID, err)
		}
	}

	log.Println("Rollback completed successfully.")
	return nil
}
