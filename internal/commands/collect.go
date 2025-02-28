package commands

import (
	"encoding/json"
	"fmt"
	"log"
	"time"

	"github.com/z4ce/cci-migrator/internal/database"
	"github.com/z4ce/cci-migrator/internal/snyk"
)

const (
	collectionVersion = "1.0.0"
	apiVersion       = "v1"
)

// CollectCommand handles the collection of ignores
type CollectCommand struct {
	db     *database.DB
	client *snyk.Client
	orgID  string
}

// NewCollectCommand creates a new collect command
func NewCollectCommand(db *database.DB, client *snyk.Client, orgID string) *CollectCommand {
	return &CollectCommand{
		db:     db,
		client: client,
		orgID:  orgID,
	}
}

// Execute runs the collect command
func (c *CollectCommand) Execute() error {
	log.Printf("Starting collection for organization: %s", c.orgID)

	projects, err := c.client.GetProjects(c.orgID)
	if err != nil {
		return fmt.Errorf("failed to get projects: %w", err)
	}

	log.Printf("Found %d projects to process", len(projects))

	for _, project := range projects {
		log.Printf("Processing project: %s (%s)", project.Name, project.ID)

		ignores, err := c.client.GetIgnores(c.orgID, project.ID)
		if err != nil {
			log.Printf("Warning: failed to get ignores for project %s: %v", project.ID, err)
			continue
		}

		for _, ignore := range ignores {
			// Get code details for the ignore
			details, err := c.client.GetCodeDetails(c.orgID, project.ID, ignore.IssueID)
			if err != nil {
				log.Printf("Warning: failed to get code details for issue %s: %v", ignore.IssueID, err)
				continue
			}

			// Convert Snyk ignore to database ignore
			originalState, err := json.Marshal(ignore)
			if err != nil {
				log.Printf("Warning: failed to marshal original state for ignore %s: %v", ignore.ID, err)
				continue
			}

			dbIgnore := &database.Ignore{
				ID:            ignore.ID,
				IssueID:       ignore.IssueID,
				OrgID:         c.orgID,
				ProjectID:     project.ID,
				Reason:        ignore.Reason,
				IgnoreType:    ignore.ReasonType,
				CreatedAt:     ignore.CreatedAt,
				ExpiresAt:     ignore.ExpiresAt,
				Fingerprint:   details.ID,
				OriginalState: string(originalState),
			}

			if err := c.db.InsertIgnore(dbIgnore); err != nil {
				log.Printf("Warning: failed to insert ignore %s: %v", ignore.ID, err)
				continue
			}

			log.Printf("Collected ignore %s from project %s", ignore.ID, project.ID)
		}
	}

	// Update collection metadata
	if err := c.db.UpdateCollectionMetadata(time.Now(), collectionVersion, apiVersion); err != nil {
		return fmt.Errorf("failed to update collection metadata: %w", err)
	}

	log.Printf("Collection completed successfully")
	return nil
} 