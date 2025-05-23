package commands

import (
	"encoding/json"
	"fmt"
	"log"
	"time"

	"github.com/z4ce/cci-migrator/internal/snyk"
)

// RetestCommand handles the retest phase of the migration
type RetestCommand struct {
	db     DatabaseInterface
	client ClientInterface
	orgID  string
	debug  bool
}

// NewRetestCommand creates a new retest command
func NewRetestCommand(db DatabaseInterface, client ClientInterface, orgID string, debug bool) *RetestCommand {
	return &RetestCommand{
		db:     db,
		client: client,
		orgID:  orgID,
		debug:  debug,
	}
}

// Execute runs the retest command
func (c *RetestCommand) Execute() error {
	log.Printf("Starting retest for organization: %s", c.orgID)

	// Get all projects with migrated ignores that haven't been retested
	queryResult, err := c.db.Query(`
		SELECT DISTINCT p.id, p.name, p.target_information
		FROM projects p
		JOIN ignores i ON p.id = i.project_id
		WHERE p.org_id = ? AND i.migrated_at IS NOT NULL AND p.retested_at IS NULL
	`, c.orgID)
	if err != nil {
		return fmt.Errorf("failed to get projects to retest: %w", err)
	}

	// Type assertion for rows
	rows, ok := queryResult.(interface {
		Next() bool
		Scan(dest ...interface{}) error
		Close() error
	})
	if !ok {
		return fmt.Errorf("unexpected query result type")
	}
	defer rows.Close()

	var totalProjects, successfulRetests, failedRetests int

	for rows.Next() {
		var projectID, projectName, targetJSON string
		err := rows.Scan(&projectID, &projectName, &targetJSON)
		if err != nil {
			return fmt.Errorf("failed to scan project: %w", err)
		}

		totalProjects++
		log.Printf("Retesting project %d: %s (%s)", totalProjects, projectName, projectID)

		// Parse target information
		var target snyk.Target
		if err := json.Unmarshal([]byte(targetJSON), &target); err != nil {
			log.Printf("Warning: failed to parse target information for project %s: %v", projectID, err)
			failedRetests++
			continue
		}

		// If the target information is empty, fetch it from the API and update the database
		if target.Name == "" && target.URL == "" && target.Owner == "" && target.Repo == "" && target.Branch == "" && target.Origin == "" && target.Source == "" {
			// We don't have the target information yet; fetch the target ID via projects API
			projects, err := c.client.GetProjects(c.orgID)
			if err != nil {
				log.Printf("Warning: failed to fetch projects to determine target_id for project %s: %v", projectID, err)
				failedRetests++
				continue
			}

			var targetID string
			var targetReference string
			for _, p := range projects {
				if p.ID == projectID {
					targetID = p.Target.ID
					targetReference = p.TargetReference
					break
				}
			}

			if targetID == "" {
				log.Printf("Warning: could not determine target_id for project %s", projectID)
				failedRetests++
				continue
			}

			apiTarget, err := c.client.GetProjectTarget(c.orgID, targetID)
			if err != nil {
				log.Printf("Warning: failed to fetch target information from API for project %s: %v", projectID, err)
				failedRetests++
				continue
			}

			// Add the target_reference as the branch if available
			if targetReference != "" {
				apiTarget.Branch = targetReference
			}

			target = *apiTarget

			// Update the database with fresh target information so future runs have it available
			targetBytes, _ := json.Marshal(apiTarget)
			_, err = c.db.Exec(`
				UPDATE projects
				SET target_information = ?
				WHERE id = ?
			`, string(targetBytes), projectID)
			if err != nil {
				log.Printf("Warning: failed to update target information for project %s: %v", projectID, err)
			}
		}

		// Call Import API to retest
		err = c.client.RetestProject(c.orgID, &target)
		if err != nil {
			log.Printf("Warning: failed to retest project %s: %v", projectID, err)
			failedRetests++
			continue
		}

		// Mark project as retested
		now := time.Now()
		_, err = c.db.Exec(`
			UPDATE projects
			SET retested_at = ?
			WHERE id = ?
		`, now, projectID)
		if err != nil {
			log.Printf("Warning: failed to mark project as retested: %v", err)
			continue
		}

		successfulRetests++
		log.Printf("Successfully retested project %s", projectID)
	}

	log.Printf("Retest summary:")
	log.Printf("  Total projects to retest: %d", totalProjects)
	log.Printf("  Projects successfully retested: %d", successfulRetests)
	log.Printf("  Projects failed to retest: %d", failedRetests)

	return nil
}
