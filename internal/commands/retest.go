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

	// First, get a count of CLI projects to show user what's being skipped
	cliCountResult, err := c.db.Query(`
		SELECT COUNT(DISTINCT p.id)
		FROM projects p
		JOIN ignores i ON p.id = i.project_id
		WHERE p.org_id = ? AND i.migrated_at IS NOT NULL AND p.is_cli_project = 1
	`, c.orgID)
	if err != nil {
		log.Printf("Warning: failed to count CLI projects: %v", err)
	} else {
		if cliRows, ok := cliCountResult.(interface {
			Next() bool
			Scan(dest ...interface{}) error
			Close() error
		}); ok {
			defer cliRows.Close()
			if cliRows.Next() {
				var cliCount int
				if err := cliRows.Scan(&cliCount); err == nil && cliCount > 0 {
					log.Printf("Skipping %d CLI projects (cannot be retested via API)", cliCount)
				}
			}
		}
	}

	// Get all projects with migrated ignores that haven't been retested (excluding CLI projects)
	queryResult, err := c.db.Query(`
		SELECT DISTINCT p.id, p.name, p.target_information
		FROM projects p
		JOIN ignores i ON p.id = i.project_id
		WHERE p.org_id = ? AND i.migrated_at IS NOT NULL AND p.retested_at IS NULL AND p.is_cli_project = 0
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

	// Collect all project data first to avoid deadlock
	type projectData struct {
		ID         string
		Name       string
		TargetJSON string
	}

	var projects []projectData
	for rows.Next() {
		var projectID, projectName, targetJSON string
		err := rows.Scan(&projectID, &projectName, &targetJSON)
		if err != nil {
			rows.Close()
			return fmt.Errorf("failed to scan project: %w", err)
		}

		projects = append(projects, projectData{
			ID:         projectID,
			Name:       projectName,
			TargetJSON: targetJSON,
		})
	}
	rows.Close() // Close the result set before processing

	var totalProjects, successfulRetests, failedRetests int
	totalProjects = len(projects)

	// Now process the collected projects
	for i, proj := range projects {
		log.Printf("Retesting project %d/%d: %s (%s)", i+1, totalProjects, proj.Name, proj.ID)

		// Parse target information
		var target snyk.Target
		if err := json.Unmarshal([]byte(proj.TargetJSON), &target); err != nil {
			log.Printf("Warning: failed to parse target information for project %s: %v", proj.ID, err)
			failedRetests++
			continue
		}

		// If the target information is empty, fetch it from the API and update the database
		if target.Name == "" && target.URL == "" && target.Owner == "" && target.Repo == "" && target.Branch == "" && target.Origin == "" && target.Source == "" {
			// We don't have the target information yet; fetch the target ID via projects API
			apiProjects, err := c.client.GetProjects(c.orgID)
			if err != nil {
				log.Printf("Warning: failed to fetch projects to determine target_id for project %s: %v", proj.ID, err)
				failedRetests++
				continue
			}

			var targetID string
			var targetReference string
			for _, p := range apiProjects {
				if p.ID == proj.ID {
					targetID = p.Target.ID
					targetReference = p.TargetReference
					break
				}
			}

			if targetID == "" {
				log.Printf("Warning: could not determine target_id for project %s", proj.ID)
				failedRetests++
				continue
			}

			apiTarget, err := c.client.GetProjectTarget(c.orgID, targetID)
			if err != nil {
				log.Printf("Warning: failed to fetch target information from API for project %s: %v", proj.ID, err)
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
			`, string(targetBytes), proj.ID)
			if err != nil {
				log.Printf("Warning: failed to update target information for project %s: %v", proj.ID, err)
			}
		}

		// Call Import API to retest
		err = c.client.RetestProject(c.orgID, &target)
		if err != nil {
			log.Printf("Warning: failed to retest project %s: %v", proj.ID, err)
			failedRetests++
			continue
		}

		// Mark project as retested
		now := time.Now()
		_, err = c.db.Exec(`
			UPDATE projects
			SET retested_at = ?
			WHERE id = ?
		`, now, proj.ID)
		if err != nil {
			log.Printf("Warning: failed to mark project as retested: %v", err)
			continue
		}

		successfulRetests++
		log.Printf("Successfully retested project %s", proj.ID)
	}

	log.Printf("Retest summary:")
	log.Printf("  Total projects to retest: %d", totalProjects)
	log.Printf("  Projects successfully retested: %d", successfulRetests)
	log.Printf("  Projects failed to retest: %d", failedRetests)

	return nil
}
