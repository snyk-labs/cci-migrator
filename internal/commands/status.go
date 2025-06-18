package commands

import (
	"database/sql"
	"fmt"
	"log"
	"time"
)

// StatusCommand handles checking the migration status
type StatusCommand struct {
	db    DatabaseInterface
	orgID string
	debug bool
}

// NewStatusCommand creates a new status command
func NewStatusCommand(db DatabaseInterface, orgID string, debug bool) *StatusCommand {
	return &StatusCommand{
		db:    db,
		orgID: orgID,
		debug: debug,
	}
}

// Execute runs the status command
func (c *StatusCommand) Execute() error {
	log.Printf("Checking migration status for organization: %s", c.orgID)

	// Get counts from database
	ignores, err := c.db.GetIgnoresByOrgID(c.orgID)
	if err != nil {
		return fmt.Errorf("failed to get ignores: %w", err)
	}

	issues, err := c.db.GetIssuesByOrgID(c.orgID)
	if err != nil {
		return fmt.Errorf("failed to get issues: %w", err)
	}

	projects, err := c.db.GetProjectsByOrgID(c.orgID)
	if err != nil {
		return fmt.Errorf("failed to get projects: %w", err)
	}

	policies, err := c.db.GetPoliciesByOrgID(c.orgID)
	if err != nil {
		return fmt.Errorf("failed to get policies: %w", err)
	}

	// Count items by status
	var totalIgnores, selectedIgnores, migratedIgnores, deletedIgnores int
	for _, ignore := range ignores {
		totalIgnores++
		if ignore.SelectedForMigration {
			selectedIgnores++
		}
		if ignore.MigratedAt != nil {
			migratedIgnores++
		}
		if ignore.DeletedAt != nil {
			deletedIgnores++
		}
	}

	var totalPolicies, createdPolicies int
	for _, policy := range policies {
		totalPolicies++
		if policy.ExternalID != "" {
			createdPolicies++
		}
	}

	var retestedProjects, cliProjects, regularProjects int
	for _, project := range projects {
		if project.IsCliProject {
			cliProjects++
		} else {
			regularProjects++
			if project.RetestedAt != nil {
				retestedProjects++
			}
		}
	}

	// Calculate projects that actually need retesting (only those with migrated ignores)
	var projectsNeedingRetest int
	projectsWithMigratedIgnores := make(map[string]bool)

	// Find projects that have migrated ignores
	for _, ignore := range ignores {
		if ignore.MigratedAt != nil {
			projectsWithMigratedIgnores[ignore.ProjectID] = true
		}
	}

	// Count non-CLI projects that have migrated ignores
	for _, project := range projects {
		if !project.IsCliProject && projectsWithMigratedIgnores[project.ID] {
			projectsNeedingRetest++
		}
	}

	// Check for collection metadata
	var collectionCompletedAt time.Time
	var collectionVersion, apiVersion string

	rows, err := c.db.Query("SELECT collection_completed_at, collection_version, api_version FROM collection_metadata LIMIT 1")
	if err != nil {
		return fmt.Errorf("failed to query collection metadata: %w", err)
	}
	defer rows.(interface{ Close() error }).Close()

	sqlRows := rows.(*sql.Rows)
	if sqlRows.Next() {
		if err := sqlRows.Scan(&collectionCompletedAt, &collectionVersion, &apiVersion); err != nil {
			return fmt.Errorf("failed to scan collection metadata: %w", err)
		}
	}

	// Print status
	fmt.Printf("\nMigration Status for Organization: %s\n", c.orgID)
	fmt.Printf("----------------------------------------\n")
	fmt.Printf("Collection Phase:\n")
	if !collectionCompletedAt.IsZero() {
		fmt.Printf("  Completed: %s\n", collectionCompletedAt.Format("2006-01-02 15:04:05"))
		fmt.Printf("  Collector Version: %s\n", collectionVersion)
		fmt.Printf("  API Version: %s\n", apiVersion)
	} else {
		fmt.Printf("  Not completed\n")
	}
	fmt.Printf("  Projects: %d\n", len(projects))
	fmt.Printf("  CLI Projects (cannot be retested): %d\n", cliProjects)
	fmt.Printf("  Regular Projects: %d\n", regularProjects)
	fmt.Printf("  Issues: %d\n", len(issues))
	fmt.Printf("  Ignores: %d\n", totalIgnores)

	fmt.Printf("\nPlan Phase:\n")
	fmt.Printf("  Selected Ignores: %d/%d (%.1f%%)\n", selectedIgnores, totalIgnores, percentage(selectedIgnores, totalIgnores))
	fmt.Printf("  Planned Policies: %d\n", totalPolicies)

	fmt.Printf("\nExecution Phase:\n")
	fmt.Printf("  Created Policies: %d/%d (%.1f%%)\n", createdPolicies, totalPolicies, percentage(createdPolicies, totalPolicies))
	fmt.Printf("  Migrated Ignores: %d/%d (%.1f%%)\n", migratedIgnores, selectedIgnores, percentage(migratedIgnores, selectedIgnores))

	fmt.Printf("\nRetest Phase:\n")
	fmt.Printf("  Retested Projects: %d/%d (%.1f%%)\n", retestedProjects, projectsNeedingRetest, percentage(retestedProjects, projectsNeedingRetest))

	fmt.Printf("\nCleanup Phase:\n")
	fmt.Printf("  Deleted Ignores: %d/%d (%.1f%%)\n", deletedIgnores, selectedIgnores, percentage(deletedIgnores, selectedIgnores))

	// Determine overall status
	fmt.Printf("\nOverall Status: ")
	if totalIgnores == 0 {
		fmt.Println("NOT STARTED")
	} else if selectedIgnores == 0 {
		fmt.Println("COLLECTION COMPLETE")
	} else if createdPolicies == 0 {
		fmt.Println("PLANNING COMPLETE")
	} else if migratedIgnores < selectedIgnores {
		fmt.Println("EXECUTION IN PROGRESS")
	} else if retestedProjects < projectsNeedingRetest {
		fmt.Println("RETEST IN PROGRESS")
	} else if deletedIgnores < selectedIgnores {
		fmt.Println("CLEANUP IN PROGRESS")
	} else {
		fmt.Println("MIGRATION COMPLETE")
	}

	return nil
}

// percentage calculates the percentage of part out of total
func percentage(part, total int) float64 {
	if total == 0 {
		return 0.0
	}
	return float64(part) * 100.0 / float64(total)
}

// RollbackCommand handles rollback operations
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
	fmt.Println("WARNING: Rollback will attempt to undo the migration by:")
	fmt.Println("  1. Marking all migrated ignores as not migrated")
	fmt.Println("  2. Marking all deleted ignores as not deleted")
	fmt.Println("  3. Marking all policies as not created")
	fmt.Println()
	fmt.Println("This operation cannot undo API changes that have already been made.")
	fmt.Println("You will need to manually delete created policies in the Snyk UI.")
	fmt.Println()
	fmt.Print("Are you sure you want to proceed? (y/N): ")

	var confirm string
	fmt.Scanln(&confirm)

	if confirm != "y" && confirm != "Y" {
		fmt.Println("Rollback cancelled.")
		return nil
	}

	// Reset migrated_at and deleted_at fields for all ignores
	_, err := c.db.Exec(`
		UPDATE ignores 
		SET migrated_at = NULL, deleted_at = NULL, policy_id = '', internal_policy_id = '' 
		WHERE org_id = ?
	`, c.orgID)

	if err != nil {
		return fmt.Errorf("failed to reset ignore status: %w", err)
	}

	// Reset external_id for all policies
	_, err = c.db.Exec(`
		UPDATE policies 
		SET external_id = '' 
		WHERE org_id = ?
	`, c.orgID)

	if err != nil {
		return fmt.Errorf("failed to reset policy status: %w", err)
	}

	// Reset retested_at for all projects
	_, err = c.db.Exec(`
		UPDATE projects 
		SET retested_at = NULL 
		WHERE org_id = ?
	`, c.orgID)

	if err != nil {
		return fmt.Errorf("failed to reset project status: %w", err)
	}

	fmt.Println("Database rollback completed successfully.")
	fmt.Println("IMPORTANT: Any policies created in Snyk must be manually deleted.")

	return nil
}
