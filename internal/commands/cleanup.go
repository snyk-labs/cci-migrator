package commands

import (
	"fmt"
	"log"
	"time"
)

// CleanupCommand handles the cleanup phase of the migration
type CleanupCommand struct {
	db     DatabaseInterface
	client ClientInterface
	orgID  string
}

// NewCleanupCommand creates a new cleanup command
func NewCleanupCommand(db DatabaseInterface, client ClientInterface, orgID string) *CleanupCommand {
	return &CleanupCommand{
		db:     db,
		client: client,
		orgID:  orgID,
	}
}

// Execute runs the cleanup command
func (c *CleanupCommand) Execute() error {
	log.Printf("Starting cleanup for organization: %s", c.orgID)

	// Get all migrated ignores that haven't been deleted
	queryResult, err := c.db.Query(`
		SELECT id, project_id
		FROM ignores
		WHERE org_id = ? AND migrated_at IS NOT NULL AND deleted_at IS NULL
	`, c.orgID)
	if err != nil {
		return fmt.Errorf("failed to get ignores to delete: %w", err)
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

	var totalIgnores, deletedIgnores, failedDeletions int

	for rows.Next() {
		var ignoreID, projectID string
		err := rows.Scan(&ignoreID, &projectID)
		if err != nil {
			return fmt.Errorf("failed to scan ignore: %w", err)
		}

		totalIgnores++
		log.Printf("Deleting ignore %d: %s from project %s", totalIgnores, ignoreID, projectID)

		// Delete the ignore using the V1 API
		err = c.client.DeleteIgnore(c.orgID, projectID, ignoreID)
		if err != nil {
			log.Printf("Warning: failed to delete ignore %s: %v", ignoreID, err)
			failedDeletions++
			continue
		}

		// Mark ignore as deleted
		now := time.Now()
		_, err = c.db.Exec(`
			UPDATE ignores
			SET deleted_at = ?
			WHERE id = ?
		`, now, ignoreID)
		if err != nil {
			log.Printf("Warning: failed to mark ignore as deleted: %v", err)
			continue
		}

		deletedIgnores++
		log.Printf("Successfully deleted ignore %s", ignoreID)
	}

	log.Printf("Cleanup summary:")
	log.Printf("  Total ignores to delete: %d", totalIgnores)
	log.Printf("  Ignores successfully deleted: %d", deletedIgnores)
	log.Printf("  Ignores failed to delete: %d", failedDeletions)

	// Count progress
	var totalCount, migratedCount, deletedCount int

	countResult := c.db.QueryRow("SELECT COUNT(*) FROM ignores WHERE org_id = ?", c.orgID)
	err = countResult.Scan(&totalCount)
	if err != nil {
		log.Printf("Warning: failed to count total ignores: %v", err)
	}

	migratedResult := c.db.QueryRow("SELECT COUNT(*) FROM ignores WHERE org_id = ? AND migrated_at IS NOT NULL", c.orgID)
	err = migratedResult.Scan(&migratedCount)
	if err != nil {
		log.Printf("Warning: failed to count migrated ignores: %v", err)
	}

	deletedResult := c.db.QueryRow("SELECT COUNT(*) FROM ignores WHERE org_id = ? AND deleted_at IS NOT NULL", c.orgID)
	err = deletedResult.Scan(&deletedCount)
	if err != nil {
		log.Printf("Warning: failed to count deleted ignores: %v", err)
	}

	log.Printf("Overall migration progress:")
	log.Printf("  Total ignores: %d", totalCount)

	if totalCount > 0 {
		log.Printf("  Migrated ignores: %d (%.1f%%)", migratedCount, float64(migratedCount)/float64(totalCount)*100)
		log.Printf("  Deleted ignores: %d (%.1f%%)", deletedCount, float64(deletedCount)/float64(totalCount)*100)

		if migratedCount == totalCount && deletedCount == totalCount {
			log.Printf("Migration completed successfully!")
		} else {
			log.Printf("Migration is still in progress")
		}
	} else {
		log.Printf("No ignores found to migrate")
	}

	return nil
}
