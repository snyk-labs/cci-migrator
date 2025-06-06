package commands

import (
	"fmt"
	"log"
	"strings"
	"time"
)

// CleanupCommand handles the cleanup phase of the migration
type CleanupCommand struct {
	db     DatabaseInterface
	client ClientInterface
	orgID  string
	debug  bool
}

// NewCleanupCommand creates a new cleanup command
func NewCleanupCommand(db DatabaseInterface, client ClientInterface, orgID string, debug bool) *CleanupCommand {
	return &CleanupCommand{
		db:     db,
		client: client,
		orgID:  orgID,
		debug:  debug,
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

	// Collect all ignores to process (to avoid holding cursor during updates)
	type ignoreData struct {
		ID        string
		ProjectID string
	}

	var ignores []ignoreData
	for rows.Next() {
		var ignoreID, projectID string
		err := rows.Scan(&ignoreID, &projectID)
		if err != nil {
			rows.Close()
			return fmt.Errorf("failed to scan ignore: %w", err)
		}

		ignores = append(ignores, ignoreData{
			ID:        ignoreID,
			ProjectID: projectID,
		})
	}
	rows.Close()

	var totalIgnores, deletedIgnores, failedDeletions int
	totalIgnores = len(ignores)

	// Process each ignore
	for i, ignore := range ignores {
		log.Printf("Deleting ignore %d/%d: %s from project %s", i+1, totalIgnores, ignore.ID, ignore.ProjectID)

		// Delete the ignore using the V1 API
		err = c.client.DeleteIgnore(c.orgID, ignore.ProjectID, ignore.ID)
		if err != nil {
			log.Printf("Warning: failed to delete ignore %s: %v", ignore.ID, err)
			failedDeletions++
			continue
		}

		// Mark ignore as deleted with transaction retry logic
		var transactionError error
		for retryCount := 0; retryCount < 3; retryCount++ {
			if retryCount > 0 {
				log.Printf("Retrying transaction for ignore %s (attempt %d/3)...", ignore.ID, retryCount+1)
				// Add a small delay before retrying to allow locks to clear
				time.Sleep(time.Duration(retryCount) * 500 * time.Millisecond)
			}

			// Begin a transaction for this database update
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

			// Mark ignore as deleted within the transaction
			now := time.Now()
			_, err = tx.Exec(`
				UPDATE ignores
				SET deleted_at = ?
				WHERE id = ?
			`, now, ignore.ID)
			if err != nil {
				log.Printf("Warning: failed to mark ignore as deleted: %v", err)
				// Rollback and check if we should retry
				if rollbackErr := tx.Rollback(); rollbackErr != nil {
					log.Printf("Warning: failed to rollback transaction: %v", rollbackErr)
				}
				// If this is a locking error, try again
				if strings.Contains(err.Error(), "locked") {
					transactionError = err
					continue
				}
				transactionError = err
				break // Permanent error, don't retry
			}

			// Commit the transaction
			if err := tx.Commit(); err != nil {
				log.Printf("Warning: failed to commit transaction: %v", err)
				// If this is a locking error, try again
				if strings.Contains(err.Error(), "locked") {
					transactionError = err
					continue
				}
				transactionError = err
				break // Permanent error, don't retry
			}

			// Transaction was successful
			transactionError = nil
			break // Exit retry loop on success
		}

		// Check if all retries failed
		if transactionError != nil {
			log.Printf("Warning: all transaction attempts failed for ignore %s: %v", ignore.ID, transactionError)
			failedDeletions++
			continue
		}

		deletedIgnores++
		log.Printf("Successfully deleted ignore %s", ignore.ID)
	}

	log.Printf("Cleanup summary:")
	log.Printf("  Total ignores to delete: %d", totalIgnores)
	log.Printf("  Ignores successfully deleted: %d", deletedIgnores)
	log.Printf("  Ignores failed to delete: %d", failedDeletions)

	// Count progress (outside of transaction to avoid deadlock)
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
