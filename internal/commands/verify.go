package commands

import (
	"fmt"
	"log"
)

// VerifyCommand handles verification of collected data
type VerifyCommand struct {
	db     DatabaseInterface
	client ClientInterface
	orgID  string
	debug  bool
}

// NewVerifyCommand creates a new verify command
func NewVerifyCommand(db DatabaseInterface, client ClientInterface, orgID string, debug bool) *VerifyCommand {
	return &VerifyCommand{
		db:     db,
		client: client,
		orgID:  orgID,
		debug:  debug,
	}
}

// Execute runs the verify command
func (c *VerifyCommand) Execute() error {
	log.Printf("Starting verification for organization: %s", c.orgID)

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

	// Count ignores with missing asset keys
	var missingAssetKeys int
	for _, ignore := range ignores {
		if ignore.AssetKey == "" {
			missingAssetKeys++
		}
	}

	// Count projects with missing target information
	var missingTargetInfo, cliProjects int
	for _, project := range projects {
		if project.IsCliProject {
			cliProjects++
		} else if project.TargetInformation == "" {
			missingTargetInfo++
		}
	}

	// Print verification results
	fmt.Printf("Verification Results for Organization: %s\n", c.orgID)
	fmt.Printf("Total Projects: %d\n", len(projects))
	fmt.Printf("CLI Projects (cannot be retested): %d\n", cliProjects)
	fmt.Printf("Regular Projects: %d\n", len(projects)-cliProjects)
	fmt.Printf("Total Issues: %d\n", len(issues))
	fmt.Printf("Total Ignores: %d\n", len(ignores))
	fmt.Printf("Ignores with Missing Asset Keys: %d\n", missingAssetKeys)
	fmt.Printf("Regular Projects with Missing Target Information: %d\n", missingTargetInfo)

	// Check for collection metadata
	var metadataCount int
	rows, err := c.db.Query("SELECT COUNT(*) FROM collection_metadata")
	if err != nil {
		return fmt.Errorf("failed to query collection metadata: %w", err)
	}

	// Use type assertion with a more general interface
	if closer, ok := rows.(interface{ Close() error }); ok {
		defer closer.Close()
	}

	// Use type assertion with a more general interface for scanning
	if scanner, ok := rows.(interface {
		Next() bool
		Scan(dest ...interface{}) error
	}); ok {
		if scanner.Next() {
			if err := scanner.Scan(&metadataCount); err != nil {
				return fmt.Errorf("failed to scan collection metadata count: %w", err)
			}
		}
	}

	if metadataCount == 0 {
		fmt.Println("WARNING: No collection metadata found. Collection may not be complete.")
	} else {
		fmt.Println("Collection metadata found. Collection appears to be complete.")
	}

	// Verification summary
	if missingAssetKeys > 0 || missingTargetInfo > 0 || metadataCount == 0 {
		fmt.Println("\nVerification Status: INCOMPLETE")
		fmt.Println("Some data appears to be missing or incomplete. Consider re-running the gather command.")
	} else {
		fmt.Println("\nVerification Status: COMPLETE")
		fmt.Println("All required data appears to be present.")
	}

	return nil
}
