package commands

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"time"

	"github.com/z4ce/cci-migrator/internal/database"
	"github.com/z4ce/cci-migrator/internal/snyk"
)

const (
	gatherVersion = "2.0.0"
	apiVersion    = "v1"
)

// DatabaseInterface defines the database operations needed by commands
type DatabaseInterface interface {
	GetIgnoresByOrgID(orgID string) ([]*database.Ignore, error)
	InsertIgnore(ignore *database.Ignore) error
	InsertIssue(issue *database.Issue) error
	InsertProject(project *database.Project) error
	InsertPolicy(policy *database.Policy) error
	GetIssuesByOrgID(orgID string) ([]*database.Issue, error)
	GetProjectsByOrgID(orgID string) ([]*database.Project, error)
	GetPoliciesByOrgID(orgID string) ([]*database.Policy, error)
	UpdateCollectionMetadata(completedAt time.Time, collectionVersion, apiVersion string) error
	Exec(query string, args ...interface{}) (interface{}, error)
	QueryRow(query string, args ...interface{}) *sql.Row
	Query(query string, args ...interface{}) (interface{}, error)
	Begin() (interface{}, error)
	Close() error
}

// TransactionInterface defines database transaction operations
type TransactionInterface interface {
	Exec(query string, args ...interface{}) (interface{}, error)
	Commit() error
	Rollback() error
}

// ClientInterface defines the Snyk API operations needed by the GatherCommand
type ClientInterface interface {
	GetProjects(orgID string) ([]snyk.Project, error)
	GetIgnores(orgID, projectID string) ([]snyk.Ignore, error)
	GetProjectTarget(orgID, projectID string) (*snyk.Target, error)
	GetSASTIssues(orgID, projectID string) ([]snyk.SASTIssue, error)
	CreatePolicy(orgID string, attributes snyk.CreatePolicyAttributes, meta map[string]interface{}) (*snyk.Policy, error)
	RetestProject(orgID, projectID string, target *snyk.Target) error
	DeleteIgnore(orgID, projectID, ignoreID string) error
}

// GatherCommand handles the gathering of ignores, issues, and projects
type GatherCommand struct {
	db     DatabaseInterface
	client ClientInterface
	orgID  string
	debug  bool
}

// NewGatherCommand creates a new gather command
func NewGatherCommand(db DatabaseInterface, client ClientInterface, orgID string, debug bool) *GatherCommand {
	return &GatherCommand{
		db:     db,
		client: client,
		orgID:  orgID,
		debug:  debug,
	}
}

// debugLog logs a message only when debug mode is enabled
func (c *GatherCommand) debugLog(format string, args ...interface{}) {
	if c.debug {
		log.Printf("Debug: "+format, args...)
	}
}

// Execute runs the gather command
func (c *GatherCommand) Execute() error {
	log.Printf("Starting data gathering for organization: %s", c.orgID)

	// Phase 1: Gather all SAST projects
	log.Printf("Phase 1: Gathering SAST projects...")
	projects, err := c.client.GetProjects(c.orgID)
	if err != nil {
		return fmt.Errorf("failed to get projects: %w", err)
	}

	log.Printf("Found %d SAST projects to process", len(projects))

	for _, project := range projects {
		log.Printf("Processing project: %s (%s)", project.Name, project.ID)

		// Get and store target information
		target, err := c.client.GetProjectTarget(c.orgID, project.ID)
		if err != nil {
			log.Printf("Warning: failed to get target for project %s: %v", project.ID, err)
			continue
		}

		targetInfo, err := json.Marshal(target)
		if err != nil {
			log.Printf("Warning: failed to marshal target for project %s: %v", project.ID, err)
			continue
		}

		dbProject := &database.Project{
			ID:                project.ID,
			OrgID:             c.orgID,
			Name:              project.Name,
			TargetInformation: string(targetInfo),
		}

		if err := c.db.InsertProject(dbProject); err != nil {
			log.Printf("Warning: failed to insert project %s: %v", project.ID, err)
			continue
		}

		log.Printf("Successfully stored project %s with target information", project.ID)
	}

	// Phase 2: Gather all SAST ignores
	log.Printf("Phase 2: Gathering SAST ignores...")
	for _, project := range projects {
		log.Printf("Processing ignores for project: %s (%s)", project.Name, project.ID)

		ignores, err := c.client.GetIgnores(c.orgID, project.ID)
		if err != nil {
			log.Printf("Warning: failed to get ignores for project %s: %v", project.ID, err)
			continue
		}

		log.Printf("Fetched %d ignores for project %s", len(ignores), project.ID)

		if len(ignores) == 0 {
			log.Printf("No ignores found for project %s, skipping", project.ID)
			continue
		}

		for i, ignore := range ignores {
			log.Printf("Processing ignore %d/%d: ID=%s", i+1, len(ignores), ignore.ID)

			// Convert Snyk ignore to database ignore
			originalState, err := json.Marshal(ignore)
			if err != nil {
				log.Printf("Warning: failed to marshal original state for ignore %s: %v", ignore.ID, err)
				continue
			}

			dbIgnore := &database.Ignore{
				ID:            ignore.ID,
				IssueID:       ignore.ID, // The ignore ID is the same as the issue ID
				OrgID:         c.orgID,
				ProjectID:     project.ID,
				Reason:        ignore.Reason,
				IgnoreType:    ignore.ReasonType,
				CreatedAt:     ignore.CreatedAt,
				ExpiresAt:     ignore.ExpiresAt,
				AssetKey:      "", // Will be populated in phase 3
				OriginalState: string(originalState),
			}

			if err := c.db.InsertIgnore(dbIgnore); err != nil {
				log.Printf("Warning: failed to insert ignore %s: %v", ignore.ID, err)
				continue
			}

			log.Printf("Successfully inserted ignore %s into database", ignore.ID)
		}
	}

	// Phase 3: Gather all SAST issues and match with ignores
	log.Printf("Phase 3: Gathering SAST issues and asset keys...")

	// Get all SAST issues for the organization at once
	issues, err := c.client.GetSASTIssues(c.orgID, "")
	if err != nil {
		log.Printf("Warning: failed to get SAST issues: %v", err)
		return fmt.Errorf("failed to get SAST issues: %w", err)
	}

	log.Printf("Fetched %d SAST issues for organization", len(issues))

	// Process issues and update ignores
	for i, issue := range issues {
		log.Printf("Processing issue %d/%d: ID=%s, AssetKey=%s, ProjectKey=%s", i+1, len(issues), issue.ID, issue.Attributes.KeyAsset, issue.Attributes.Key)

		originalState, err := json.Marshal(issue)
		if err != nil {
			log.Printf("Warning: failed to marshal original state for issue %s: %v", issue.ID, err)
			continue
		}

		// Store issue in database
		dbIssue := &database.Issue{
			ID:            issue.ID,
			OrgID:         c.orgID,
			ProjectID:     issue.Relationships.ScanItem.Data.ID,
			AssetKey:      issue.Attributes.KeyAsset,
			ProjectKey:    issue.Attributes.Key,
			OriginalState: string(originalState),
		}

		c.debugLog("Preparing to insert issue: ID=%s OrgID=%s ProjectID=%s AssetKey=%s ProjectKey=%s",
			dbIssue.ID, dbIssue.OrgID, dbIssue.ProjectID, dbIssue.AssetKey, dbIssue.ProjectKey)

		if err := c.db.InsertIssue(dbIssue); err != nil {
			log.Printf("Warning: failed to insert issue %s: %v", issue.ID, err)
			continue
		}

		log.Printf("Successfully inserted issue %s with asset key %s and project key %s into database", issue.ID, issue.Attributes.KeyAsset, issue.Attributes.Key)
	}

	// Phase 3.1: Update asset keys for all ignores from issues
	log.Printf("Phase 3.1: Updating asset keys for all ignores in organization %s...", c.orgID)
	updateIgnoresQuery := `
		UPDATE ignores
		SET asset_key = (
			SELECT i.asset_key
			FROM issues i
			WHERE i.project_key = ignores.issue_id   -- Corrected join condition
			  AND i.org_id = ignores.org_id
			  AND i.project_id = ignores.project_id
			LIMIT 1 -- Ensures subquery returns one row
		)
		WHERE ignores.org_id = ?
		  AND EXISTS (
			SELECT 1
			FROM issues i
			WHERE i.project_key = ignores.issue_id   -- Corrected join condition
			  AND i.org_id = ignores.org_id
			  AND i.project_id = ignores.project_id
			  AND i.asset_key IS NOT NULL
			  AND i.asset_key != ''
		);`

	result, err := c.db.Exec(updateIgnoresQuery, c.orgID)
	if err != nil {
		log.Printf("Warning: failed to bulk update asset keys for ignores in org %s: %v", c.orgID, err)
		// Depending on requirements, this could be a fatal error:
		// return fmt.Errorf("failed to bulk update asset keys for ignores: %w", err)
	} else {
		// Check if the result provides RowsAffected (standard sql.Result)
		if res, ok := result.(interface{ RowsAffected() (int64, error) }); ok {
			rowsAffected, raErr := res.RowsAffected()
			if raErr != nil {
				log.Printf("Warning: could not get rows affected after bulk update for org %s: %v", c.orgID, raErr)
			} else {
				log.Printf("Successfully executed bulk update for ignores in org %s. Rows affected: %d", c.orgID, rowsAffected)
			}
		} else {
			// Fallback log if RowsAffected is not available
			log.Printf("Successfully executed bulk update for ignores in organization %s (RowsAffected not available).", c.orgID)
		}
	}

	// Update collection metadata
	if err := c.db.UpdateCollectionMetadata(time.Now(), gatherVersion, apiVersion); err != nil {
		return fmt.Errorf("failed to update collection metadata: %w", err)
	}

	// Print summary
	ignores, err := c.db.GetIgnoresByOrgID(c.orgID)
	if err != nil {
		log.Printf("Error checking ignores after gathering: %v", err)
	} else {
		log.Printf("Found %d SAST ignores for organization %s after gathering", len(ignores), c.orgID)

		// Count ignores with asset keys
		ignoresWithAssetKey := 0
		for _, ignore := range ignores {
			if ignore.AssetKey != "" {
				ignoresWithAssetKey++
			}
		}

		log.Printf("%d of %d ignores have asset keys (%.1f%%)",
			ignoresWithAssetKey, len(ignores),
			float64(ignoresWithAssetKey)/float64(len(ignores))*100)
	}

	// Get issues count
	countRow := c.db.QueryRow("SELECT COUNT(*) FROM issues WHERE org_id = ?", c.orgID)
	var issuesCount int
	if err := countRow.Scan(&issuesCount); err != nil {
		log.Printf("Error checking issues count: %v", err)
	} else {
		log.Printf("Found %d SAST issues for organization %s", issuesCount, c.orgID)
	}

	// Get projects count
	projectCountRow := c.db.QueryRow("SELECT COUNT(*) FROM projects WHERE org_id = ?", c.orgID)
	var projectsCount int
	if err := projectCountRow.Scan(&projectsCount); err != nil {
		log.Printf("Error checking projects count: %v", err)
	} else {
		log.Printf("Found %d SAST projects for organization %s", projectsCount, c.orgID)
	}

	log.Printf("Data gathering completed successfully")
	return nil
}

// Print prints the contents of the database
func (c *GatherCommand) Print() error {
	log.Printf("Printing gathered data for organization: %s", c.orgID)

	// Print ignores
	ignores, err := c.db.GetIgnoresByOrgID(c.orgID)
	if err != nil {
		return fmt.Errorf("failed to get ignores: %w", err)
	}

	log.Printf("Found %d ignores:", len(ignores))
	for i, ignore := range ignores {
		if i < 10 || len(ignores) < 20 { // Print first 10 or all if less than 20
			log.Printf("  Ignore %d/%d: ID=%s, IssueID=%s, AssetKey=%s, Type=%s, Reason=%s",
				i+1, len(ignores), ignore.ID, ignore.IssueID, ignore.AssetKey, ignore.IgnoreType, ignore.Reason)
		} else if i == 10 {
			log.Printf("  ... and %d more ignores", len(ignores)-10)
			break
		}
	}

	// Print issues (get from database)
	rows, err := c.db.Query("SELECT id, org_id, project_id, asset_key, project_key FROM issues WHERE org_id = ?", c.orgID)
	if err != nil {
		return fmt.Errorf("failed to get issues: %w", err)
	}

	type SimpleIssue struct {
		ID         string
		OrgID      string
		ProjectID  string
		AssetKey   string
		ProjectKey string
	}

	var issues []SimpleIssue
	if rowsScanner, ok := rows.(interface {
		Next() bool
		Scan(dest ...interface{}) error
		Close() error
	}); ok {
		defer rowsScanner.Close()

		for rowsScanner.Next() {
			var issue SimpleIssue
			if err := rowsScanner.Scan(&issue.ID, &issue.OrgID, &issue.ProjectID, &issue.AssetKey, &issue.ProjectKey); err != nil {
				log.Printf("Error scanning issue row: %v", err)
				continue
			}
			issues = append(issues, issue)
		}
	}

	log.Printf("Found %d issues:", len(issues))
	for i, issue := range issues {
		if i < 10 || len(issues) < 20 { // Print first 10 or all if less than 20
			log.Printf("  Issue %d/%d: ID=%s, AssetKey=%s, ProjectKey=%s",
				i+1, len(issues), issue.ID, issue.AssetKey, issue.ProjectKey)
		} else if i == 10 {
			log.Printf("  ... and %d more issues", len(issues)-10)
			break
		}
	}

	// Print projects (get from database)
	projectRows, err := c.db.Query("SELECT id, org_id, name FROM projects WHERE org_id = ?", c.orgID)
	if err != nil {
		return fmt.Errorf("failed to get projects: %w", err)
	}

	type SimpleProject struct {
		ID    string
		OrgID string
		Name  string
	}

	var projects []SimpleProject
	if projectRowsScanner, ok := projectRows.(interface {
		Next() bool
		Scan(dest ...interface{}) error
		Close() error
	}); ok {
		defer projectRowsScanner.Close()

		for projectRowsScanner.Next() {
			var project SimpleProject
			if err := projectRowsScanner.Scan(&project.ID, &project.OrgID, &project.Name); err != nil {
				log.Printf("Error scanning project row: %v", err)
				continue
			}
			projects = append(projects, project)
		}
	}

	log.Printf("Found %d projects:", len(projects))
	for i, project := range projects {
		if i < 10 || len(projects) < 20 { // Print first 10 or all if less than 20
			log.Printf("  Project %d/%d: ID=%s, Name=%s",
				i+1, len(projects), project.ID, project.Name)
		} else if i == 10 {
			log.Printf("  ... and %d more projects", len(projects)-10)
			break
		}
	}

	return nil
}
