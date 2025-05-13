package commands

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"fmt"
	"log"
	"sort"
	"strings"

	"github.com/z4ce/cci-migrator/internal/database"
)

// PlanCommand handles the planning of migration
type PlanCommand struct {
	db     DatabaseInterface
	client ClientInterface
	orgID  string
	debug  bool
}

// NewPlanCommand creates a new plan command
func NewPlanCommand(db DatabaseInterface, client ClientInterface, orgID string, debug bool) *PlanCommand {
	return &PlanCommand{
		db:     db,
		client: client,
		orgID:  orgID,
		debug:  debug,
	}
}

// Execute runs the plan command
func (c *PlanCommand) Execute() error {
	log.Printf("Starting migration planning for organization: %s", c.orgID)

	// Get all ignores with asset keys
	rows, err := c.db.Query(`
		SELECT * FROM ignores 
		WHERE org_id = ? AND asset_key != '' AND asset_key IS NOT NULL
	`, c.orgID)
	if err != nil {
		return fmt.Errorf("failed to get ignores with asset keys: %w", err)
	}

	sqlRows := rows.(*sql.Rows)
	defer sqlRows.Close()

	// Group ignores by asset key
	assetKeyMap := make(map[string][]*database.Ignore)
	var totalIgnores int

	for sqlRows.Next() {
		ignore := &database.Ignore{}
		err := sqlRows.Scan(
			&ignore.ID, &ignore.IssueID, &ignore.OrgID, &ignore.ProjectID,
			&ignore.Reason, &ignore.IgnoreType, &ignore.CreatedAt, &ignore.ExpiresAt,
			&ignore.AssetKey, &ignore.OriginalState,
			&ignore.DeletedAt, &ignore.MigratedAt, &ignore.PolicyID, &ignore.InternalPolicyID,
			&ignore.SelectedForMigration,
		)
		if err != nil {
			return fmt.Errorf("failed to scan ignore: %w", err)
		}

		assetKeyMap[ignore.AssetKey] = append(assetKeyMap[ignore.AssetKey], ignore)
		totalIgnores++
	}

	log.Printf("Found %d ignores with asset keys across %d unique asset keys",
		totalIgnores, len(assetKeyMap))

	// Process each asset key
	var singleIgnoreCount, multipleIgnoreCount int
	var policiesCreated, ignoresToMigrate int

	for assetKey, ignores := range assetKeyMap {
		if len(ignores) == 1 {
			singleIgnoreCount++
			// For single ignores, just mark it for migration
			selectedIgnore := ignores[0]
			if err := c.createPolicy(selectedIgnore, []*database.Ignore{selectedIgnore}); err != nil {
				log.Printf("Warning: failed to create policy for asset key %s: %v", assetKey, err)
				continue
			}
			ignoresToMigrate++
			policiesCreated++
		} else {
			multipleIgnoreCount++
			// For multiple ignores, apply conflict resolution
			selectedIgnore := c.resolveConflict(ignores)
			if err := c.createPolicy(selectedIgnore, ignores); err != nil {
				log.Printf("Warning: failed to create policy for asset key %s: %v", assetKey, err)
				continue
			}
			ignoresToMigrate += len(ignores)
			policiesCreated++
		}
	}

	log.Printf("Planning summary:")
	log.Printf("  Total asset keys: %d", len(assetKeyMap))
	log.Printf("  Asset keys with single ignores: %d", singleIgnoreCount)
	log.Printf("  Asset keys with multiple ignores: %d", multipleIgnoreCount)
	log.Printf("  Total policies to be created: %d", policiesCreated)
	log.Printf("  Total ignores to be migrated: %d", ignoresToMigrate)

	return nil
}

// resolveConflict implements the conflict resolution strategy
func (c *PlanCommand) resolveConflict(ignores []*database.Ignore) *database.Ignore {
	// Group ignores by type
	wontFixIgnores := make([]*database.Ignore, 0)
	notVulnerableIgnores := make([]*database.Ignore, 0)
	temporaryIgnores := make([]*database.Ignore, 0)

	for _, ignore := range ignores {
		switch ignore.IgnoreType {
		case "wont-fix":
			wontFixIgnores = append(wontFixIgnores, ignore)
		case "not-vulnerable":
			notVulnerableIgnores = append(notVulnerableIgnores, ignore)
		case "temporary":
			temporaryIgnores = append(temporaryIgnores, ignore)
		default:
			// If we don't recognize the type, default to temporary
			temporaryIgnores = append(temporaryIgnores, ignore)
		}
	}

	// Sort each group by creation date (earliest first)
	sortByDate := func(ignores []*database.Ignore) *database.Ignore {
		if len(ignores) == 0 {
			return nil
		}

		sort.Slice(ignores, func(i, j int) bool {
			return ignores[i].CreatedAt.Before(ignores[j].CreatedAt)
		})

		return ignores[0]
	}

	// Apply priority order: wont-fix > not-vulnerable > temporary
	if len(wontFixIgnores) > 0 {
		selectedIgnore := sortByDate(wontFixIgnores)
		log.Printf("Selected 'wont-fix' ignore %s from %d candidates (earliest creation date)",
			selectedIgnore.ID, len(wontFixIgnores))
		return selectedIgnore
	}

	if len(notVulnerableIgnores) > 0 {
		selectedIgnore := sortByDate(notVulnerableIgnores)
		log.Printf("Selected 'not-vulnerable' ignore %s from %d candidates (earliest creation date)",
			selectedIgnore.ID, len(notVulnerableIgnores))
		return selectedIgnore
	}

	if len(temporaryIgnores) > 0 {
		selectedIgnore := sortByDate(temporaryIgnores)
		log.Printf("Selected 'temporary' ignore %s from %d candidates (earliest creation date)",
			selectedIgnore.ID, len(temporaryIgnores))
		return selectedIgnore
	}

	// This should never happen as we've covered all cases
	log.Printf("Warning: Could not select an ignore, using the first one")
	return ignores[0]
}

// createPolicy creates a policy entry in the database
func (c *PlanCommand) createPolicy(selectedIgnore *database.Ignore, allIgnores []*database.Ignore) error {
	// Generate a unique internal ID
	internalID, err := generateInternalID()
	if err != nil {
		return fmt.Errorf("failed to generate internal ID: %w", err)
	}

	// Create policy description with details of all source ignores
	var sourceIgnoreIDs []string
	var ignoreDetails []string

	for _, ignore := range allIgnores {
		sourceIgnoreIDs = append(sourceIgnoreIDs, ignore.ID)

		// Mark if this is the selected ignore
		var selectedMarker string
		if ignore.ID == selectedIgnore.ID {
			selectedMarker = " (SELECTED)"

			// Mark this ignore as selected for migration in the ignores table
			_, err = c.db.Exec(`
				UPDATE ignores SET selected_for_migration = 1, internal_policy_id = ? 
				WHERE id = ?
			`, internalID, ignore.ID)

			if err != nil {
				return fmt.Errorf("failed to mark ignore as selected: %w", err)
			}
		} else {
			// Link non-selected ignores to the policy as well
			_, err = c.db.Exec(`
				UPDATE ignores SET internal_policy_id = ? 
				WHERE id = ?
			`, internalID, ignore.ID)

			if err != nil {
				return fmt.Errorf("failed to update ignore with policy reference: %w", err)
			}
		}

		detail := fmt.Sprintf("Ignore %s: type=%s, created=%s%s, reason=%s",
			ignore.ID,
			ignore.IgnoreType,
			ignore.CreatedAt.Format("2006-01-02"),
			selectedMarker,
			ignore.Reason)

		ignoreDetails = append(ignoreDetails, detail)
	}

	// Create enhanced reason with source information
	enhancedReason := selectedIgnore.Reason
	if enhancedReason == "" {
		enhancedReason = "Migrated from SAST ignore"
	}

	enhancedReason += "\n\nMigrated from the following ignores:\n" + strings.Join(ignoreDetails, "\n")

	// Create policy in database
	policy := &database.Policy{
		InternalID:    internalID,
		OrgID:         c.orgID,
		AssetKey:      selectedIgnore.AssetKey,
		PolicyType:    selectedIgnore.IgnoreType,
		Reason:        enhancedReason,
		ExpiresAt:     selectedIgnore.ExpiresAt,
		SourceIgnores: strings.Join(sourceIgnoreIDs, ","),
	}

	if err := c.db.InsertPolicy(policy); err != nil {
		return fmt.Errorf("failed to insert policy: %w", err)
	}

	log.Printf("Created policy plan for asset key %s with %d source ignores",
		selectedIgnore.AssetKey, len(allIgnores))

	return nil
}

// generateInternalID generates a unique internal ID for policies
func generateInternalID() (string, error) {
	bytes := make([]byte, 16)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return "policy-" + hex.EncodeToString(bytes), nil
}

// PrintPlan prints the contents of the plan
func (c *PlanCommand) PrintPlan() error {
	log.Printf("Printing migration plan for organization: %s", c.orgID)

	// Get all policies
	policies, err := c.db.GetPoliciesByOrgID(c.orgID)
	if err != nil {
		return fmt.Errorf("failed to get policies: %w", err)
	}

	log.Printf("Found %d policies in the plan:", len(policies))
	for i, policy := range policies {
		if i < 10 || len(policies) < 20 { // Print first 10 or all if less than 20
			ignoreCount := len(strings.Split(policy.SourceIgnores, ","))
			log.Printf("  Policy %d/%d: InternalID=%s, AssetKey=%s, Type=%s, Ignores=%d",
				i+1, len(policies), policy.InternalID, policy.AssetKey, policy.PolicyType, ignoreCount)
		} else if i == 10 {
			log.Printf("  ... and %d more policies", len(policies)-10)
			break
		}
	}

	// Get selected ignores
	countRows, err := c.db.Query(`
		SELECT COUNT(*) FROM ignores 
		WHERE org_id = ? AND selected_for_migration = 1
	`, c.orgID)
	if err != nil {
		return fmt.Errorf("failed to count selected ignores: %w", err)
	}

	sqlCountRows := countRows.(*sql.Rows)
	defer sqlCountRows.Close()

	var selectedCount int
	if sqlCountRows.Next() {
		if err := sqlCountRows.Scan(&selectedCount); err != nil {
			return fmt.Errorf("failed to scan selected count: %w", err)
		}
	}

	log.Printf("Selected %d ignores for migration", selectedCount)

	return nil
}
