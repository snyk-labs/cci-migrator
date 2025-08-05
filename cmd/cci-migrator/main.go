package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/z4ce/cci-migrator/internal/commands"
	"github.com/z4ce/cci-migrator/internal/database"
	"github.com/z4ce/cci-migrator/internal/snyk"
)

func main() {
	// Create flag sets for global flags
	globalFlags := flag.NewFlagSet("cci-migrator", flag.ExitOnError)

	var (
		orgID       string
		groupID     string
		apiToken    string
		apiEndpoint string
		dbPath      string
		backupPath  string
		projectType string
		strategy    string
		overrideCsv string
		backupFile  string
		debug       bool
	)

	// Set up global flags
	globalFlags.StringVar(&orgID, "org-id", "", "Snyk Organization ID")
	globalFlags.StringVar(&groupID, "group-id", "", "Snyk Group ID (runs command for all orgs in group)")
	globalFlags.StringVar(&apiToken, "api-token", "", "Snyk API Token")
	globalFlags.StringVar(&apiEndpoint, "api-endpoint", "api.snyk.io", "Snyk API endpoint (default: api.snyk.io)")
	globalFlags.StringVar(&dbPath, "db-path", "./cci-migration.db", "Path to SQLite database")
	globalFlags.StringVar(&backupPath, "backup-path", "./backups", "Path to backup directory")
	globalFlags.StringVar(&projectType, "project-type", "sast", "Project type to migrate (only sast supported currently)")
	globalFlags.StringVar(&strategy, "strategy", "priority-earliest", "Conflict resolution strategy")
	globalFlags.StringVar(&overrideCsv, "override-csv", "", "Path to CSV with manual override mappings")
	globalFlags.StringVar(&backupFile, "backup-file", "", "Specific backup file to restore (for restore command)")
	globalFlags.BoolVar(&debug, "debug", false, "Enable debug output of HTTP requests and responses")

	// Check if we have any arguments
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	// Get the subcommand
	command := os.Args[1]

	// Parse the remaining arguments
	if err := globalFlags.Parse(os.Args[2:]); err != nil {
		log.Fatal(err)
	}

	// Validate required flags
	if orgID == "" && groupID == "" {
		log.Fatal("either org-id or group-id is required")
	}
	if orgID != "" && groupID != "" {
		log.Fatal("cannot specify both org-id and group-id")
	}
	if apiToken == "" {
		log.Fatal("api-token is required")
	}

	// Initialize database
	db, err := database.New(dbPath)
	if err != nil {
		log.Fatalf("Failed to initialize database: %v", err)
	}
	defer db.Close()

	// Initialize Snyk client
	client := snyk.New(apiToken, apiEndpoint, debug)

	// Check if this is a database-level command that doesn't need org processing
	databaseLevelCommands := map[string]bool{
		"backup":  true,
		"restore": true,
	}

	// For database-level commands, we don't need to fetch organizations
	if databaseLevelCommands[command] {
		if groupID != "" {
			fmt.Printf("Note: '%s' command affects the entire database, group-id parameter is ignored\n", command)
		}
		// Use orgID if provided, otherwise use empty string (not needed for database commands)
		commandOrgID := orgID
		if err := executeCommand(command, db, client, commandOrgID, "", dbPath, backupPath, backupFile, debug); err != nil {
			log.Fatalf("Command '%s' failed: %v", command, err)
		}
		return
	}

	// Handle gather command differently - it's the only one that fetches organizations from API
	if command == "gather" {
		if err := executeCommand(command, db, client, orgID, groupID, dbPath, backupPath, backupFile, debug); err != nil {
			log.Fatalf("Command '%s' failed: %v", command, err)
		}
		return
	}

	// For non-gather commands, get organization IDs from database
	var orgIDs []string
	if groupID != "" {
		orgs, err := db.GetOrganizationsByGroupID(groupID)
		if err != nil {
			log.Fatalf("Failed to get organizations for group %s from database: %v", groupID, err)
		}
		for _, org := range orgs {
			orgIDs = append(orgIDs, org.ID)
		}
		if len(orgIDs) == 0 {
			log.Fatalf("No organizations found in database for group %s. Run 'gather' command first.", groupID)
		}
		fmt.Printf("Found %d organizations in database for group %s\n", len(orgIDs), groupID)
	} else {
		orgIDs = []string{orgID}
	}

	// Execute organization-level commands for each org
	for i, currentOrgID := range orgIDs {
		if len(orgIDs) > 1 {
			fmt.Printf("\n=== Processing organization %d/%d: %s ===\n", i+1, len(orgIDs), currentOrgID)
		}

		if err := executeCommand(command, db, client, currentOrgID, "", dbPath, backupPath, backupFile, debug); err != nil {
			log.Fatalf("Command '%s' failed for org %s: %v", command, currentOrgID, err)
		}
	}
}

func executeCommand(command string, db *database.DB, client *snyk.Client, orgID, groupID, dbPath, backupPath, backupFile string, debug bool) error {
	// Execute the appropriate command
	switch command {
	case "gather":
		cmd := commands.NewGatherCommand(db, client, orgID, groupID, debug)
		if err := cmd.Execute(); err != nil {
			return fmt.Errorf("Gather failed: %v", err)
		}
	case "verify":
		cmd := commands.NewVerifyCommand(db, client, orgID, debug)
		if err := cmd.Execute(); err != nil {
			return fmt.Errorf("Verification failed: %v", err)
		}
	case "print":
		cmd := commands.NewGatherCommand(db, client, orgID, groupID, debug)
		if err := cmd.Print(); err != nil {
			return fmt.Errorf("Print failed: %v", err)
		}
	case "backup":
		cmd := commands.NewBackupCommand(db, dbPath, backupPath, debug)
		if err := cmd.Execute(); err != nil {
			return fmt.Errorf("Backup failed: %v", err)
		}
	case "restore":
		cmd := commands.NewRestoreCommand(db, dbPath, backupPath, backupFile, debug)
		if err := cmd.Execute(); err != nil {
			return fmt.Errorf("Restore failed: %v", err)
		}
	case "plan":
		cmd := commands.NewPlanCommand(db, client, orgID, debug)
		if err := cmd.Execute(); err != nil {
			return fmt.Errorf("Plan failed: %v", err)
		}
	case "print-plan":
		cmd := commands.NewPlanCommand(db, client, orgID, debug)
		if err := cmd.PrintPlan(); err != nil {
			return fmt.Errorf("Print plan failed: %v", err)
		}
	case "execute":
		cmd := commands.NewExecuteCommand(db, client, orgID, debug)
		if err := cmd.Execute(); err != nil {
			return fmt.Errorf("Execute failed: %v", err)
		}
	case "retest":
		cmd := commands.NewRetestCommand(db, client, orgID, debug)
		if err := cmd.Execute(); err != nil {
			return fmt.Errorf("Retest failed: %v", err)
		}
	case "cleanup":
		cmd := commands.NewCleanupCommand(db, client, orgID, debug)
		if err := cmd.Execute(); err != nil {
			return fmt.Errorf("Cleanup failed: %v", err)
		}
	case "status":
		cmd := commands.NewStatusCommand(db, orgID, debug)
		if err := cmd.Execute(); err != nil {
			return fmt.Errorf("Status check failed: %v", err)
		}
	case "rollback":
		cmd := commands.NewRollbackCommand(db, client, orgID, debug)
		if err := cmd.Execute(); err != nil {
			return fmt.Errorf("Rollback failed: %v", err)
		}
	default:
		return fmt.Errorf("Unknown command: %s", command)
	}
	return nil
}

func printUsage() {
	fmt.Println(`Usage: cci-migrator [command] [options]

Commands:
  gather      Collect and store existing ignores, issues, and projects
  verify      Verify collection completeness
  print       Display gathered information (ignores, issues, projects)
  backup      Create backup of collection database
  restore     Restore from backup
  plan        Create migration plan and resolve conflicts
  print-plan  Display the migration plan
  execute     Create new policies based on plan
  retest      Retest projects with changes
  cleanup     Delete existing ignores
  status      Show migration status
  rollback    Attempt to rollback migration

Global Options:
  --org-id          Snyk Organization ID (required if --group-id not specified)
  --group-id        Snyk Group ID (runs command for all orgs in group, mutually exclusive with --org-id)
  --api-token       Snyk API Token (required)
  --api-endpoint    Snyk API endpoint (default: api.snyk.io)
  --db-path         Path to SQLite database (default: ./cci-migration.db)
  --backup-path     Path to backup directory (default: ./backups)
  --project-type    Project type to migrate (default: sast, only sast supported currently)
  --strategy        Conflict resolution strategy (default: priority-earliest)
  --override-csv    Path to CSV with manual override mappings
  --backup-file     Specific backup file to restore (for restore command)
  --debug           Enable debug output of HTTP requests and responses`)
}
