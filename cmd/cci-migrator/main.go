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
		apiToken    string
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
	globalFlags.StringVar(&apiToken, "api-token", "", "Snyk API Token")
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
	if orgID == "" {
		log.Fatal("org-id is required")
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
	client := snyk.New(apiToken, debug)

	// Execute the appropriate command
	switch command {
	case "gather":
		cmd := commands.NewGatherCommand(db, client, orgID)
		if err := cmd.Execute(); err != nil {
			log.Fatalf("Gather failed: %v", err)
		}
	case "verify":
		cmd := commands.NewVerifyCommand(db, client, orgID)
		if err := cmd.Execute(); err != nil {
			log.Fatalf("Verification failed: %v", err)
		}
	case "print":
		cmd := commands.NewGatherCommand(db, client, orgID)
		if err := cmd.Print(); err != nil {
			log.Fatalf("Print failed: %v", err)
		}
	case "backup":
		cmd := commands.NewBackupCommand(db, dbPath, backupPath)
		if err := cmd.Execute(); err != nil {
			log.Fatalf("Backup failed: %v", err)
		}
	case "restore":
		cmd := commands.NewRestoreCommand(db, dbPath, backupPath, backupFile)
		if err := cmd.Execute(); err != nil {
			log.Fatalf("Restore failed: %v", err)
		}
	case "plan":
		cmd := commands.NewPlanCommand(db, client, orgID)
		if err := cmd.Execute(); err != nil {
			log.Fatalf("Plan failed: %v", err)
		}
	case "print-plan":
		cmd := commands.NewPlanCommand(db, client, orgID)
		if err := cmd.PrintPlan(); err != nil {
			log.Fatalf("Print plan failed: %v", err)
		}
	case "execute":
		cmd := commands.NewExecuteCommand(db, client, orgID)
		if err := cmd.Execute(); err != nil {
			log.Fatalf("Execute failed: %v", err)
		}
	case "retest":
		cmd := commands.NewRetestCommand(db, client, orgID)
		if err := cmd.Execute(); err != nil {
			log.Fatalf("Retest failed: %v", err)
		}
	case "cleanup":
		cmd := commands.NewCleanupCommand(db, client, orgID)
		if err := cmd.Execute(); err != nil {
			log.Fatalf("Cleanup failed: %v", err)
		}
	case "status":
		cmd := commands.NewStatusCommand(db, orgID)
		if err := cmd.Execute(); err != nil {
			log.Fatalf("Status check failed: %v", err)
		}
	case "rollback":
		cmd := commands.NewRollbackCommand(db, client, orgID)
		if err := cmd.Execute(); err != nil {
			log.Fatalf("Rollback failed: %v", err)
		}
	default:
		fmt.Printf("Unknown command: %s\n", command)
		printUsage()
		os.Exit(1)
	}
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
  --org-id          Snyk Organization ID
  --api-token       Snyk API Token
  --db-path         Path to SQLite database (default: ./cci-migration.db)
  --backup-path     Path to backup directory (default: ./backups)
  --project-type    Project type to migrate (default: sast, only sast supported currently)
  --strategy        Conflict resolution strategy (default: priority-earliest)
  --override-csv    Path to CSV with manual override mappings
  --backup-file     Specific backup file to restore (for restore command)
  --debug           Enable debug output of HTTP requests and responses`)
}
