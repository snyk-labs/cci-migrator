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
		orgID      string
		apiToken   string
		dbPath     string
		backupPath string
	)

	// Set up global flags
	globalFlags.StringVar(&orgID, "org-id", "", "Snyk Organization ID")
	globalFlags.StringVar(&apiToken, "api-token", "", "Snyk API Token")
	globalFlags.StringVar(&dbPath, "db-path", "./cci-migration.db", "Path to SQLite database")
	globalFlags.StringVar(&backupPath, "backup-path", "./backups", "Path to backup directory")

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
	client := snyk.New(apiToken)

	// Execute the appropriate command
	switch command {
	case "collect":
		cmd := commands.NewCollectCommand(db, client, orgID)
		if err := cmd.Execute(); err != nil {
			log.Fatalf("Collection failed: %v", err)
		}
	case "verify":
		fmt.Println("Starting verification...")
		// TODO: Implement verification
	case "backup":
		fmt.Println("Creating backup...")
		// TODO: Implement backup
	case "restore":
		fmt.Println("Restoring from backup...")
		// TODO: Implement restore
	case "analyze":
		fmt.Println("Starting SARIF analysis...")
		// TODO: Implement analysis
	case "delete":
		fmt.Println("Starting delete operation...")
		// TODO: Implement delete
	case "migrate":
		fmt.Println("Starting migration...")
		// TODO: Implement migration
	case "status":
		fmt.Println("Checking status...")
		// TODO: Implement status check
	case "rollback":
		fmt.Println("Starting rollback...")
		// TODO: Implement rollback
	default:
		fmt.Printf("Unknown command: %s\n", command)
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println(`Usage: cci-migrator [command] [options]

Commands:
  collect     Collect and store existing ignores
  verify      Verify collection completeness
  backup      Create backup of collection database
  restore     Restore from backup
  analyze     Get SARIF data and match findings
  delete      Delete existing ignores (idempotent)
  migrate     Perform the migration (idempotent)
  status      Show migration status
  rollback    Attempt to rollback migration

Global Options:
  --org-id          Snyk Organization ID
  --api-token       Snyk API Token
  --db-path         Path to SQLite database (default: ./cci-migration.db)
  --backup-path     Path to backup directory (default: ./backups)`)
} 