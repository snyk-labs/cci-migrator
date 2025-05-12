package commands

import (
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"time"
)

// BackupCommand handles database backup operations
type BackupCommand struct {
	db         DatabaseInterface
	dbPath     string
	backupPath string
}

// NewBackupCommand creates a new backup command
func NewBackupCommand(db DatabaseInterface, dbPath, backupPath string) *BackupCommand {
	return &BackupCommand{
		db:         db,
		dbPath:     dbPath,
		backupPath: backupPath,
	}
}

// Execute runs the backup command
func (c *BackupCommand) Execute() error {
	log.Printf("Starting database backup from %s", c.dbPath)

	// Ensure backup directory exists
	if err := os.MkdirAll(c.backupPath, 0755); err != nil {
		return fmt.Errorf("failed to create backup directory: %w", err)
	}

	// Generate backup filename with timestamp
	timestamp := time.Now().Format("20060102-150405")
	backupFile := filepath.Join(c.backupPath, fmt.Sprintf("cci-migration-%s.db", timestamp))

	log.Printf("Creating backup at: %s", backupFile)

	// Open source database file
	src, err := os.Open(c.dbPath)
	if err != nil {
		return fmt.Errorf("failed to open source database: %w", err)
	}
	defer src.Close()

	// Create destination backup file
	dst, err := os.Create(backupFile)
	if err != nil {
		return fmt.Errorf("failed to create backup file: %w", err)
	}
	defer dst.Close()

	// Copy database file to backup
	if _, err := io.Copy(dst, src); err != nil {
		return fmt.Errorf("failed to copy database to backup: %w", err)
	}

	log.Printf("Backup completed successfully: %s", backupFile)
	fmt.Printf("Backup created at: %s\n", backupFile)

	return nil
}

// RestoreCommand handles database restore operations
type RestoreCommand struct {
	db         DatabaseInterface
	dbPath     string
	backupPath string
	backupFile string
}

// NewRestoreCommand creates a new restore command
func NewRestoreCommand(db DatabaseInterface, dbPath, backupPath, backupFile string) *RestoreCommand {
	return &RestoreCommand{
		db:         db,
		dbPath:     dbPath,
		backupPath: backupPath,
		backupFile: backupFile,
	}
}

// Execute runs the restore command
func (c *RestoreCommand) Execute() error {
	// If no specific backup file is provided, find the latest
	sourceFile := c.backupFile
	if sourceFile == "" {
		var err error
		sourceFile, err = c.findLatestBackup()
		if err != nil {
			return err
		}
	} else if !filepath.IsAbs(sourceFile) {
		// If relative path, prepend backup directory
		sourceFile = filepath.Join(c.backupPath, sourceFile)
	}

	log.Printf("Restoring database from backup: %s", sourceFile)

	// Close database connection before restore
	if err := c.db.Close(); err != nil {
		log.Printf("Warning: failed to close database connection: %v", err)
	}

	// Create a backup of the current database before restoring
	currentBackup := fmt.Sprintf("%s.before-restore.%s", c.dbPath, time.Now().Format("20060102-150405"))
	log.Printf("Creating backup of current database at: %s", currentBackup)

	// Copy current database to backup
	if err := copyFile(c.dbPath, currentBackup); err != nil {
		return fmt.Errorf("failed to backup current database: %w", err)
	}

	// Copy backup file to database path
	if err := copyFile(sourceFile, c.dbPath); err != nil {
		return fmt.Errorf("failed to restore database: %w", err)
	}

	log.Printf("Database restored successfully from: %s", sourceFile)
	fmt.Printf("Database restored from: %s\n", sourceFile)
	fmt.Printf("Previous database backed up to: %s\n", currentBackup)

	return nil
}

// findLatestBackup finds the most recent backup file
func (c *RestoreCommand) findLatestBackup() (string, error) {
	files, err := os.ReadDir(c.backupPath)
	if err != nil {
		return "", fmt.Errorf("failed to read backup directory: %w", err)
	}

	var latest string
	var latestTime time.Time

	for _, file := range files {
		if file.IsDir() {
			continue
		}

		if filepath.Ext(file.Name()) == ".db" {
			info, err := file.Info()
			if err != nil {
				continue
			}

			if latest == "" || info.ModTime().After(latestTime) {
				latest = filepath.Join(c.backupPath, file.Name())
				latestTime = info.ModTime()
			}
		}
	}

	if latest == "" {
		return "", fmt.Errorf("no backup files found in %s", c.backupPath)
	}

	return latest, nil
}

// copyFile copies a file from src to dst
func copyFile(src, dst string) error {
	sourceFile, err := os.Open(src)
	if err != nil {
		return err
	}
	defer sourceFile.Close()

	destFile, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer destFile.Close()

	_, err = io.Copy(destFile, sourceFile)
	return err
}
