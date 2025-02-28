package database

import (
	"os"
	"testing"
	"time"
)

func TestDatabase(t *testing.T) {
	// Create a temporary database file
	dbPath := "test.db"
	defer os.Remove(dbPath)

	// Initialize database
	db, err := New(dbPath)
	if err != nil {
		t.Fatalf("Failed to create database: %v", err)
	}
	defer db.Close()

	// Test inserting and retrieving an ignore
	testIgnore := &Ignore{
		ID:          "test-id",
		IssueID:     "test-issue",
		OrgID:       "test-org",
		ProjectID:   "test-project",
		Reason:      "test reason",
		IgnoreType:  "permanent",
		CreatedAt:   time.Now(),
		Fingerprint: "test-fingerprint",
	}

	// Test InsertIgnore
	if err := db.InsertIgnore(testIgnore); err != nil {
		t.Fatalf("Failed to insert ignore: %v", err)
	}

	// Test GetIgnoresByOrgID
	ignores, err := db.GetIgnoresByOrgID(testIgnore.OrgID)
	if err != nil {
		t.Fatalf("Failed to get ignores: %v", err)
	}

	if len(ignores) != 1 {
		t.Fatalf("Expected 1 ignore, got %d", len(ignores))
	}

	ignore := ignores[0]
	if ignore.ID != testIgnore.ID {
		t.Errorf("Expected ignore ID %s, got %s", testIgnore.ID, ignore.ID)
	}
	if ignore.IssueID != testIgnore.IssueID {
		t.Errorf("Expected issue ID %s, got %s", testIgnore.IssueID, ignore.IssueID)
	}

	// Test UpdateCollectionMetadata
	now := time.Now()
	if err := db.UpdateCollectionMetadata(now, "1.0.0", "v1"); err != nil {
		t.Fatalf("Failed to update collection metadata: %v", err)
	}

	// Verify collection metadata
	var completedAt time.Time
	var version, apiVersion string
	err = db.QueryRow("SELECT collection_completed_at, collection_version, api_version FROM collection_metadata LIMIT 1").
		Scan(&completedAt, &version, &apiVersion)
	if err != nil {
		t.Fatalf("Failed to get collection metadata: %v", err)
	}

	if version != "1.0.0" {
		t.Errorf("Expected version 1.0.0, got %s", version)
	}
	if apiVersion != "v1" {
		t.Errorf("Expected API version v1, got %s", apiVersion)
	}
} 