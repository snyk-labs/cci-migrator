package commands

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/z4ce/cci-migrator/internal/database"
	"github.com/z4ce/cci-migrator/internal/snyk"
)

func TestCollectCommand(t *testing.T) {
	// Create a test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Logf("Received request for path: %s", r.URL.Path)
		t.Logf("Query parameters: %v", r.URL.Query())
		t.Logf("Headers: %v", r.Header)

		switch r.URL.Path {
		case "/org/test-org/project/test-project/ignores":
			// Verify v1 API auth header
			if r.Header.Get("Authorization") != "token test-token" {
				t.Errorf("Expected Authorization header 'token test-token', got %s", r.Header.Get("Authorization"))
				http.Error(w, "Invalid token", http.StatusUnauthorized)
				return
			}

			// Return test ignores
			ignores := []snyk.Ignore{
				{
					ID:         "test-id",
					IssueID:    "test-issue",
					Reason:     "test reason",
					ReasonType: "permanent",
					CreatedAt:  time.Now(),
					IgnoredBy: snyk.User{
						ID:    "user-id",
						Name:  "Test User",
						Email: "test@example.com",
					},
					Issue: snyk.Issue{
						ID:       "issue-id",
						Title:    "Test Issue",
						Type:     "sast",
						Package:  "test-package",
						Language: "go",
					},
				},
			}
			json.NewEncoder(w).Encode(ignores)

		case "/orgs/test-org/code_issue_details/test-issue":
			// Verify REST API headers
			if r.Header.Get("Authorization") != "Bearer test-token" {
				t.Errorf("Expected Authorization header 'Bearer test-token', got %s", r.Header.Get("Authorization"))
				http.Error(w, "Invalid token", http.StatusUnauthorized)
				return
			}
			if r.Header.Get("Accept") != "application/vnd.api+json" {
				t.Errorf("Expected Accept header 'application/vnd.api+json', got %s", r.Header.Get("Accept"))
				http.Error(w, "Invalid Accept header", http.StatusBadRequest)
				return
			}

			// Verify query parameters
			query := r.URL.Query()
			if query.Get("version") != "2024-10-14~experimental" {
				t.Errorf("Expected version 2024-10-14~experimental, got %s", query.Get("version"))
				http.Error(w, "Invalid version", http.StatusBadRequest)
				return
			}
			if query.Get("project_id") != "test-project" {
				t.Errorf("Expected project_id test-project, got %s", query.Get("project_id"))
				http.Error(w, "Invalid project_id", http.StatusBadRequest)
				return
			}

			// Return test code details
			details := snyk.CodeDetails{
				ID:          "test-fingerprint",
				Title:       "Test Issue",
				Severity:    "high",
				FilePath:    "src/main.go",
				LineNumber:  42,
				Description: "Test description",
				CWE:        "CWE-123",
				AdditionalFields: map[string]interface{}{
					"test": "value",
				},
			}
			json.NewEncoder(w).Encode(details)

		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	// Create a temporary database
	dbPath := "test.db"
	defer os.Remove(dbPath)

	// Initialize database
	db, err := database.New(dbPath)
	if err != nil {
		t.Fatalf("Failed to create database: %v", err)
	}
	defer db.Close()

	// Create Snyk client with test server
	client := &snyk.Client{
		HTTPClient: http.DefaultClient,
		Token:     "test-token",
		V1BaseURL: server.URL,
		RestBaseURL: server.URL,
	}

	// Create and execute collect command
	cmd := NewCollectCommand(db, client, "test-org")
	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	// Verify the data was collected correctly
	ignores, err := db.GetIgnoresByOrgID("test-org")
	if err != nil {
		t.Fatalf("Failed to get ignores: %v", err)
	}

	if len(ignores) != 1 {
		t.Fatalf("Expected 1 ignore, got %d", len(ignores))
	}

	ignore := ignores[0]
	if ignore.ID != "test-id" {
		t.Errorf("Expected ignore ID test-id, got %s", ignore.ID)
	}
	if ignore.IssueID != "test-issue" {
		t.Errorf("Expected issue ID test-issue, got %s", ignore.IssueID)
	}
	if ignore.Fingerprint != "test-fingerprint" {
		t.Errorf("Expected fingerprint test-fingerprint, got %s", ignore.Fingerprint)
	}

	// Verify collection metadata was updated
	var completedAt time.Time
	var version, storedAPIVersion string
	err = db.QueryRow("SELECT collection_completed_at, collection_version, api_version FROM collection_metadata LIMIT 1").
		Scan(&completedAt, &version, &storedAPIVersion)
	if err != nil {
		t.Fatalf("Failed to get collection metadata: %v", err)
	}

	if version != collectionVersion {
		t.Errorf("Expected version %s, got %s", collectionVersion, version)
	}
	if storedAPIVersion != apiVersion {
		t.Errorf("Expected API version %s, got %s", apiVersion, storedAPIVersion)
	}
} 