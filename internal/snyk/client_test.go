package snyk

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestGetIgnores(t *testing.T) {
	// Create a test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify request
		if r.Method != "GET" {
			t.Errorf("Expected GET request, got %s", r.Method)
		}
		if r.Header.Get("Authorization") != "token test-token" {
			t.Errorf("Expected Authorization header 'token test-token', got %s", r.Header.Get("Authorization"))
		}

		// Return test data
		ignores := []Ignore{
			{
				ID:         "test-id",
				IssueID:    "test-issue",
				Reason:     "test reason",
				ReasonType: "permanent",
				CreatedAt:  time.Now(),
				IgnoredBy: User{
					ID:    "user-id",
					Name:  "Test User",
					Email: "test@example.com",
				},
				Issue: Issue{
					ID:       "issue-id",
					Title:    "Test Issue",
					Type:     "sast",
					Package:  "test-package",
					Language: "go",
				},
			},
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(ignores)
	}))
	defer server.Close()

	// Create client with test server URL
	client := &Client{
		HTTPClient: http.DefaultClient,
		Token:     "test-token",
		V1BaseURL: server.URL,
	}

	// Test GetIgnores
	ignores, err := client.GetIgnores("test-org", "test-project")
	if err != nil {
		t.Fatalf("GetIgnores failed: %v", err)
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
}

func TestGetCodeDetails(t *testing.T) {
	// Create a test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify request
		if r.Method != "GET" {
			t.Errorf("Expected GET request, got %s", r.Method)
		}
		if r.Header.Get("Authorization") != "Bearer test-token" {
			t.Errorf("Expected Authorization header 'Bearer test-token', got %s", r.Header.Get("Authorization"))
		}
		if r.Header.Get("Accept") != "application/vnd.api+json" {
			t.Errorf("Expected Accept header 'application/vnd.api+json', got %s", r.Header.Get("Accept"))
		}

		// Check query parameters
		query := r.URL.Query()
		if query.Get("version") != "2024-10-14~experimental" {
			t.Errorf("Expected version 2024-10-14~experimental, got %s", query.Get("version"))
		}
		if query.Get("project_id") != "test-project" {
			t.Errorf("Expected project_id test-project, got %s", query.Get("project_id"))
		}

		// Return test data
		details := CodeDetails{
			ID:          "test-id",
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

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(details)
	}))
	defer server.Close()

	// Create client with test server URL
	client := &Client{
		HTTPClient: http.DefaultClient,
		Token:     "test-token",
		RestBaseURL: server.URL,
	}

	// Test GetCodeDetails
	details, err := client.GetCodeDetails("test-org", "test-project", "test-issue")
	if err != nil {
		t.Fatalf("GetCodeDetails failed: %v", err)
	}

	if details.ID != "test-id" {
		t.Errorf("Expected ID test-id, got %s", details.ID)
	}
	if details.Title != "Test Issue" {
		t.Errorf("Expected title Test Issue, got %s", details.Title)
	}
	if details.Severity != "high" {
		t.Errorf("Expected severity high, got %s", details.Severity)
	}
	if details.FilePath != "src/main.go" {
		t.Errorf("Expected file path src/main.go, got %s", details.FilePath)
	}
	if details.LineNumber != 42 {
		t.Errorf("Expected line number 42, got %d", details.LineNumber)
	}
}

func TestRateLimitHandling(t *testing.T) {
	// Create a test server that returns a rate limit response
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Retry-After", "60")
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer server.Close()

	// Create client with test server URL
	client := &Client{
		HTTPClient: http.DefaultClient,
		Token:     "test-token",
		RestBaseURL: server.URL,
	}

	// Test rate limit handling
	_, err := client.GetCodeDetails("test-org", "test-project", "test-issue")
	if err == nil {
		t.Fatal("Expected rate limit error, got nil")
	}

	rateLimitErr, ok := err.(*RateLimitError)
	if !ok {
		t.Fatalf("Expected RateLimitError, got %T", err)
	}

	expectedDuration := 60 * time.Second
	if rateLimitErr.RetryAfter != expectedDuration {
		t.Errorf("Expected retry after %v, got %v", expectedDuration, rateLimitErr.RetryAfter)
	}
} 