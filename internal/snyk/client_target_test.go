package snyk

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestGetProjectTarget(t *testing.T) {
	orgID := "org123"
	targetID := "target789"

	// ---------------------------------------------------------------------
	// Spin up a test HTTP server that mimics the two REST API endpoints that
	// GetProjectTarget interacts with.
	// ---------------------------------------------------------------------
	handler := http.NewServeMux()

	// Endpoint: /rest/orgs/{orgID}/targets/{targetID}
	handler.HandleFunc("/rest/orgs/"+orgID+"/targets/"+targetID, func(w http.ResponseWriter, r *http.Request) {
		resp := map[string]any{
			"data": map[string]any{
				"id":   targetID,
				"type": "target",
				"attributes": map[string]any{
					"created_at":   time.Date(2022, 9, 1, 0, 0, 0, 0, time.UTC).Format(time.RFC3339),
					"display_name": "owner/repo",
					"is_private":   false,
					"url":          "http://github.com/owner/repo",
				},
			},
		}
		_ = json.NewEncoder(w).Encode(resp)
	})

	server := httptest.NewServer(handler)
	defer server.Close()

	// ---------------------------------------------------------------------
	// Exercise GetProjectTarget with the test server
	// ---------------------------------------------------------------------
	client := New("", "api.snyk.io", false)
	client.RestBaseURL = server.URL + "/rest"

	tgt, err := client.GetProjectTarget(orgID, targetID)
	if err != nil {
		t.Fatalf("GetProjectTarget returned error: %v", err)
	}

	if tgt == nil {
		t.Fatalf("expected target, got nil")
	}

	if tgt.ID != targetID {
		t.Errorf("expected target ID %s, got %s", targetID, tgt.ID)
	}

	if tgt.Owner != "owner" {
		t.Errorf("expected owner 'owner', got %s", tgt.Owner)
	}

	if tgt.Repo != "repo" {
		t.Errorf("expected repo 'repo', got %s", tgt.Repo)
	}

	if tgt.URL != "http://github.com/owner/repo" {
		t.Errorf("unexpected target URL: %s", tgt.URL)
	}

	if tgt.DisplayName != "owner/repo" {
		t.Errorf("unexpected display_name: %s", tgt.DisplayName)
	}
}
