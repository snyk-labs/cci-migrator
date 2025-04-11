package snyk

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// Client represents a Snyk API client
type Client struct {
	HTTPClient  *http.Client
	Token       string
	V1BaseURL   string
	RestBaseURL string
}

// New creates a new Snyk API client
func New(token string) *Client {
	return &Client{
		HTTPClient: &http.Client{
			Timeout: time.Second * 30,
		},
		Token:       token,
		V1BaseURL:   "https://api.snyk.io/v1",
		RestBaseURL: "https://api.snyk.io/rest",
	}
}

// Ignore represents a Snyk ignore
type Ignore struct {
	ID         string     `json:"id"`
	IssueID    string     `json:"issueId"`
	Reason     string     `json:"reason"`
	ReasonType string     `json:"reasonType"`
	CreatedAt  time.Time  `json:"created"`
	ExpiresAt  *time.Time `json:"expires,omitempty"`
	IgnoredBy  User       `json:"ignoredBy"`
	Issue      Issue      `json:"issue"`
}

// User represents a Snyk user
type User struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	Email string `json:"email"`
}

// Issue represents a Snyk issue
type Issue struct {
	ID       string `json:"id"`
	Title    string `json:"title"`
	Type     string `json:"type"`
	Package  string `json:"package"`
	Language string `json:"language"`
}

// CodeDetails represents the response from the code issue details API
type CodeDetails struct {
	ID               string                 `json:"id"`
	Title            string                 `json:"title"`
	Severity         string                 `json:"severity"`
	FilePath         string                 `json:"filePath"`
	LineNumber       int                    `json:"lineNumber"`
	Description      string                 `json:"description"`
	CWE              string                 `json:"cwe"`
	AdditionalFields map[string]interface{} `json:"additionalFields"`
}

// RateLimitError represents a rate limit error from the Snyk API
type RateLimitError struct {
	RetryAfter time.Duration
	Message    string
}

func (e *RateLimitError) Error() string {
	return fmt.Sprintf("rate limit exceeded: %s, retry after %v", e.Message, e.RetryAfter)
}

// handleResponse checks for rate limits and other common API response issues
func (c *Client) handleResponse(resp *http.Response) error {
	if resp.StatusCode == http.StatusTooManyRequests {
		retryAfter := resp.Header.Get("Retry-After")
		seconds, err := time.ParseDuration(retryAfter + "s")
		if err != nil {
			seconds = 60 * time.Second // default to 60 seconds if header is missing or invalid
		}
		return &RateLimitError{
			RetryAfter: seconds,
			Message:    "API rate limit exceeded",
		}
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status code: %d for URL: %s", resp.StatusCode, resp.Request.URL)
	}

	return nil
}

// IgnoresResponse represents the response from the ignores API
type IgnoresResponse struct {
	Ignores map[string]Ignore `json:""`
}

// GetIgnores retrieves all ignores for a given organization and project
func (c *Client) GetIgnores(orgID, projectID string) ([]Ignore, error) {
	url := fmt.Sprintf("%s/org/%s/project/%s/ignores", c.V1BaseURL, orgID, projectID)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "token "+c.Token)

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to execute request: %w", err)
	}
	defer resp.Body.Close()

	if err := c.handleResponse(resp); err != nil {
		return nil, err
	}

	var response IgnoresResponse
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	// Convert map of ignores to slice
	ignores := make([]Ignore, 0, len(response.Ignores))
	for id, ignore := range response.Ignores {
		ignore.ID = id // Ensure the ID is set from the map key
		ignores = append(ignores, ignore)
	}

	return ignores, nil
}

// GetCodeDetails retrieves code issue details for a given issue
func (c *Client) GetCodeDetails(orgID, projectID, issueID string) (*CodeDetails, error) {
	baseURL := fmt.Sprintf("%s/orgs/%s/code_issue_details/%s", c.RestBaseURL, orgID, issueID)

	// Create URL with query parameters
	url := fmt.Sprintf("%s?version=2024-10-14~experimental&project_id=%s", baseURL, projectID)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+c.Token)
	req.Header.Set("Accept", "application/vnd.api+json")

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to execute request: %w", err)
	}
	defer resp.Body.Close()

	if err := c.handleResponse(resp); err != nil {
		return nil, err
	}

	var details CodeDetails
	if err := json.NewDecoder(resp.Body).Decode(&details); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return &details, nil
}

// Project represents a Snyk project from the REST API
type Project struct {
	ID                  string    `json:"id"`
	Name                string    `json:"name"`
	Created             time.Time `json:"created"`
	Origin              string    `json:"origin"`
	Type                string    `json:"type"`
	Status              string    `json:"status"`
	BusinessCriticality []string  `json:"businessCriticality"`
	Environment         []string  `json:"environment"`
	Lifecycle           []string  `json:"lifecycle"`
	Tags                []struct {
		Key   string `json:"key"`
		Value string `json:"value"`
	} `json:"tags"`
}

// ProjectsResponse represents the JSON:API response for projects
type ProjectsResponse struct {
	Data []struct {
		ID         string  `json:"id"`
		Type       string  `json:"type"`
		Attributes Project `json:"attributes"`
	} `json:"data"`
}

// GetProjects retrieves all projects for a given organization using the REST API
func (c *Client) GetProjects(orgID string) ([]Project, error) {
	url := fmt.Sprintf("%s/orgs/%s/projects?version=2024-10-14~experimental&types=sast", c.RestBaseURL, orgID)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "token "+c.Token)
	req.Header.Set("Accept", "application/vnd.api+json")

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to execute request: %w", err)
	}
	defer resp.Body.Close()

	if err := c.handleResponse(resp); err != nil {
		return nil, err
	}

	var response ProjectsResponse
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	projects := make([]Project, len(response.Data))
	for i, item := range response.Data {
		projects[i] = item.Attributes
		projects[i].ID = item.ID // Ensure ID is set from the data object
	}

	return projects, nil
}
