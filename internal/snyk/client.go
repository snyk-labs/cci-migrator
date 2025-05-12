package snyk

import (
	"bytes"
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

// SASTIssue represents a SAST issue from the Issues API
type SASTIssue struct {
	ID             string                 `json:"id"`
	IssueType      string                 `json:"issueType"`
	PkgName        string                 `json:"pkgName"`
	PkgVersions    []string               `json:"pkgVersions"`
	IssueData      map[string]interface{} `json:"issueData"`
	AssetKey       string                 `json:"assetKey"`
	FilePath       string                 `json:"filePath"`
	LineNumber     int                    `json:"lineNumber"`
	Priority       string                 `json:"priority"`
	ProjectID      string                 `json:"projectId"`
	IsFixed        bool                   `json:"isFixed"`
	IsPatched      bool                   `json:"isPatched"`
	IsIgnored      bool                   `json:"isIgnored"`
	IgnoreReasons  []string               `json:"ignoreReasons"`
	FixInfo        map[string]interface{} `json:"fixInfo"`
	Introduction   string                 `json:"introduction"`
	OriginalStatus string                 `json:"originalStatus"`
	ProjectName    string                 `json:"projectName"`
}

// Target represents information about a project's target
type Target struct {
	Name    string                 `json:"name"`
	Branch  string                 `json:"branch"`
	Owner   string                 `json:"owner"`
	Repo    string                 `json:"repo"`
	URL     string                 `json:"url"`
	Origin  string                 `json:"origin"`
	Source  string                 `json:"source"`
	Options map[string]interface{} `json:"options"`
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
	fmt.Printf("Making request to get ignores: %s\n", url)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "token "+c.Token)
	fmt.Printf("Authorization header set: %s\n", "token "+c.Token[:5]+"...")

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to execute request: %w", err)
	}
	defer resp.Body.Close()

	fmt.Printf("Response status code: %d\n", resp.StatusCode)
	fmt.Printf("Response headers: %v\n", resp.Header)

	if err := c.handleResponse(resp); err != nil {
		return nil, err
	}

	var response IgnoresResponse
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	fmt.Printf("Decoded ignores response with %d ignores\n", len(response.Ignores))

	// Convert map of ignores to slice
	ignores := make([]Ignore, 0, len(response.Ignores))
	for id, ignore := range response.Ignores {
		ignore.ID = id // Ensure the ID is set from the map key
		ignores = append(ignores, ignore)
		fmt.Printf("Added ignore with ID: %s, IssueID: %s\n", id, ignore.IssueID)
	}

	return ignores, nil
}

// GetSASTIssues retrieves SAST issues for a given organization and project
func (c *Client) GetSASTIssues(orgID, projectID string) ([]SASTIssue, error) {
	url := fmt.Sprintf("%s/orgs/%s/issues?version=2023-09-14~experimental&project_id=%s&type=code", c.RestBaseURL, orgID, projectID)

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

	// Parse JSON:API response
	type IssueData struct {
		ID         string    `json:"id"`
		Type       string    `json:"type"`
		Attributes SASTIssue `json:"attributes"`
	}

	type Response struct {
		Data []IssueData `json:"data"`
	}

	var response Response
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	issues := make([]SASTIssue, len(response.Data))
	for i, item := range response.Data {
		issues[i] = item.Attributes
		issues[i].ID = item.ID // Ensure ID is set from the data object
	}

	return issues, nil
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
	Target Target `json:"target,omitempty"`
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
	url := fmt.Sprintf("%s/orgs/%s/projects?version=2023-09-14~experimental&types=sast&limit=100", c.RestBaseURL, orgID)

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

// GetProjectTarget retrieves target information for a given project
func (c *Client) GetProjectTarget(orgID, projectID string) (*Target, error) {
	url := fmt.Sprintf("%s/orgs/%s/projects/%s?version=2023-09-14~experimental", c.RestBaseURL, orgID, projectID)

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

	type ProjectData struct {
		ID         string  `json:"id"`
		Type       string  `json:"type"`
		Attributes Project `json:"attributes"`
	}

	type Response struct {
		Data ProjectData `json:"data"`
	}

	var response Response
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return &response.Data.Attributes.Target, nil
}

// RetestProject initiates a retest for a given project (can't affect API behavior)
func (c *Client) RetestProject(orgID, projectID string, target *Target) error {
	url := fmt.Sprintf("%s/org/%s/integrations/imports", c.V1BaseURL, orgID)

	// Create import payload based on target information
	type ImportPayload struct {
		Target Target `json:"target"`
	}

	payload := ImportPayload{
		Target: *target,
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal import payload: %w", err)
	}

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(body))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "token "+c.Token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to execute request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusAccepted {
		return fmt.Errorf("unexpected status code: %d for URL: %s", resp.StatusCode, resp.Request.URL)
	}

	return nil
}

// DeleteIgnore deletes an ignore
func (c *Client) DeleteIgnore(orgID, projectID, ignoreID string) error {
	url := fmt.Sprintf("%s/org/%s/project/%s/ignore/%s", c.V1BaseURL, orgID, projectID, ignoreID)

	req, err := http.NewRequest("DELETE", url, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "token "+c.Token)

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to execute request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("unexpected status code: %d for URL: %s", resp.StatusCode, resp.Request.URL)
	}

	return nil
}

// Policy represents a Snyk policy from the REST API
type Policy struct {
	ID         string     `json:"id"`
	Type       string     `json:"type"`
	AssetKey   string     `json:"assetKey"`
	Reason     string     `json:"reason"`
	ExpiresAt  *time.Time `json:"expiresAt,omitempty"`
	CreatedAt  time.Time  `json:"createdAt"`
	CreatedBy  string     `json:"createdBy"`
	ModifiedAt *time.Time `json:"modifiedAt,omitempty"`
	ModifiedBy *string    `json:"modifiedBy,omitempty"`
}

// PolicyResponse represents a policy in the JSON:API response format
type PolicyResponse struct {
	ID         string `json:"id"`
	Type       string `json:"type"`
	Attributes Policy `json:"attributes"`
}

// PoliciesResponse represents the JSON:API response for policies
type PoliciesResponse struct {
	Data  []PolicyResponse `json:"data"`
	Links struct {
		Self  string `json:"self"`
		First string `json:"first,omitempty"`
		Last  string `json:"last,omitempty"`
		Next  string `json:"next,omitempty"`
		Prev  string `json:"prev,omitempty"`
	} `json:"links,omitempty"`
}

// CreatePolicyPayload represents the payload for creating a new policy
type CreatePolicyPayload struct {
	Data struct {
		Type       string `json:"type"`
		Attributes struct {
			Type      string     `json:"type"`
			AssetKey  string     `json:"assetKey"`
			Reason    string     `json:"reason"`
			ExpiresAt *time.Time `json:"expiresAt,omitempty"`
		} `json:"attributes"`
	} `json:"data"`
}

// UpdatePolicyPayload represents the payload for updating a policy
type UpdatePolicyPayload struct {
	Data struct {
		Type       string `json:"type"`
		ID         string `json:"id"`
		Attributes struct {
			Reason    string     `json:"reason,omitempty"`
			ExpiresAt *time.Time `json:"expiresAt,omitempty"`
		} `json:"attributes"`
	} `json:"data"`
}

// GetPolicies retrieves all policies for a given organization
func (c *Client) GetPolicies(orgID string, options map[string]string) ([]Policy, error) {
	url := fmt.Sprintf("%s/orgs/%s/policies?version=2024-10-15", c.RestBaseURL, orgID)

	// Add query parameters from options
	if options != nil && len(options) > 0 {
		query := ""
		for key, value := range options {
			if query == "" {
				query = fmt.Sprintf("&%s=%s", key, value)
			} else {
				query = fmt.Sprintf("%s&%s=%s", query, key, value)
			}
		}
		url += query
	}

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

	var response PoliciesResponse
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	policies := make([]Policy, len(response.Data))
	for i, item := range response.Data {
		policies[i] = item.Attributes
		policies[i].ID = item.ID // Ensure ID is set from the data object
	}

	return policies, nil
}

// GetPolicy retrieves a specific policy by ID
func (c *Client) GetPolicy(orgID, policyID string) (*Policy, error) {
	url := fmt.Sprintf("%s/orgs/%s/policies/%s?version=2024-10-15", c.RestBaseURL, orgID, policyID)

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

	var response struct {
		Data PolicyResponse `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	policy := response.Data.Attributes
	policy.ID = response.Data.ID

	return &policy, nil
}

// CreatePolicy creates a new policy using the Policy API
func (c *Client) CreatePolicy(orgID string, policyType string, assetKey string, reason string, expiresAt *time.Time) (string, error) {
	url := fmt.Sprintf("%s/orgs/%s/policies?version=2024-10-15", c.RestBaseURL, orgID)

	payload := CreatePolicyPayload{}
	payload.Data.Type = "policy"
	payload.Data.Attributes.Type = policyType
	payload.Data.Attributes.AssetKey = assetKey
	payload.Data.Attributes.Reason = reason
	payload.Data.Attributes.ExpiresAt = expiresAt

	body, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("failed to marshal policy payload: %w", err)
	}

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(body))
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "token "+c.Token)
	req.Header.Set("Content-Type", "application/vnd.api+json")
	req.Header.Set("Accept", "application/vnd.api+json")

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to execute request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		return "", fmt.Errorf("unexpected status code: %d for URL: %s", resp.StatusCode, resp.Request.URL)
	}

	var response struct {
		Data struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return "", fmt.Errorf("failed to decode response: %w", err)
	}

	return response.Data.ID, nil
}

// UpdatePolicy updates an existing policy
func (c *Client) UpdatePolicy(orgID string, policyID string, reason string, expiresAt *time.Time) (*Policy, error) {
	url := fmt.Sprintf("%s/orgs/%s/policies/%s?version=2024-10-15", c.RestBaseURL, orgID, policyID)

	payload := UpdatePolicyPayload{}
	payload.Data.Type = "policy"
	payload.Data.ID = policyID
	payload.Data.Attributes.Reason = reason
	payload.Data.Attributes.ExpiresAt = expiresAt

	body, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal policy payload: %w", err)
	}

	req, err := http.NewRequest("PATCH", url, bytes.NewBuffer(body))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "token "+c.Token)
	req.Header.Set("Content-Type", "application/vnd.api+json")
	req.Header.Set("Accept", "application/vnd.api+json")

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to execute request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d for URL: %s", resp.StatusCode, resp.Request.URL)
	}

	var response struct {
		Data PolicyResponse `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	policy := response.Data.Attributes
	policy.ID = response.Data.ID

	return &policy, nil
}

// DeletePolicy deletes a policy
func (c *Client) DeletePolicy(orgID string, policyID string) error {
	url := fmt.Sprintf("%s/orgs/%s/policies/%s?version=2024-10-15", c.RestBaseURL, orgID, policyID)

	req, err := http.NewRequest("DELETE", url, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "token "+c.Token)
	req.Header.Set("Accept", "application/vnd.api+json")

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to execute request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("unexpected status code: %d for URL: %s", resp.StatusCode, resp.Request.URL)
	}

	return nil
}
