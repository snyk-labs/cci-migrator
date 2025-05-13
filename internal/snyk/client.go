package snyk

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"
)

// Client represents a Snyk API client
type Client struct {
	HTTPClient  *http.Client
	Token       string
	V1BaseURL   string
	RestBaseURL string
	Debug       bool
}

// New creates a new Snyk API client
func New(token string, debug bool) *Client {
	return &Client{
		HTTPClient: &http.Client{
			Timeout: time.Second * 30,
		},
		Token:       token,
		V1BaseURL:   "https://api.snyk.io/v1",
		RestBaseURL: "https://api.snyk.io/rest",
		Debug:       debug,
	}
}

// Ignore represents a Snyk ignore
type Ignore struct {
	ID                 string     `json:"id"`
	Reason             string     `json:"reason"`
	ReasonType         string     `json:"reasonType"`
	CreatedAt          time.Time  `json:"created"`
	ExpiresAt          *time.Time `json:"expires,omitempty"`
	IgnoredBy          User       `json:"ignoredBy"`
	DisregardIfFixable bool       `json:"disregardIfFixable"`
	IgnoreScope        string     `json:"ignoreScope"`
	Path               []struct {
		Module string `json:"module"`
	} `json:"path"`
}

// IgnoreDetail represents the individual ignore details in API response
type IgnoreDetail struct {
	Reason             string    `json:"reason"`
	CreatedAt          time.Time `json:"created"`
	IgnoredBy          User      `json:"ignoredBy"`
	ReasonType         string    `json:"reasonType"`
	DisregardIfFixable bool      `json:"disregardIfFixable"`
	Path               []struct {
		Module string `json:"module"`
	} `json:"path"`
	IgnoreScope string     `json:"ignoreScope"`
	ExpiresAt   *time.Time `json:"expires,omitempty"`
}

// IgnoresResponse represents the response from the ignores API
type IgnoresResponse map[string][]IgnoreDetail

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
	ID         string `json:"id"`
	Type       string `json:"type"`
	Attributes struct {
		Classes []struct {
			ID     string `json:"id"`
			Source string `json:"source"`
			Type   string `json:"type"`
		} `json:"classes"`
		Coordinates []struct {
			IsFixableManually bool `json:"is_fixable_manually"`
			IsFixableSnyk     bool `json:"is_fixable_snyk"`
			IsFixableUpstream bool `json:"is_fixable_upstream"`
			Representations   []struct {
				SourceLocation struct {
					CommitID string `json:"commit_id"`
					File     string `json:"file"`
					Region   struct {
						End struct {
							Column int `json:"column"`
							Line   int `json:"line"`
						} `json:"end"`
						Start struct {
							Column int `json:"column"`
							Line   int `json:"line"`
						} `json:"start"`
					} `json:"region"`
				} `json:"sourceLocation"`
			} `json:"representations"`
		} `json:"coordinates"`
		CreatedAt              time.Time `json:"created_at"`
		Description            string    `json:"description"`
		EffectiveSeverityLevel string    `json:"effective_severity_level"`
		Ignored                bool      `json:"ignored"`
		Key                    string    `json:"key"`
		KeyAsset               string    `json:"key_asset"`
		Problems               []struct {
			ID        string    `json:"id"`
			Source    string    `json:"source"`
			Type      string    `json:"type"`
			UpdatedAt time.Time `json:"updated_at"`
		} `json:"problems"`
		Risk struct {
			Factors []any `json:"factors"`
			Score   struct {
				Model string `json:"model"`
				Value int    `json:"value"`
			} `json:"score"`
		} `json:"risk"`
		Status    string    `json:"status"`
		Title     string    `json:"title"`
		Type      string    `json:"type"`
		UpdatedAt time.Time `json:"updated_at"`
	} `json:"attributes"`
	Relationships struct {
		Organization struct {
			Data struct {
				ID   string `json:"id"`
				Type string `json:"type"`
			} `json:"data"`
			Links struct {
				Related string `json:"related"`
			} `json:"links"`
		} `json:"organization"`
		ScanItem struct {
			Data struct {
				ID   string `json:"id"`
				Type string `json:"type"`
			} `json:"data"`
			Links struct {
				Related string `json:"related"`
			} `json:"links"`
		} `json:"scan_item"`
	} `json:"relationships"`
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
	if c.Debug {
		fmt.Fprintf(os.Stderr, "Response status code: %d\n", resp.StatusCode)
		fmt.Fprintf(os.Stderr, "Response headers: %v\n", resp.Header)
	}

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

// debugRequest logs request details if debug is enabled
func (c *Client) debugRequest(req *http.Request, body []byte) {
	if !c.Debug {
		return
	}

	fmt.Fprintf(os.Stderr, "Making request: %s %s\n", req.Method, req.URL)
	fmt.Fprintf(os.Stderr, "Request headers: %v\n", req.Header)

	if body != nil {
		var prettyJSON bytes.Buffer
		if err := json.Indent(&prettyJSON, body, "", "  "); err == nil {
			fmt.Fprintf(os.Stderr, "Request body: %s\n", prettyJSON.String())
		} else {
			fmt.Fprintf(os.Stderr, "Request body: %s\n", string(body))
		}
	}
}

// debugResponse logs response body if debug is enabled
func (c *Client) debugResponse(resp *http.Response) {
	if !c.Debug || resp == nil {
		return
	}

	// Clone the response body so we can read it without consuming it
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading response body: %v\n", err)
		return
	}

	// Put the body back so it can be read again
	resp.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))

	// Pretty print JSON if possible
	var prettyJSON bytes.Buffer
	if err := json.Indent(&prettyJSON, bodyBytes, "", "  "); err == nil {
		fmt.Fprintf(os.Stderr, "Response body: %s\n", prettyJSON.String())
	} else {
		fmt.Fprintf(os.Stderr, "Response body: %s\n", string(bodyBytes))
	}
}

// GetIgnores retrieves all ignores for a given organization and project
func (c *Client) GetIgnores(orgID, projectID string) ([]Ignore, error) {
	url := fmt.Sprintf("%s/org/%s/project/%s/ignores", c.V1BaseURL, orgID, projectID)
	if c.Debug {
		fmt.Fprintf(os.Stderr, "Making request to get ignores: %s\n", url)
	}

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "token "+c.Token)
	if c.Debug {
		fmt.Fprintf(os.Stderr, "Authorization header set: %s\n", "token "+c.Token[:5]+"...")
	}
	c.debugRequest(req, nil)

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to execute request: %w", err)
	}
	defer resp.Body.Close()

	if c.Debug {
		c.debugResponse(resp)
	}

	if err := c.handleResponse(resp); err != nil {
		return nil, err
	}

	var response IgnoresResponse
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	if c.Debug {
		fmt.Fprintf(os.Stderr, "Decoded ignores response with %d ignore IDs\n", len(response))
	}

	// Convert map of ignores to slice
	ignores := make([]Ignore, 0)
	for id, ignoreDetails := range response {
		if len(ignoreDetails) == 0 {
			continue
		}

		// Use the first ignore detail (most APIs return only one per ID)
		detail := ignoreDetails[0]

		ignore := Ignore{
			ID:                 id,
			Reason:             detail.Reason,
			ReasonType:         detail.ReasonType,
			CreatedAt:          detail.CreatedAt,
			ExpiresAt:          detail.ExpiresAt,
			IgnoredBy:          detail.IgnoredBy,
			DisregardIfFixable: detail.DisregardIfFixable,
			IgnoreScope:        detail.IgnoreScope,
			Path:               detail.Path,
		}

		ignores = append(ignores, ignore)
		if c.Debug {
			fmt.Fprintf(os.Stderr, "Added ignore with ID: %s\n", id)
		}
	}

	if c.Debug {
		fmt.Fprintf(os.Stderr, "Total ignores processed: %d\n", len(ignores))
	}

	return ignores, nil
}

// GetSASTIssues retrieves SAST issues for a given organization and project
// If projectID is empty, retrieves issues for the entire organization
func (c *Client) GetSASTIssues(orgID string, projectID string) ([]SASTIssue, error) {
	baseURL := fmt.Sprintf("%s/orgs/%s/issues?version=2024-10-15&type=code&limit=100", c.RestBaseURL, orgID)

	// Add project_id parameter if provided
	url := baseURL
	if projectID != "" {
		url = fmt.Sprintf("%s&project_id=%s", baseURL, projectID)
	}

	// Use getAllSASTIssues to handle pagination
	return c.getAllSASTIssues(url)
}

// getAllSASTIssues handles paginated requests for SAST issues
func (c *Client) getAllSASTIssues(initialURL string) ([]SASTIssue, error) {

	type Response struct {
		Data  []SASTIssue `json:"data"`
		Links struct {
			Next string `json:"next,omitempty"`
		} `json:"links,omitempty"`
	}

	var allIssues []SASTIssue
	nextURL := initialURL
	retryCount := 0
	maxRetries := 5

	for nextURL != "" {
		// Create request
		req, err := http.NewRequest("GET", nextURL, nil)
		if err != nil {
			return nil, fmt.Errorf("failed to create request: %w", err)
		}

		req.Header.Set("Authorization", "token "+c.Token)
		req.Header.Set("Accept", "application/vnd.api+json")
		c.debugRequest(req, nil)

		// Execute request
		resp, err := c.HTTPClient.Do(req)
		if err != nil {
			return nil, fmt.Errorf("failed to execute request: %w", err)
		}

		// Handle rate limiting
		if resp.StatusCode == http.StatusTooManyRequests {
			resp.Body.Close()
			if retryCount >= maxRetries {
				return nil, fmt.Errorf("maximum retries exceeded for rate limiting")
			}

			retryAfter := resp.Header.Get("Retry-After")
			seconds, err := time.ParseDuration(retryAfter + "s")
			if err != nil {
				seconds = 60 * time.Second // default to 60 seconds if header is missing or invalid
			}

			if c.Debug {
				fmt.Fprintf(os.Stderr, "Rate limited, waiting for %v seconds before retry\n", seconds.Seconds())
			}

			time.Sleep(seconds)
			retryCount++
			continue
		}

		if c.Debug {
			c.debugResponse(resp)
		}

		// Check for other errors
		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			return nil, fmt.Errorf("unexpected status code: %d for URL: %s, body: %s",
				resp.StatusCode, resp.Request.URL, string(body))
		}

		// Parse response
		var response Response
		if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
			resp.Body.Close()
			return nil, fmt.Errorf("failed to decode response: %w", err)
		}
		resp.Body.Close()

		// Process issues
		allIssues = append(allIssues, response.Data...)

		// Check for next page and handle relative URLs
		if response.Links.Next != "" {
			// If the next URL is relative (starts with /), prepend the base URL
			if response.Links.Next[0] == '/' {
				nextURL = "https://api.snyk.io" + response.Links.Next
			} else {
				nextURL = response.Links.Next
			}
		} else {
			nextURL = ""
		}
	}

	return allIssues, nil
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
	url := fmt.Sprintf("%s/orgs/%s/projects?version=2024-10-15&types=sast&limit=100", c.RestBaseURL, orgID)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "token "+c.Token)
	req.Header.Set("Accept", "application/vnd.api+json")
	c.debugRequest(req, nil)

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to execute request: %w", err)
	}
	defer resp.Body.Close()

	if c.Debug {
		c.debugResponse(resp)
	}

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
	url := fmt.Sprintf("%s/orgs/%s/projects/%s?version=2024-10-15", c.RestBaseURL, orgID, projectID)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "token "+c.Token)
	req.Header.Set("Accept", "application/vnd.api+json")
	c.debugRequest(req, nil)

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to execute request: %w", err)
	}
	defer resp.Body.Close()

	if c.Debug {
		c.debugResponse(resp)
	}

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
	c.debugRequest(req, body)

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to execute request: %w", err)
	}
	defer resp.Body.Close()

	if c.Debug {
		c.debugResponse(resp)
	}

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
	c.debugRequest(req, nil)

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to execute request: %w", err)
	}
	defer resp.Body.Close()

	if c.Debug {
		c.debugResponse(resp)
	}

	if resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("unexpected status code: %d for URL: %s", resp.StatusCode, resp.Request.URL)
	}

	return nil
}

// UserIdentity represents the user who created/modified an entity in policy responses.
type UserIdentity struct {
	Email string `json:"email,omitempty"`
	ID    string `json:"id"`
	Name  string `json:"name,omitempty"`
}

// ActionData contains details for an action, e.g., for an ignore action.
type ActionData struct {
	Expires    *time.Time `json:"expires,omitempty"`
	IgnoreType string     `json:"ignore_type"`
	Reason     string     `json:"reason"`
}

// Action represents the action part of a policy.
type Action struct {
	Data ActionData `json:"data"`
}

// Condition represents a single condition for a policy.
type Condition struct {
	Field    string `json:"field"`
	Operator string `json:"operator"`
	Value    string `json:"value"`
}

// ConditionsGroup represents a group of conditions for a policy.
type ConditionsGroup struct {
	Conditions      []Condition `json:"conditions"`
	LogicalOperator string      `json:"logical_operator"`
}

// Policy represents a Snyk policy's attributes from the REST API
type Policy struct {
	// ID is set from the parent JSON:API object, not part of attributes json directly
	ID              string          `json:"-"`
	Name            string          `json:"name"`
	Action          Action          `json:"action"`
	ActionType      string          `json:"action_type"` // e.g., "ignore"
	ConditionsGroup ConditionsGroup `json:"conditions_group"`
	CreatedAt       time.Time       `json:"created_at"`
	CreatedBy       UserIdentity    `json:"created_by"`
	Review          string          `json:"review"` // e.g., "pending"
	UpdatedAt       time.Time       `json:"updated_at"`
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

// CreatePolicyAttributes defines the attributes for creating a policy.
type CreatePolicyAttributes struct {
	Name            string          `json:"name"`
	Action          Action          `json:"action"`
	ActionType      string          `json:"action_type"`
	ConditionsGroup ConditionsGroup `json:"conditions_group"`
}

// CreatePolicyPayload represents the payload for creating a new policy
type CreatePolicyPayload struct {
	Data struct {
		Type       string                 `json:"type"`
		Attributes CreatePolicyAttributes `json:"attributes"`
		Meta       map[string]interface{} `json:"meta,omitempty"`
	} `json:"data"`
}

// UpdatePolicyAttributes defines the attributes for updating a policy.
// Pointers are used to indicate optional fields for PATCH operations.
type UpdatePolicyAttributes struct {
	Name            *string          `json:"name,omitempty"`
	Action          *Action          `json:"action,omitempty"`
	ActionType      *string          `json:"action_type,omitempty"`
	ConditionsGroup *ConditionsGroup `json:"conditions_group,omitempty"`
	Review          *string          `json:"review,omitempty"`
}

// UpdatePolicyPayload represents the payload for updating a policy
type UpdatePolicyPayload struct {
	Data struct {
		Type       string                 `json:"type"`
		ID         string                 `json:"id"`
		Attributes UpdatePolicyAttributes `json:"attributes"`
		Meta       map[string]interface{} `json:"meta,omitempty"`
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
	c.debugRequest(req, nil)

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to execute request: %w", err)
	}
	defer resp.Body.Close()

	if c.Debug {
		c.debugResponse(resp)
	}

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
	c.debugRequest(req, nil)

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to execute request: %w", err)
	}
	defer resp.Body.Close()

	if c.Debug {
		c.debugResponse(resp)
	}

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
func (c *Client) CreatePolicy(orgID string, attributes CreatePolicyAttributes, meta map[string]interface{}) (*Policy, error) {
	url := fmt.Sprintf("%s/orgs/%s/policies?version=2024-10-15", c.RestBaseURL, orgID)

	payload := CreatePolicyPayload{}
	payload.Data.Type = "policy"
	payload.Data.Attributes = attributes
	payload.Data.Meta = meta

	body, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal policy payload: %w", err)
	}

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(body))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "token "+c.Token)
	req.Header.Set("Content-Type", "application/vnd.api+json")
	req.Header.Set("Accept", "application/vnd.api+json")
	c.debugRequest(req, body)

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to execute request: %w", err)
	}
	defer resp.Body.Close()

	if c.Debug {
		c.debugResponse(resp)
	}

	if resp.StatusCode != http.StatusCreated {
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

// UpdatePolicy updates an existing policy
func (c *Client) UpdatePolicy(orgID string, policyID string, attributes UpdatePolicyAttributes, meta map[string]interface{}) (*Policy, error) {
	url := fmt.Sprintf("%s/orgs/%s/policies/%s?version=2024-10-15", c.RestBaseURL, orgID, policyID)

	payload := UpdatePolicyPayload{}
	payload.Data.Type = "policy"
	payload.Data.ID = policyID
	payload.Data.Attributes = attributes
	payload.Data.Meta = meta

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
	c.debugRequest(req, body)

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to execute request: %w", err)
	}
	defer resp.Body.Close()

	if c.Debug {
		c.debugResponse(resp)
	}

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
	c.debugRequest(req, nil)

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to execute request: %w", err)
	}
	defer resp.Body.Close()

	if c.Debug {
		c.debugResponse(resp)
	}

	if resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("unexpected status code: %d for URL: %s", resp.StatusCode, resp.Request.URL)
	}

	return nil
}
