// Package snyk provides a client for interacting with the Snyk API.
// The client is designed to support idempotent operations - when creating
// resources like policies, 409 (Conflict) responses are treated as successful
// operations rather than errors, allowing migration scripts to be safely re-run.
package snyk

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
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

// RequestOptions holds common request configuration
type RequestOptions struct {
	Method      string
	Path        string
	QueryParams map[string]string
	Body        interface{}
	Headers     map[string]string
	BaseURL     string
}

// New creates a new Snyk API client
func New(token string, apiEndpoint string, debug bool) *Client {
	return &Client{
		HTTPClient: &http.Client{
			Timeout: time.Second * 30,
		},
		Token:       token,
		V1BaseURL:   fmt.Sprintf("https://%s/v1", apiEndpoint),
		RestBaseURL: fmt.Sprintf("https://%s/rest", apiEndpoint),
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
	Name          string                 `json:"name"`
	Branch        string                 `json:"branch"`
	Owner         string                 `json:"owner"`
	Repo          string                 `json:"repo"`
	URL           string                 `json:"url"`
	Origin        string                 `json:"origin"`
	Source        string                 `json:"source"`
	Options       map[string]interface{} `json:"options"`
	ID            string                 `json:"id,omitempty"`
	IntegrationID string                 `json:"integration_id,omitempty"`
	DisplayName   string                 `json:"display_name,omitempty"`
	IsPrivate     bool                   `json:"is_private,omitempty"`
	CreatedAt     time.Time              `json:"created_at,omitempty"`
}

// RateLimitError represents a rate limit error from the Snyk API
type RateLimitError struct {
	RetryAfter time.Duration
	Message    string
}

func (e *RateLimitError) Error() string {
	return fmt.Sprintf("rate limit exceeded: %s, retry after %v", e.Message, e.RetryAfter)
}

// buildURL constructs a full URL with query parameters
func (c *Client) buildURL(baseURL, path string, queryParams map[string]string) string {
	u := fmt.Sprintf("%s%s", baseURL, path)
	if len(queryParams) > 0 {
		values := url.Values{}
		for key, value := range queryParams {
			values.Add(key, value)
		}
		u = fmt.Sprintf("%s?%s", u, values.Encode())
	}
	return u
}

// setCommonHeaders sets the standard headers for API requests
func (c *Client) setCommonHeaders(req *http.Request, contentType string) {
	req.Header.Set("Authorization", "token "+c.Token)
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
}

// makeRequest creates and executes an HTTP request with common error handling
func (c *Client) makeRequest(opts RequestOptions) (*http.Response, error) {
	// Determine base URL
	baseURL := opts.BaseURL
	if baseURL == "" {
		baseURL = c.RestBaseURL
	}

	// Build URL with query parameters
	fullURL := c.buildURL(baseURL, opts.Path, opts.QueryParams)

	// Prepare request body
	var bodyReader io.Reader
	var bodyBytes []byte
	if opts.Body != nil {
		var err error
		bodyBytes, err = json.Marshal(opts.Body)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal request body: %w", err)
		}
		bodyReader = bytes.NewBuffer(bodyBytes)
	}

	// Create request
	req, err := http.NewRequest(opts.Method, fullURL, bodyReader)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Set common headers
	c.setCommonHeaders(req, opts.Headers["Content-Type"])

	// Set additional headers
	for key, value := range opts.Headers {
		if key != "Content-Type" { // Already handled above
			req.Header.Set(key, value)
		}
	}

	// Debug request
	c.debugRequest(req, bodyBytes)

	// Execute request
	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to execute request: %w", err)
	}

	// Debug response
	if c.Debug {
		c.debugResponse(resp)
	}

	return resp, nil
}

// makeRequestWithRetry executes a request with rate limiting retry logic
func (c *Client) makeRequestWithRetry(opts RequestOptions, maxRetries int) (*http.Response, error) {
	var lastResp *http.Response
	retryCount := 0

	for retryCount <= maxRetries {
		resp, err := c.makeRequest(opts)
		if err != nil {
			return nil, err
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
				seconds = 60 * time.Second // default to 60 seconds
			}

			if c.Debug {
				fmt.Fprintf(os.Stderr, "Rate limited, waiting for %v seconds before retry\n", seconds.Seconds())
			}

			time.Sleep(seconds)
			retryCount++
			continue
		}

		lastResp = resp
		break
	}

	return lastResp, nil
}

// handleJSONResponse handles common response processing and JSON decoding
func (c *Client) handleJSONResponse(resp *http.Response, target interface{}, allowedStatusCodes ...int) error {
	defer resp.Body.Close()

	// Default allowed status codes
	if len(allowedStatusCodes) == 0 {
		allowedStatusCodes = []int{http.StatusOK}
	}

	// Check status code
	statusAllowed := false
	for _, code := range allowedStatusCodes {
		if resp.StatusCode == code {
			statusAllowed = true
			break
		}
	}

	if !statusAllowed {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("unexpected status code: %d for URL: %s, body: %s",
			resp.StatusCode, resp.Request.URL, string(bodyBytes))
	}

	// Decode JSON response
	if target != nil {
		if err := json.NewDecoder(resp.Body).Decode(target); err != nil {
			return fmt.Errorf("failed to decode response: %w", err)
		}
	}

	return nil
}

// paginateAllSASTIssues handles paginated requests for SAST issues
func (c *Client) paginateAllSASTIssues(initialOpts RequestOptions) ([]SASTIssue, error) {
	type Response struct {
		Data  []SASTIssue `json:"data"`
		Links struct {
			Next string `json:"next,omitempty"`
		} `json:"links,omitempty"`
	}

	var allIssues []SASTIssue
	nextURL := c.buildURL(initialOpts.BaseURL, initialOpts.Path, initialOpts.QueryParams)

	for nextURL != "" {
		currentOpts := initialOpts
		if nextURL != c.buildURL(initialOpts.BaseURL, initialOpts.Path, initialOpts.QueryParams) {
			// Parse the URL to extract path and query parameters
			parsedURL, err := url.Parse(nextURL)
			if err != nil {
				return nil, fmt.Errorf("failed to parse next URL: %w", err)
			}

			currentOpts.Path = parsedURL.Path
			currentOpts.QueryParams = make(map[string]string)
			for key, values := range parsedURL.Query() {
				if len(values) > 0 {
					currentOpts.QueryParams[key] = values[0]
				}
			}
			currentOpts.BaseURL = fmt.Sprintf("%s://%s", parsedURL.Scheme, parsedURL.Host)
		}

		resp, err := c.makeRequestWithRetry(currentOpts, 5)
		if err != nil {
			return nil, err
		}

		if resp.StatusCode != http.StatusOK {
			bodyBytes, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			return nil, fmt.Errorf("unexpected status code: %d for URL: %s, body: %s",
				resp.StatusCode, resp.Request.URL, string(bodyBytes))
		}

		var response Response
		if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
			resp.Body.Close()
			return nil, fmt.Errorf("failed to decode response: %w", err)
		}
		resp.Body.Close()

		allIssues = append(allIssues, response.Data...)

		// Check for next page and handle relative URLs
		if response.Links.Next != "" {
			if response.Links.Next[0] == '/' {
				nextURL = strings.Replace(c.RestBaseURL, "/rest", "", 1) + response.Links.Next
			} else {
				nextURL = response.Links.Next
			}
		} else {
			nextURL = ""
		}
	}

	return allIssues, nil
}

// paginateAllProjects handles paginated requests for projects
func (c *Client) paginateAllProjects(initialOpts RequestOptions) ([]Project, error) {
	type Response struct {
		Data  []ProjectResponse `json:"data"`
		Links struct {
			Next string `json:"next,omitempty"`
		} `json:"links,omitempty"`
	}

	var allProjects []Project
	nextURL := c.buildURL(initialOpts.BaseURL, initialOpts.Path, initialOpts.QueryParams)

	for nextURL != "" {
		currentOpts := initialOpts
		if nextURL != c.buildURL(initialOpts.BaseURL, initialOpts.Path, initialOpts.QueryParams) {
			// Parse the URL to extract path and query parameters
			parsedURL, err := url.Parse(nextURL)
			if err != nil {
				return nil, fmt.Errorf("failed to parse next URL: %w", err)
			}

			currentOpts.Path = parsedURL.Path
			currentOpts.QueryParams = make(map[string]string)
			for key, values := range parsedURL.Query() {
				if len(values) > 0 {
					currentOpts.QueryParams[key] = values[0]
				}
			}
			currentOpts.BaseURL = fmt.Sprintf("%s://%s", parsedURL.Scheme, parsedURL.Host)
		}

		resp, err := c.makeRequestWithRetry(currentOpts, 5)
		if err != nil {
			return nil, err
		}

		if resp.StatusCode != http.StatusOK {
			bodyBytes, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			return nil, fmt.Errorf("unexpected status code: %d for URL: %s, body: %s",
				resp.StatusCode, resp.Request.URL, string(bodyBytes))
		}

		var response Response
		if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
			resp.Body.Close()
			return nil, fmt.Errorf("failed to decode response: %w", err)
		}
		resp.Body.Close()

		// Convert ProjectResponse to Project
		for _, item := range response.Data {
			project := item.Attributes
			project.ID = item.ID // Ensure ID is set from the data object

			// Set the target ID from the relationships section
			if item.Relationships.Target.Data.ID != "" {
				project.Target = Target{
					ID: item.Relationships.Target.Data.ID,
				}
			}
			allProjects = append(allProjects, project)
		}

		// Check for next page and handle relative URLs
		if response.Links.Next != "" {
			if response.Links.Next[0] == '/' {
				nextURL = strings.Replace(c.RestBaseURL, "/rest", "", 1) + response.Links.Next
			} else {
				nextURL = response.Links.Next
			}
		} else {
			nextURL = ""
		}
	}

	return allProjects, nil
}

// paginateAllOrganizations handles paginated requests for organizations
func (c *Client) paginateAllOrganizations(initialOpts RequestOptions) ([]Organization, error) {
	type Response struct {
		Data  []OrganizationResponse `json:"data"`
		Links struct {
			Next string `json:"next,omitempty"`
		} `json:"links,omitempty"`
	}

	var allOrganizations []Organization
	nextURL := c.buildURL(initialOpts.BaseURL, initialOpts.Path, initialOpts.QueryParams)

	for nextURL != "" {
		currentOpts := initialOpts
		if nextURL != c.buildURL(initialOpts.BaseURL, initialOpts.Path, initialOpts.QueryParams) {
			// Parse the URL to extract path and query parameters
			parsedURL, err := url.Parse(nextURL)
			if err != nil {
				return nil, fmt.Errorf("failed to parse next URL: %w", err)
			}

			currentOpts.Path = parsedURL.Path
			currentOpts.QueryParams = make(map[string]string)
			for key, values := range parsedURL.Query() {
				if len(values) > 0 {
					currentOpts.QueryParams[key] = values[0]
				}
			}
			currentOpts.BaseURL = fmt.Sprintf("%s://%s", parsedURL.Scheme, parsedURL.Host)
		}

		resp, err := c.makeRequestWithRetry(currentOpts, 5)
		if err != nil {
			return nil, err
		}

		if resp.StatusCode != http.StatusOK {
			bodyBytes, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			return nil, fmt.Errorf("unexpected status code: %d for URL: %s, body: %s",
				resp.StatusCode, resp.Request.URL, string(bodyBytes))
		}

		var response Response
		if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
			resp.Body.Close()
			return nil, fmt.Errorf("failed to decode response: %w", err)
		}
		resp.Body.Close()

		// Convert OrganizationResponse to Organization
		for _, item := range response.Data {
			org := item.Attributes
			org.ID = item.ID
			allOrganizations = append(allOrganizations, org)
		}

		// Check for next page and handle relative URLs
		if response.Links.Next != "" {
			if response.Links.Next[0] == '/' {
				nextURL = strings.Replace(c.RestBaseURL, "/rest", "", 1) + response.Links.Next
			} else {
				nextURL = response.Links.Next
			}
		} else {
			nextURL = ""
		}
	}

	return allOrganizations, nil
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
	opts := RequestOptions{
		Method:  "GET",
		Path:    fmt.Sprintf("/org/%s/project/%s/ignores", orgID, projectID),
		BaseURL: c.V1BaseURL,
	}

	resp, err := c.makeRequest(opts)
	if err != nil {
		return nil, err
	}

	var response IgnoresResponse
	if err := c.handleJSONResponse(resp, &response); err != nil {
		return nil, err
	}

	if c.Debug {
		fmt.Fprintf(os.Stderr, "Decoded ignores response with %d ignore IDs\n", len(response))
	}

	// Convert map of ignores to slice
	ignores := make([]Ignore, 0, len(response))
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

// CreateIgnore creates an ignore via the v1 API
func (c *Client) CreateIgnore(orgID, projectID string, ignore Ignore) error {
	// Prepare request payload
	type ignoreRequest struct {
		IgnorePath         string     `json:"ignorePath"`
		Reason             string     `json:"reason"`
		ReasonType         string     `json:"reasonType"`
		DisregardIfFixable bool       `json:"disregardIfFixable"`
		Expires            *time.Time `json:"expires,omitempty"`
	}
	payload := ignoreRequest{
		IgnorePath:         "*",
		Reason:             ignore.Reason,
		ReasonType:         ignore.ReasonType,
		DisregardIfFixable: ignore.DisregardIfFixable,
		Expires:            ignore.ExpiresAt,
	}

	opts := RequestOptions{
		Method:  "POST",
		Path:    fmt.Sprintf("/org/%s/project/%s/ignore/%s", orgID, projectID, ignore.ID),
		BaseURL: c.V1BaseURL,
		Body:    payload,
		Headers: map[string]string{
			"Content-Type": "application/json",
			"Accept":       "application/json",
		},
	}

	resp, err := c.makeRequest(opts)
	if err != nil {
		return err
	}

	return c.handleJSONResponse(resp, nil, http.StatusOK)
}

// GetSASTIssues retrieves SAST issues for a given organization and project
// If projectID is empty, retrieves issues for the entire organization
func (c *Client) GetSASTIssues(orgID string, projectID string) ([]SASTIssue, error) {
	queryParams := map[string]string{
		"version": "2024-10-15",
		"type":    "code",
		"limit":   "100",
	}

	if projectID != "" {
		queryParams["project_id"] = projectID
	}

	opts := RequestOptions{
		Method:      "GET",
		Path:        fmt.Sprintf("/orgs/%s/issues", orgID),
		QueryParams: queryParams,
		Headers: map[string]string{
			"Accept": "application/vnd.api+json",
		},
	}

	return c.paginateAllSASTIssues(opts)
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
	TargetReference string `json:"target_reference"`
	Target          Target `json:"-"` // Using json:"-" since this comes from relationships, not attributes
}

// ProjectResponse represents a single project in the JSON:API response
type ProjectResponse struct {
	ID            string  `json:"id"`
	Type          string  `json:"type"`
	Attributes    Project `json:"attributes"`
	Relationships struct {
		Target struct {
			Data struct {
				Type string `json:"type"`
				ID   string `json:"id"`
			} `json:"data"`
		} `json:"target"`
	} `json:"relationships"`
}

// ProjectsResponse represents the JSON:API response for projects
type ProjectsResponse struct {
	Data []ProjectResponse `json:"data"`
}

// GetProjects retrieves all projects for a given organization using the REST API
func (c *Client) GetProjects(orgID string) ([]Project, error) {
	opts := RequestOptions{
		Method: "GET",
		Path:   fmt.Sprintf("/orgs/%s/projects", orgID),
		QueryParams: map[string]string{
			"version": "2024-10-15",
			"types":   "sast",
			"limit":   "100",
		},
		Headers: map[string]string{
			"Accept": "application/vnd.api+json",
		},
	}

	return c.paginateAllProjects(opts)
}

// GetProjectTarget retrieves the target details for a given project. The REST API
// does not embed the full target information inside the project response – it
// only exposes a target_id. Therefore, the method performs two requests:
//  1. GET /orgs/{org_id}/projects/{project_id} to obtain the target_id
//  2. GET /orgs/{org_id}/targets/{target_id}  to obtain the target details
//
// The data returned by the second call is then mapped into the legacy Target
// struct so that the rest of the codebase (e.g. RetestProject) continues to
// work unchanged.
func (c *Client) GetProjectTarget(orgID, targetID string) (*Target, error) {
	opts := RequestOptions{
		Method: "GET",
		Path:   fmt.Sprintf("/orgs/%s/targets/%s", orgID, targetID),
		QueryParams: map[string]string{
			"version": "2024-10-15",
		},
		Headers: map[string]string{
			"Accept": "application/vnd.api+json",
		},
	}

	resp, err := c.makeRequest(opts)
	if err != nil {
		return nil, err
	}

	// Minimal struct to capture the relevant fields from the target response
	var targetResp struct {
		Data struct {
			ID         string `json:"id"`
			Type       string `json:"type"`
			Attributes struct {
				CreatedAt   time.Time `json:"created_at"`
				DisplayName string    `json:"display_name"`
				IsPrivate   bool      `json:"is_private"`
				URL         string    `json:"url"`
			} `json:"attributes"`
			Relationships struct {
				Integration struct {
					Data struct {
						Attributes struct {
							IntegrationType string `json:"integration_type"`
						} `json:"attributes"`
						ID   string `json:"id"`
						Type string `json:"type"`
					} `json:"data"`
				} `json:"integration"`
			} `json:"relationships"`
		} `json:"data"`
	}

	if err := c.handleJSONResponse(resp, &targetResp); err != nil {
		return nil, err
	}

	attrs := targetResp.Data.Attributes

	// Map the response into the legacy Target struct so the rest of the code
	// continues to work without modification.
	tgt := &Target{
		Name:          attrs.DisplayName,
		DisplayName:   attrs.DisplayName,
		URL:           attrs.URL,
		CreatedAt:     attrs.CreatedAt,
		IsPrivate:     attrs.IsPrivate,
		ID:            targetResp.Data.ID,
		IntegrationID: targetResp.Data.Relationships.Integration.Data.ID,
		Options:       make(map[string]interface{}),
	}

	// Attempt to parse owner / repo from the display name if it follows the
	// conventional "owner/repo" pattern (as observed in the REST API docs).
	if parts := strings.Split(attrs.DisplayName, "/"); len(parts) == 2 {
		tgt.Owner = parts[0]
		tgt.Repo = parts[1]
	}

	// The branch, origin and source fields are not provided by the target API
	// endpoint. They remain empty, but the struct fields stay present for
	// backwards-compatibility with other parts of the codebase.

	if tgt.ID == "" {
		// Ensure the ID is always populated (older API versions may omit it in attributes)
		tgt.ID = targetResp.Data.ID
	}

	return tgt, nil
}

// RetestProject initiates a retest for a given target via its integration import endpoint
func (c *Client) RetestProject(orgID string, target *Target) error {
	// The import endpoint must be called on the integration that owns the target.
	integrationID := strings.TrimSpace(target.IntegrationID)
	if integrationID == "" {
		return fmt.Errorf("target missing integration_id – cannot trigger import")
	}

	opts := RequestOptions{
		Method:  "POST",
		Path:    fmt.Sprintf("/org/%s/integrations/%s/import", orgID, integrationID),
		BaseURL: c.V1BaseURL,
		Body:    c.createImportPayload(target),
		Headers: map[string]string{
			"Content-Type": "application/json",
		},
	}

	resp, err := c.makeRequest(opts)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("unexpected status code: %d for URL: %s", resp.StatusCode, resp.Request.URL)
	}

	return nil
}

// createImportPayload creates the appropriate payload structure based on target information
func (c *Client) createImportPayload(target *Target) interface{} {
	// For all integration types, we'll use a simple payload structure
	// that includes the essential target information
	type SimpleTarget struct {
		Owner  string `json:"owner"`
		Name   string `json:"name"`
		Branch string `json:"branch,omitempty"`
	}

	type ImportPayload struct {
		Target SimpleTarget `json:"target"`
	}

	return ImportPayload{
		Target: SimpleTarget{
			Owner:  target.Owner,
			Name:   target.Repo,
			Branch: target.Branch,
		},
	}
}

// DeleteIgnore deletes an ignore
func (c *Client) DeleteIgnore(orgID, projectID, ignoreID string) error {
	opts := RequestOptions{
		Method:  "DELETE",
		Path:    fmt.Sprintf("/org/%s/project/%s/ignore/%s", orgID, projectID, ignoreID),
		BaseURL: c.V1BaseURL,
	}

	resp, err := c.makeRequest(opts)
	if err != nil {
		return err
	}

	return c.handleJSONResponse(resp, nil, http.StatusNoContent, http.StatusOK)
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
	queryParams := map[string]string{
		"version": "2024-10-15",
	}

	// Add query parameters from options
	for key, value := range options {
		queryParams[key] = value
	}

	opts := RequestOptions{
		Method:      "GET",
		Path:        fmt.Sprintf("/orgs/%s/policies", orgID),
		QueryParams: queryParams,
		Headers: map[string]string{
			"Accept": "application/vnd.api+json",
		},
	}

	resp, err := c.makeRequest(opts)
	if err != nil {
		return nil, err
	}

	var response PoliciesResponse
	if err := c.handleJSONResponse(resp, &response); err != nil {
		return nil, err
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
	opts := RequestOptions{
		Method: "GET",
		Path:   fmt.Sprintf("/orgs/%s/policies/%s", orgID, policyID),
		QueryParams: map[string]string{
			"version": "2024-10-15",
		},
		Headers: map[string]string{
			"Accept": "application/vnd.api+json",
		},
	}

	resp, err := c.makeRequest(opts)
	if err != nil {
		return nil, err
	}

	var response struct {
		Data PolicyResponse `json:"data"`
	}
	if err := c.handleJSONResponse(resp, &response); err != nil {
		return nil, err
	}

	policy := response.Data.Attributes
	policy.ID = response.Data.ID

	return &policy, nil
}

// CreatePolicy creates a new policy using the Policy API.
// This method is designed to be idempotent - if a policy with the same
// attributes already exists (indicated by a 409 conflict response),
// it will be treated as a successful operation rather than an error.
// This allows migration operations to be safely re-run.
func (c *Client) CreatePolicy(orgID string, attributes CreatePolicyAttributes, meta map[string]interface{}) (*Policy, error) {
	payload := CreatePolicyPayload{}
	payload.Data.Type = "policy"
	payload.Data.Attributes = attributes
	payload.Data.Meta = meta

	opts := RequestOptions{
		Method: "POST",
		Path:   fmt.Sprintf("/orgs/%s/policies", orgID),
		QueryParams: map[string]string{
			"version": "2024-10-15",
		},
		Body: payload,
		Headers: map[string]string{
			"Content-Type": "application/vnd.api+json",
			"Accept":       "application/vnd.api+json",
		},
	}

	resp, err := c.makeRequest(opts)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// Handle both successful creation (201) and conflict (409) as success
	// A 409 conflict indicates the policy already exists, which is acceptable for idempotent operation
	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusConflict {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("unexpected status code: %d for URL: %s, body: %s", resp.StatusCode, resp.Request.URL, string(bodyBytes))
	}

	// For 409 conflicts, we may not get a response body with the policy data
	// In this case, we need to handle the conflict as a successful operation
	if resp.StatusCode == http.StatusConflict {
		// For conflicts, try to parse any error message but don't fail if we can't
		bodyBytes, _ := io.ReadAll(resp.Body)
		if c.Debug {
			fmt.Fprintf(os.Stderr, "Policy creation conflict (409), policy likely already exists: %s\n", string(bodyBytes))
		}

		// Since we can't reliably get the policy ID from a 409 response,
		// we'll return a minimal policy object that indicates success
		// The caller should be prepared to handle this case where ID might be empty
		return &Policy{
			Name:            attributes.Name,
			ActionType:      attributes.ActionType,
			Action:          attributes.Action,
			ConditionsGroup: attributes.ConditionsGroup,
		}, nil
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
	payload := UpdatePolicyPayload{}
	payload.Data.Type = "policy"
	payload.Data.ID = policyID
	payload.Data.Attributes = attributes
	payload.Data.Meta = meta

	opts := RequestOptions{
		Method: "PATCH",
		Path:   fmt.Sprintf("/orgs/%s/policies/%s", orgID, policyID),
		QueryParams: map[string]string{
			"version": "2024-10-15",
		},
		Body: payload,
		Headers: map[string]string{
			"Content-Type": "application/vnd.api+json",
			"Accept":       "application/vnd.api+json",
		},
	}

	resp, err := c.makeRequest(opts)
	if err != nil {
		return nil, err
	}

	var response struct {
		Data PolicyResponse `json:"data"`
	}
	if err := c.handleJSONResponse(resp, &response); err != nil {
		return nil, err
	}

	policy := response.Data.Attributes
	policy.ID = response.Data.ID
	return &policy, nil
}

// DeletePolicy deletes a policy
func (c *Client) DeletePolicy(orgID string, policyID string) error {
	opts := RequestOptions{
		Method: "DELETE",
		Path:   fmt.Sprintf("/orgs/%s/policies/%s", orgID, policyID),
		QueryParams: map[string]string{
			"version": "2024-10-15",
		},
		Headers: map[string]string{
			"Accept": "application/vnd.api+json",
		},
	}

	resp, err := c.makeRequest(opts)
	if err != nil {
		return err
	}

	return c.handleJSONResponse(resp, nil, http.StatusNoContent)
}

// Organization represents a Snyk organization from the groups API
type Organization struct {
	ID                    string    `json:"id"`
	Name                  string    `json:"name"`
	Slug                  string    `json:"slug"`
	GroupID               string    `json:"group_id"`
	IsPersonal            bool      `json:"is_personal"`
	CreatedAt             time.Time `json:"created_at"`
	UpdatedAt             time.Time `json:"updated_at"`
	AccessRequestsEnabled bool      `json:"access_requests_enabled"`
}

// OrganizationResponse represents a single organization in the JSON:API response
type OrganizationResponse struct {
	ID         string       `json:"id"`
	Type       string       `json:"type"`
	Attributes Organization `json:"attributes"`
}

// OrganizationsResponse represents the JSON:API response for organizations in a group
type OrganizationsResponse struct {
	Data    []OrganizationResponse `json:"data"`
	JSONAPI struct {
		Version string `json:"version"`
	} `json:"jsonapi"`
	Links struct {
		First string `json:"first,omitempty"`
		Last  string `json:"last,omitempty"`
		Next  string `json:"next,omitempty"`
		Prev  string `json:"prev,omitempty"`
		Self  string `json:"self,omitempty"`
	} `json:"links"`
}

// GetOrganizationsInGroup retrieves all organizations for a given group using the REST API
func (c *Client) GetOrganizationsInGroup(groupID string) ([]Organization, error) {
	opts := RequestOptions{
		Method: "GET",
		Path:   fmt.Sprintf("/groups/%s/orgs", groupID),
		QueryParams: map[string]string{
			"version": "2024-10-15",
			"limit":   "100",
		},
		Headers: map[string]string{
			"Accept": "application/vnd.api+json",
		},
	}

	return c.paginateAllOrganizations(opts)
}
