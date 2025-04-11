package snyk

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Snyk Client", func() {
	var (
		server *httptest.Server
		client *Client
	)

	BeforeEach(func() {
		// Create a test server
		server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Verify request
			Expect(r.Method).To(Equal("GET"))
			Expect(r.Header.Get("Authorization")).To(Equal("token test-token"))
			Expect(r.Header.Get("Accept")).To(Equal("application/vnd.api+json"))

			// Check query parameters
			query := r.URL.Query()
			Expect(query.Get("version")).To(Equal("2024-10-14~experimental"))
			Expect(query.Get("types")).To(Equal("sast"))

			// Return test data in JSON:API format
			response := ProjectsResponse{
				Data: []struct {
					ID         string  `json:"id"`
					Type       string  `json:"type"`
					Attributes Project `json:"attributes"`
				}{
					{
						ID:   "test-project-id",
						Type: "project",
						Attributes: Project{
							Name:                "Test Project",
							Created:             time.Now(),
							Origin:              "cli",
							Type:                "sast",
							Status:              "active",
							BusinessCriticality: []string{"high"},
							Environment:         []string{"production"},
							Lifecycle:           []string{"development"},
							Tags: []struct {
								Key   string `json:"key"`
								Value string `json:"value"`
							}{
								{
									Key:   "team",
									Value: "security",
								},
							},
						},
					},
				},
			}

			w.Header().Set("Content-Type", "application/vnd.api+json")
			json.NewEncoder(w).Encode(response)
		}))

		// Create client with test server URL
		client = &Client{
			HTTPClient:  http.DefaultClient,
			Token:       "test-token",
			RestBaseURL: server.URL,
		}
	})

	AfterEach(func() {
		server.Close()
	})

	Describe("GetProjects", func() {
		It("should retrieve projects successfully", func() {
			// Test GetProjects
			projects, err := client.GetProjects("test-org")
			Expect(err).NotTo(HaveOccurred())
			Expect(projects).To(HaveLen(1))

			project := projects[0]
			Expect(project.ID).To(Equal("test-project-id"))
			Expect(project.Name).To(Equal("Test Project"))
			Expect(project.Origin).To(Equal("cli"))
			Expect(project.Type).To(Equal("sast"))
			Expect(project.Status).To(Equal("active"))
			Expect(project.BusinessCriticality).To(Equal([]string{"high"}))
			Expect(project.Environment).To(Equal([]string{"production"}))
			Expect(project.Lifecycle).To(Equal([]string{"development"}))
			Expect(project.Tags).To(HaveLen(1))
			Expect(project.Tags[0].Key).To(Equal("team"))
			Expect(project.Tags[0].Value).To(Equal("security"))
		})
	})

	Describe("GetIgnores", func() {
		BeforeEach(func() {
			// Override the server handler for this test
			server.Close()
			server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				// Verify request
				Expect(r.Method).To(Equal("GET"))
				Expect(r.Header.Get("Authorization")).To(Equal("token test-token"))

				// Verify URL path
				expectedPath := "/org/test-org/project/test-project/ignores"
				Expect(r.URL.Path).To(Equal(expectedPath))

				// Return test data
				now := time.Now()
				expires := now.Add(24 * time.Hour)
				response := IgnoresResponse{
					Ignores: map[string]Ignore{
						"test-ignore-id": {
							IssueID:    "SNYK-123",
							Reason:     "Test reason",
							ReasonType: "not-vulnerable",
							CreatedAt:  now,
							ExpiresAt:  &expires,
							IgnoredBy: User{
								ID:    "user-123",
								Name:  "Test User",
								Email: "test@example.com",
							},
							Issue: Issue{
								ID:       "SNYK-123",
								Title:    "Test Vulnerability",
								Type:     "vuln",
								Package:  "test-package",
								Language: "javascript",
							},
						},
					},
				}

				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(response)
			}))

			// Update client with new server URL
			client.V1BaseURL = server.URL
		})

		It("should retrieve ignores successfully", func() {
			// Test GetIgnores
			ignores, err := client.GetIgnores("test-org", "test-project")
			Expect(err).NotTo(HaveOccurred())
			Expect(ignores).To(HaveLen(1))

			ignore := ignores[0]
			Expect(ignore.ID).To(Equal("test-ignore-id"))
			Expect(ignore.IssueID).To(Equal("SNYK-123"))
			Expect(ignore.Reason).To(Equal("Test reason"))
			Expect(ignore.ReasonType).To(Equal("not-vulnerable"))
			Expect(ignore.IgnoredBy.Name).To(Equal("Test User"))
			Expect(ignore.Issue.Title).To(Equal("Test Vulnerability"))
		})
	})
})
