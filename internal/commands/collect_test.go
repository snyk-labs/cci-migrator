package commands

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/z4ce/cci-migrator/internal/database"
	"github.com/z4ce/cci-migrator/internal/snyk"
)

var _ = Describe("Collect Command", func() {
	var (
		server *httptest.Server
		db     *database.DB
		client *snyk.Client
		cmd    *CollectCommand
		dbPath string
	)

	BeforeEach(func() {
		// Create a test server
		server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			GinkgoWriter.Printf("Received request for path: %s\n", r.URL.Path)
			GinkgoWriter.Printf("Query parameters: %v\n", r.URL.Query())
			GinkgoWriter.Printf("Headers: %v\n", r.Header)

			switch r.URL.Path {
			case "/orgs/test-org/projects":
				// Verify REST API headers and query parameters
				Expect(r.Header.Get("Authorization")).To(Equal("token test-token"))
				Expect(r.Header.Get("Accept")).To(Equal("application/vnd.api+json"))

				// Verify query parameters
				query := r.URL.Query()
				Expect(query.Get("version")).To(Equal("2024-10-14~experimental"))
				Expect(query.Get("types")).To(Equal("sast"))

				// Return test projects data
				response := snyk.ProjectsResponse{
					Data: []struct {
						ID         string       `json:"id"`
						Type       string       `json:"type"`
						Attributes snyk.Project `json:"attributes"`
					}{
						{
							ID:   "test-project",
							Type: "project",
							Attributes: snyk.Project{
								Name:   "Test Project",
								Type:   "sast",
								Status: "active",
							},
						},
					},
				}
				w.Header().Set("Content-Type", "application/vnd.api+json")
				json.NewEncoder(w).Encode(response)

			case "/org/test-org/project/test-project/ignores":
				// Verify v1 API auth header
				Expect(r.Header.Get("Authorization")).To(Equal("token test-token"))

				// Return test ignores
				now := time.Now()
				response := snyk.IgnoresResponse{
					Ignores: map[string]snyk.Ignore{
						"test-ignore-id": {
							IssueID:    "test-issue",
							Reason:     "test reason",
							ReasonType: "permanent",
							CreatedAt:  now,
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
					},
				}
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(response)

			case "/orgs/test-org/code_issue_details/test-issue":
				// Verify REST API headers
				Expect(r.Header.Get("Authorization")).To(Equal("Bearer test-token"))
				Expect(r.Header.Get("Accept")).To(Equal("application/vnd.api+json"))

				// Verify query parameters
				query := r.URL.Query()
				Expect(query.Get("version")).To(Equal("2024-10-14~experimental"))
				Expect(query.Get("project_id")).To(Equal("test-project"))

				// Return test code details
				details := snyk.CodeDetails{
					ID:          "test-fingerprint",
					Title:       "Test Issue",
					Severity:    "high",
					FilePath:    "src/main.go",
					LineNumber:  42,
					Description: "Test description",
					CWE:         "CWE-123",
					AdditionalFields: map[string]interface{}{
						"test": "value",
					},
				}
				json.NewEncoder(w).Encode(details)

			default:
				http.NotFound(w, r)
			}
		}))

		// Create a temporary database
		dbPath = "test.db"
		var err error
		db, err = database.New(dbPath)
		Expect(err).NotTo(HaveOccurred())

		// Create Snyk client with test server
		client = &snyk.Client{
			HTTPClient:  http.DefaultClient,
			Token:       "test-token",
			V1BaseURL:   server.URL,
			RestBaseURL: server.URL,
		}

		// Create collect command
		cmd = NewCollectCommand(db, client, "test-org")
	})

	AfterEach(func() {
		server.Close()
		db.Close()
		os.Remove(dbPath)
	})

	It("should collect data successfully", func() {
		// Execute collect command
		err := cmd.Execute()
		Expect(err).NotTo(HaveOccurred())

		// Verify the data was collected correctly
		ignores, err := db.GetIgnoresByOrgID("test-org")
		Expect(err).NotTo(HaveOccurred())
		Expect(ignores).To(HaveLen(1))

		ignore := ignores[0]
		Expect(ignore.ID).To(Equal("test-ignore-id"))
		Expect(ignore.IssueID).To(Equal("test-issue"))
		Expect(ignore.Fingerprint).To(Equal("test-fingerprint"))

		// Verify collection metadata was updated
		var completedAt time.Time
		var version, storedAPIVersion string
		err = db.QueryRow("SELECT collection_completed_at, collection_version, api_version FROM collection_metadata LIMIT 1").
			Scan(&completedAt, &version, &storedAPIVersion)
		Expect(err).NotTo(HaveOccurred())

		Expect(version).To(Equal(collectionVersion))
		Expect(storedAPIVersion).To(Equal(apiVersion))
	})
})
