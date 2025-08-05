package commands_test

import (
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/z4ce/cci-migrator/internal/commands"
	"github.com/z4ce/cci-migrator/internal/database"
	"github.com/z4ce/cci-migrator/internal/snyk"
)

var _ = Describe("Gather Command", func() {
	var (
		mockDB     *MockDB
		mockClient *MockClient
		cmd        *commands.GatherCommand
	)

	BeforeEach(func() {
		mockDB = NewMockDB()
		mockClient = NewMockClient()
		cmd = commands.NewGatherCommand(mockDB, mockClient, "test-org-id", "", false)
	})

	Describe("Execute", func() {
		It("should gather projects, ignores, and issues", func() {
			// Set up mock client responses
			mockClient.GetProjectsFunc = func(orgID string) ([]snyk.Project, error) {
				Expect(orgID).To(Equal("test-org-id"))
				return []snyk.Project{
					{
						ID:     "test-project-id",
						Name:   "Test Project",
						Type:   "sast",
						Origin: "github",
						Target: snyk.Target{
							ID: "test-target-id",
						},
					},
				}, nil
			}

			mockClient.GetProjectTargetFunc = func(orgID, targetID string) (*snyk.Target, error) {
				Expect(orgID).To(Equal("test-org-id"))
				Expect(targetID).To(Equal("test-target-id"))
				return &snyk.Target{
					Name:   "test-repo",
					Branch: "main",
				}, nil
			}

			mockClient.GetIgnoresFunc = func(orgID, projectID string) ([]snyk.Ignore, error) {
				Expect(orgID).To(Equal("test-org-id"))
				Expect(projectID).To(Equal("test-project-id"))
				return []snyk.Ignore{
					{
						ID:         "test-ignore-id",
						Reason:     "test reason",
						ReasonType: "wont-fix",
						CreatedAt:  time.Now(),
						Path: []struct {
							Module string `json:"module"`
						}{
							{Module: "test-module"},
						},
						IgnoredBy: snyk.User{
							ID:    "test-user-id",
							Name:  "Test User",
							Email: "test@example.com",
						},
						DisregardIfFixable: false,
						IgnoreScope:        "project",
					},
				}, nil
			}

			mockClient.GetSASTIssuesFunc = func(orgID, projectID string) ([]snyk.SASTIssue, error) {
				Expect(orgID).To(Equal("test-org-id"))
				Expect(projectID).To(Equal(""))
				return []snyk.SASTIssue{
					{
						ID:   "test-ignore-id",
						Type: "issue",
						Attributes: struct {
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
						}{
							KeyAsset:               "test-asset-key",
							Ignored:                true,
							CreatedAt:              time.Now(),
							Description:            "Test Issue",
							EffectiveSeverityLevel: "medium",
							Key:                    "test-key",
							Status:                 "open",
							Title:                  "Test Issue Title",
							UpdatedAt:              time.Now(),
							Classes: []struct {
								ID     string `json:"id"`
								Source string `json:"source"`
								Type   string `json:"type"`
							}{
								{
									ID:     "CWE-123",
									Source: "CWE",
									Type:   "weakness",
								},
							},
							Coordinates: []struct {
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
							}{
								{
									IsFixableManually: false,
									IsFixableSnyk:     false,
									IsFixableUpstream: false,
									Representations: []struct {
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
									}{
										{
											SourceLocation: struct {
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
											}{
												CommitID: "test-commit",
												File:     "test.go",
												Region: struct {
													End struct {
														Column int `json:"column"`
														Line   int `json:"line"`
													} `json:"end"`
													Start struct {
														Column int `json:"column"`
														Line   int `json:"line"`
													} `json:"start"`
												}{
													End: struct {
														Column int `json:"column"`
														Line   int `json:"line"`
													}{
														Column: 20,
														Line:   100,
													},
													Start: struct {
														Column int `json:"column"`
														Line   int `json:"line"`
													}{
														Column: 1,
														Line:   100,
													},
												},
											},
										},
									},
								},
							},
							Problems: []struct {
								ID        string    `json:"id"`
								Source    string    `json:"source"`
								Type      string    `json:"type"`
								UpdatedAt time.Time `json:"updated_at"`
							}{
								{
									ID:        "test-problem-id",
									Source:    "SNYK",
									Type:      "vulnerability",
									UpdatedAt: time.Now(),
								},
							},
							Risk: struct {
								Factors []any `json:"factors"`
								Score   struct {
									Model string `json:"model"`
									Value int    `json:"value"`
								} `json:"score"`
							}{
								Factors: []any{},
								Score: struct {
									Model string `json:"model"`
									Value int    `json:"value"`
								}{
									Model: "v1",
									Value: 363,
								},
							},
						},
						Relationships: struct {
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
						}{
							Organization: struct {
								Data struct {
									ID   string `json:"id"`
									Type string `json:"type"`
								} `json:"data"`
								Links struct {
									Related string `json:"related"`
								} `json:"links"`
							}{
								Data: struct {
									ID   string `json:"id"`
									Type string `json:"type"`
								}{
									ID:   "test-org-id",
									Type: "organization",
								},
								Links: struct {
									Related string `json:"related"`
								}{
									Related: "/orgs/test-org-id",
								},
							},
							ScanItem: struct {
								Data struct {
									ID   string `json:"id"`
									Type string `json:"type"`
								} `json:"data"`
								Links struct {
									Related string `json:"related"`
								} `json:"links"`
							}{
								Data: struct {
									ID   string `json:"id"`
									Type string `json:"type"`
								}{
									ID:   "test-project-id",
									Type: "scan_item",
								},
								Links: struct {
									Related string `json:"related"`
								}{
									Related: "/scan-items/test-project-id",
								},
							},
						},
					},
				}, nil
			}

			// Set up mock QueryRow results
			mockDB.QueryRowFunc = func(query string, args ...interface{}) *sql.Row {
				// Create a mock DB connection to get a real sql.Row
				db, _ := sql.Open("sqlite3", ":memory:")
				defer db.Close()

				// Create a simple table for the query
				db.Exec("CREATE TABLE collection_metadata (count INTEGER)")
				db.Exec("INSERT INTO collection_metadata VALUES (1)")

				// Return a real sql.Row
				return db.QueryRow("SELECT 1")
			}

			// Set up mock Query results for Print method
			mockDB.QueryFunc = func(query string, args ...interface{}) (interface{}, error) {
				return &MockRows{}, nil
			}

			// Execute the command
			err := cmd.Execute()
			Expect(err).ToNot(HaveOccurred())

			// Verify that projects were stored
			Expect(mockDB.InsertProjectCalls).To(HaveLen(1))
			project := mockDB.InsertProjectCalls[0]
			Expect(project.ID).To(Equal("test-project-id"))
			Expect(project.OrgID).To(Equal("test-org-id"))
			Expect(project.Name).To(Equal("Test Project"))
			Expect(project.IsCliProject).To(BeFalse(), "GitHub origin project should not be marked as CLI project")

			// Verify target was stored
			var target snyk.Target
			err = json.Unmarshal([]byte(project.TargetInformation), &target)
			Expect(err).ToNot(HaveOccurred())
			Expect(target.Name).To(Equal("test-repo"))
			Expect(target.Branch).To(Equal("main"))

			// Verify that ignores were stored
			Expect(mockDB.InsertIgnoreCalls).To(HaveLen(1))
			ignore := mockDB.InsertIgnoreCalls[0]
			Expect(ignore.ID).To(Equal("test-ignore-id"))
			Expect(ignore.IssueID).To(Equal("test-ignore-id"))
			Expect(ignore.OrgID).To(Equal("test-org-id"))
			Expect(ignore.ProjectID).To(Equal("test-project-id"))
			Expect(ignore.Reason).To(Equal("test reason"))
			Expect(ignore.IgnoreType).To(Equal("wont-fix"))
			Expect(ignore.CreatedAt).To(BeTemporally("~", time.Now(), 1*time.Second))

			// Verify that issues were stored
			Expect(mockDB.InsertIssueCalls).To(HaveLen(1))
			insertedIssue := mockDB.InsertIssueCalls[0]
			Expect(insertedIssue.ID).To(Equal("test-ignore-id"))
			Expect(insertedIssue.OrgID).To(Equal("test-org-id"))
			Expect(insertedIssue.ProjectID).To(Equal("test-project-id"))
			Expect(insertedIssue.AssetKey).To(Equal("test-asset-key"))
			Expect(insertedIssue.ProjectKey).To(Equal("test-key"))

			// Verify that the bulk update query for asset keys was executed
			Expect(mockDB.ExecCalls).ToNot(BeEmpty(), "Expected Exec to be called for bulk update")
			bulkUpdateCallFound := false
			for _, call := range mockDB.ExecCalls {
				// Check if the query contains the core part of the update statement
				if strings.Contains(call.Query, "UPDATE ignores") && strings.Contains(call.Query, "SET asset_key = (") {
					// Check if the org ID argument is correct
					Expect(call.Args).To(HaveLen(1), "Expected 1 argument for the bulk update query")
					Expect(call.Args[0]).To(Equal("test-org-id"), "Expected the correct org ID argument")
					bulkUpdateCallFound = true
					break
				}
			}
			Expect(bulkUpdateCallFound).To(BeTrue(), "Expected to find the Exec call for bulk updating ignore asset keys")

			// Verify that collection metadata was updated
			Expect(mockDB.UpdateCollectionMetadataCalls).To(HaveLen(1))
		})

		It("should handle API errors gracefully", func() {
			// Set up mock client to return an error
			mockClient.GetProjectsFunc = func(orgID string) ([]snyk.Project, error) {
				return nil, errors.New("API error")
			}

			// Execute the command
			err := cmd.Execute()
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("failed to get projects: API error"))
		})

		It("should correctly identify CLI projects", func() {
			// Set up mock client responses for CLI project
			mockClient.GetProjectsFunc = func(orgID string) ([]snyk.Project, error) {
				Expect(orgID).To(Equal("test-org-id"))
				return []snyk.Project{
					{
						ID:     "cli-project-id",
						Name:   "CLI Project",
						Type:   "sast",
						Origin: "cli", // This is a CLI project
						Target: snyk.Target{
							ID: "cli-target-id",
						},
					},
				}, nil
			}

			mockClient.GetProjectTargetFunc = func(orgID, targetID string) (*snyk.Target, error) {
				Expect(orgID).To(Equal("test-org-id"))
				Expect(targetID).To(Equal("cli-target-id"))
				return &snyk.Target{
					Name:   "cli-repo",
					Branch: "main",
				}, nil
			}

			mockClient.GetIgnoresFunc = func(orgID, projectID string) ([]snyk.Ignore, error) {
				return []snyk.Ignore{}, nil // No ignores for simplicity
			}

			mockClient.GetSASTIssuesFunc = func(orgID, projectID string) ([]snyk.SASTIssue, error) {
				return []snyk.SASTIssue{}, nil // No issues for simplicity
			}

			// Set up mock QueryRow and Query results
			mockDB.QueryRowFunc = func(query string, args ...interface{}) *sql.Row {
				db, _ := sql.Open("sqlite3", ":memory:")
				defer db.Close()
				db.Exec("CREATE TABLE collection_metadata (count INTEGER)")
				db.Exec("INSERT INTO collection_metadata VALUES (1)")
				return db.QueryRow("SELECT 1")
			}

			mockDB.QueryFunc = func(query string, args ...interface{}) (interface{}, error) {
				return &MockRows{}, nil
			}

			// Execute the command
			err := cmd.Execute()
			Expect(err).ToNot(HaveOccurred())

			// Verify that the CLI project was stored correctly
			Expect(mockDB.InsertProjectCalls).To(HaveLen(1))
			project := mockDB.InsertProjectCalls[0]
			Expect(project.ID).To(Equal("cli-project-id"))
			Expect(project.Name).To(Equal("CLI Project"))
			Expect(project.IsCliProject).To(BeTrue(), "CLI origin project should be marked as CLI project")
		})

		It("should collect and store organizations when groupID is provided", func() {
			// Create a command with groupID
			cmdWithGroup := commands.NewGatherCommand(mockDB, mockClient, "", "test-group-id", false)

			// Set up mock client to return organizations
			mockClient.GetOrganizationsInGroupFunc = func(groupID string) ([]snyk.Organization, error) {
				Expect(groupID).To(Equal("test-group-id"))
				return []snyk.Organization{
					{
						ID:                    "org-1",
						Name:                  "Organization 1",
						Slug:                  "org-1-slug",
						GroupID:               "test-group-id",
						IsPersonal:            false,
						CreatedAt:             time.Now(),
						UpdatedAt:             time.Now(),
						AccessRequestsEnabled: true,
					},
					{
						ID:                    "org-2",
						Name:                  "Organization 2",
						Slug:                  "org-2-slug",
						GroupID:               "test-group-id",
						IsPersonal:            false,
						CreatedAt:             time.Now(),
						UpdatedAt:             time.Now(),
						AccessRequestsEnabled: true,
					},
				}, nil
			}

			// Set up mock client responses for each organization
			mockClient.GetProjectsFunc = func(orgID string) ([]snyk.Project, error) {
				return []snyk.Project{}, nil // Return empty projects for simplicity
			}

			mockClient.GetIgnoresFunc = func(orgID, projectID string) ([]snyk.Ignore, error) {
				return []snyk.Ignore{}, nil // Return empty ignores for simplicity
			}

			mockClient.GetSASTIssuesFunc = func(orgID, projectID string) ([]snyk.SASTIssue, error) {
				return []snyk.SASTIssue{}, nil // Return empty issues for simplicity
			}

			// Execute the command
			err := cmdWithGroup.Execute()
			Expect(err).ToNot(HaveOccurred())

			// Verify that organizations were stored
			Expect(mockDB.InsertOrganizationCalls).To(HaveLen(2))

			org1 := mockDB.InsertOrganizationCalls[0]
			Expect(org1.ID).To(Equal("org-1"))
			Expect(org1.Name).To(Equal("Organization 1"))
			Expect(org1.GroupID).To(Equal("test-group-id"))
			Expect(org1.IsPersonal).To(BeFalse())
			Expect(org1.AccessRequestsEnabled).To(BeTrue())

			org2 := mockDB.InsertOrganizationCalls[1]
			Expect(org2.ID).To(Equal("org-2"))
			Expect(org2.Name).To(Equal("Organization 2"))
			Expect(org2.GroupID).To(Equal("test-group-id"))
			Expect(org2.IsPersonal).To(BeFalse())
			Expect(org2.AccessRequestsEnabled).To(BeTrue())
		})

		It("should be idempotent and allow running gather multiple times", func() {
			// Set up mock client responses that will be called twice
			mockClient.GetProjectsFunc = func(orgID string) ([]snyk.Project, error) {
				Expect(orgID).To(Equal("test-org-id"))
				return []snyk.Project{
					{
						ID:     "test-project-id",
						Name:   "Test Project",
						Type:   "sast",
						Origin: "github",
						Target: snyk.Target{
							ID: "test-target-id",
						},
					},
				}, nil
			}

			mockClient.GetProjectTargetFunc = func(orgID, targetID string) (*snyk.Target, error) {
				Expect(orgID).To(Equal("test-org-id"))
				Expect(targetID).To(Equal("test-target-id"))
				return &snyk.Target{
					Name:   "test-repo",
					Branch: "main",
				}, nil
			}

			mockClient.GetIgnoresFunc = func(orgID, projectID string) ([]snyk.Ignore, error) {
				Expect(orgID).To(Equal("test-org-id"))
				Expect(projectID).To(Equal("test-project-id"))
				return []snyk.Ignore{
					{
						ID:         "test-ignore-id",
						Reason:     "test reason",
						ReasonType: "wont-fix",
						CreatedAt:  time.Now(),
						Path: []struct {
							Module string `json:"module"`
						}{
							{Module: "test-module"},
						},
						IgnoredBy: snyk.User{
							ID:    "test-user-id",
							Name:  "Test User",
							Email: "test@example.com",
						},
						DisregardIfFixable: false,
						IgnoreScope:        "project",
					},
				}, nil
			}

			mockClient.GetSASTIssuesFunc = func(orgID, projectID string) ([]snyk.SASTIssue, error) {
				Expect(orgID).To(Equal("test-org-id"))
				Expect(projectID).To(Equal(""))
				return []snyk.SASTIssue{
					{
						ID:   "test-ignore-id",
						Type: "issue",
						Attributes: struct {
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
						}{
							KeyAsset:               "test-asset-key",
							Ignored:                true,
							CreatedAt:              time.Now(),
							Description:            "Test Issue",
							EffectiveSeverityLevel: "medium",
							Key:                    "test-key",
							Status:                 "open",
							Title:                  "Test Issue Title",
							UpdatedAt:              time.Now(),
							Classes: []struct {
								ID     string `json:"id"`
								Source string `json:"source"`
								Type   string `json:"type"`
							}{
								{
									ID:     "CWE-123",
									Source: "CWE",
									Type:   "weakness",
								},
							},
							Coordinates: []struct {
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
							}{
								{
									IsFixableManually: false,
									IsFixableSnyk:     false,
									IsFixableUpstream: false,
									Representations: []struct {
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
									}{
										{
											SourceLocation: struct {
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
											}{
												CommitID: "test-commit",
												File:     "test.go",
												Region: struct {
													End struct {
														Column int `json:"column"`
														Line   int `json:"line"`
													} `json:"end"`
													Start struct {
														Column int `json:"column"`
														Line   int `json:"line"`
													} `json:"start"`
												}{
													End: struct {
														Column int `json:"column"`
														Line   int `json:"line"`
													}{
														Column: 20,
														Line:   100,
													},
													Start: struct {
														Column int `json:"column"`
														Line   int `json:"line"`
													}{
														Column: 1,
														Line:   100,
													},
												},
											},
										},
									},
								},
							},
							Problems: []struct {
								ID        string    `json:"id"`
								Source    string    `json:"source"`
								Type      string    `json:"type"`
								UpdatedAt time.Time `json:"updated_at"`
							}{
								{
									ID:        "test-problem-id",
									Source:    "SNYK",
									Type:      "vulnerability",
									UpdatedAt: time.Now(),
								},
							},
							Risk: struct {
								Factors []any `json:"factors"`
								Score   struct {
									Model string `json:"model"`
									Value int    `json:"value"`
								} `json:"score"`
							}{
								Factors: []any{},
								Score: struct {
									Model string `json:"model"`
									Value int    `json:"value"`
								}{
									Model: "v1",
									Value: 363,
								},
							},
						},
						Relationships: struct {
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
						}{
							Organization: struct {
								Data struct {
									ID   string `json:"id"`
									Type string `json:"type"`
								} `json:"data"`
								Links struct {
									Related string `json:"related"`
								} `json:"links"`
							}{
								Data: struct {
									ID   string `json:"id"`
									Type string `json:"type"`
								}{
									ID:   "test-org-id",
									Type: "organization",
								},
								Links: struct {
									Related string `json:"related"`
								}{
									Related: "/orgs/test-org-id",
								},
							},
							ScanItem: struct {
								Data struct {
									ID   string `json:"id"`
									Type string `json:"type"`
								} `json:"data"`
								Links struct {
									Related string `json:"related"`
								} `json:"links"`
							}{
								Data: struct {
									ID   string `json:"id"`
									Type string `json:"type"`
								}{
									ID:   "test-project-id",
									Type: "scan_item",
								},
								Links: struct {
									Related string `json:"related"`
								}{
									Related: "/scan-items/test-project-id",
								},
							},
						},
					},
				}, nil
			}

			// Set up mock QueryRow results
			mockDB.QueryRowFunc = func(query string, args ...interface{}) *sql.Row {
				// Create a mock DB connection to get a real sql.Row
				db, _ := sql.Open("sqlite3", ":memory:")
				defer db.Close()
				db.Exec("CREATE TABLE collection_metadata (count INTEGER)")
				db.Exec("INSERT INTO collection_metadata VALUES (1)")
				return db.QueryRow("SELECT 1")
			}

			// Set up mock Query results for Print method
			mockDB.QueryFunc = func(query string, args ...interface{}) (interface{}, error) {
				return &MockRows{}, nil
			}

			// Execute the command the first time
			err := cmd.Execute()
			Expect(err).ToNot(HaveOccurred())

			// Verify first execution results
			Expect(mockDB.InsertProjectCalls).To(HaveLen(1))
			Expect(mockDB.InsertIgnoreCalls).To(HaveLen(1))
			Expect(mockDB.InsertIssueCalls).To(HaveLen(1))
			Expect(mockDB.UpdateCollectionMetadataCalls).To(HaveLen(1))

			// Reset the call counters and execute the command a second time
			mockDB.InsertProjectCalls = []*database.Project{}
			mockDB.InsertIgnoreCalls = []*database.Ignore{}
			mockDB.InsertIssueCalls = []*database.Issue{}
			mockDB.UpdateCollectionMetadataCalls = []struct{}{}
			mockDB.ExecCalls = []MockExecCall{}

			// Execute the command the second time - this should not fail
			err = cmd.Execute()
			Expect(err).ToNot(HaveOccurred())

			// Verify second execution also worked (same data inserted again)
			Expect(mockDB.InsertProjectCalls).To(HaveLen(1))
			Expect(mockDB.InsertIgnoreCalls).To(HaveLen(1))
			Expect(mockDB.InsertIssueCalls).To(HaveLen(1))
			Expect(mockDB.UpdateCollectionMetadataCalls).To(HaveLen(1))

			// Verify the data is still the same
			project := mockDB.InsertProjectCalls[0]
			Expect(project.ID).To(Equal("test-project-id"))
			Expect(project.Name).To(Equal("Test Project"))

			ignore := mockDB.InsertIgnoreCalls[0]
			Expect(ignore.ID).To(Equal("test-ignore-id"))
			Expect(ignore.Reason).To(Equal("test reason"))

			issue := mockDB.InsertIssueCalls[0]
			Expect(issue.ID).To(Equal("test-ignore-id"))
			Expect(issue.AssetKey).To(Equal("test-asset-key"))
		})
	})
})

// Mock Row for database query row results
type MockRow struct {
	scanFunc func(dest ...interface{}) error
}

func (m *MockRow) Scan(dest ...interface{}) error {
	return m.scanFunc(dest...)
}

// Mock Rows for database query results
type MockRows struct {
	nextIndex int
	rows      [][]interface{}
	columns   []string
	closed    bool
}

func (m *MockRows) Next() bool {
	if m.nextIndex >= len(m.rows) {
		return false
	}
	m.nextIndex++
	return true
}

func (m *MockRows) Scan(dest ...interface{}) error {
	if m.nextIndex == 0 || m.nextIndex > len(m.rows) {
		return errors.New("invalid row index")
	}

	row := m.rows[m.nextIndex-1]
	for i, val := range row {
		if i < len(dest) {
			switch v := dest[i].(type) {
			case *string:
				if s, ok := val.(string); ok {
					*v = s
				}
			case *int:
				if n, ok := val.(int); ok {
					*v = n
				}
			}
		}
	}

	return nil
}

func (m *MockRows) Close() error {
	m.closed = true
	return nil
}

// Mock DB implementation
type MockDB struct {
	GetIgnoresByOrgIDCalls        []string
	InsertIgnoreCalls             []*database.Ignore
	InsertIssueCalls              []*database.Issue
	InsertProjectCalls            []*database.Project
	InsertOrganizationCalls       []*database.Organization
	UpdateCollectionMetadataCalls []struct{}
	ExecCalls                     []MockExecCall
	GetIgnoresByOrgIDFunc         func(orgID string) ([]*database.Ignore, error)
	InsertIgnoreFunc              func(ignore *database.Ignore) error
	InsertIssueFunc               func(issue *database.Issue) error
	InsertProjectFunc             func(project *database.Project) error
	InsertPolicyFunc              func(policy *database.Policy) error
	InsertOrganizationFunc        func(org *database.Organization) error
	GetIssuesByOrgIDFunc          func(orgID string) ([]*database.Issue, error)
	GetProjectsByOrgIDFunc        func(orgID string) ([]*database.Project, error)
	GetPoliciesByOrgIDFunc        func(orgID string) ([]*database.Policy, error)
	GetOrganizationsByGroupIDFunc func(groupID string) ([]*database.Organization, error)
	GetAllOrganizationsFunc       func() ([]*database.Organization, error)
	UpdateCollectionMetadataFunc  func(time.Time, string, string) error
	ExecFunc                      func(query string, args ...interface{}) (interface{}, error)
	QueryRowFunc                  func(query string, args ...interface{}) *sql.Row
	QueryFunc                     func(query string, args ...interface{}) (interface{}, error)
	BeginFunc                     func() (interface{}, error)
}

type MockExecCall struct {
	Query string
	Args  []interface{}
}

func NewMockDB() *MockDB {
	// Create a mock DB connection to get a real sql.Row for the default QueryRowFunc
	sqlDB, _ := sql.Open("sqlite3", ":memory:")

	return &MockDB{
		GetIgnoresByOrgIDCalls:        []string{},
		InsertIgnoreCalls:             []*database.Ignore{},
		InsertIssueCalls:              []*database.Issue{},
		InsertProjectCalls:            []*database.Project{},
		InsertOrganizationCalls:       []*database.Organization{},
		UpdateCollectionMetadataCalls: []struct{}{},
		ExecCalls:                     []MockExecCall{},
		GetIgnoresByOrgIDFunc:         func(orgID string) ([]*database.Ignore, error) { return []*database.Ignore{}, nil },
		InsertIgnoreFunc:              func(ignore *database.Ignore) error { return nil },
		InsertIssueFunc:               func(issue *database.Issue) error { return nil },
		InsertProjectFunc:             func(project *database.Project) error { return nil },
		InsertPolicyFunc:              func(policy *database.Policy) error { return nil },
		InsertOrganizationFunc:        func(org *database.Organization) error { return nil },
		GetIssuesByOrgIDFunc:          func(orgID string) ([]*database.Issue, error) { return []*database.Issue{}, nil },
		GetProjectsByOrgIDFunc:        func(orgID string) ([]*database.Project, error) { return []*database.Project{}, nil },
		GetPoliciesByOrgIDFunc:        func(orgID string) ([]*database.Policy, error) { return []*database.Policy{}, nil },
		GetOrganizationsByGroupIDFunc: func(groupID string) ([]*database.Organization, error) { return []*database.Organization{}, nil },
		GetAllOrganizationsFunc:       func() ([]*database.Organization, error) { return []*database.Organization{}, nil },
		UpdateCollectionMetadataFunc:  func(time.Time, string, string) error { return nil },
		ExecFunc:                      func(query string, args ...interface{}) (interface{}, error) { return nil, nil },
		QueryRowFunc:                  func(query string, args ...interface{}) *sql.Row { return sqlDB.QueryRow("SELECT 1") },
		QueryFunc:                     func(query string, args ...interface{}) (interface{}, error) { return nil, nil },
		BeginFunc:                     func() (interface{}, error) { return nil, nil },
	}
}

func (m *MockDB) GetIgnoresByOrgID(orgID string) ([]*database.Ignore, error) {
	m.GetIgnoresByOrgIDCalls = append(m.GetIgnoresByOrgIDCalls, orgID)
	return m.GetIgnoresByOrgIDFunc(orgID)
}

func (m *MockDB) InsertIgnore(ignore *database.Ignore) error {
	m.InsertIgnoreCalls = append(m.InsertIgnoreCalls, ignore)
	return m.InsertIgnoreFunc(ignore)
}

func (m *MockDB) InsertIssue(issue *database.Issue) error {
	m.InsertIssueCalls = append(m.InsertIssueCalls, issue)
	return m.InsertIssueFunc(issue)
}

func (m *MockDB) InsertProject(project *database.Project) error {
	m.InsertProjectCalls = append(m.InsertProjectCalls, project)
	return m.InsertProjectFunc(project)
}

func (m *MockDB) UpdateCollectionMetadata(completedAt time.Time, collectionVersion, apiVersion string) error {
	m.UpdateCollectionMetadataCalls = append(m.UpdateCollectionMetadataCalls, struct{}{})
	return m.UpdateCollectionMetadataFunc(completedAt, collectionVersion, apiVersion)
}

func (m *MockDB) Exec(query string, args ...interface{}) (interface{}, error) {
	m.ExecCalls = append(m.ExecCalls, MockExecCall{Query: query, Args: args})
	return m.ExecFunc(query, args...)
}

func (m *MockDB) QueryRow(query string, args ...interface{}) *sql.Row {
	return m.QueryRowFunc(query, args...)
}

func (m *MockDB) Query(query string, args ...interface{}) (interface{}, error) {
	return m.QueryFunc(query, args...)
}

func (m *MockDB) Close() error {
	return nil
}

// InsertPolicy implements the DatabaseInterface
func (m *MockDB) InsertPolicy(policy *database.Policy) error {
	return m.InsertPolicyFunc(policy)
}

// GetIssuesByOrgID implements the DatabaseInterface
func (m *MockDB) GetIssuesByOrgID(orgID string) ([]*database.Issue, error) {
	return m.GetIssuesByOrgIDFunc(orgID)
}

// GetProjectsByOrgID implements the DatabaseInterface
func (m *MockDB) GetProjectsByOrgID(orgID string) ([]*database.Project, error) {
	return m.GetProjectsByOrgIDFunc(orgID)
}

// GetPoliciesByOrgID implements the DatabaseInterface
func (m *MockDB) GetPoliciesByOrgID(orgID string) ([]*database.Policy, error) {
	return m.GetPoliciesByOrgIDFunc(orgID)
}

// InsertOrganization implements the DatabaseInterface
func (m *MockDB) InsertOrganization(org *database.Organization) error {
	m.InsertOrganizationCalls = append(m.InsertOrganizationCalls, org)
	return m.InsertOrganizationFunc(org)
}

// GetOrganizationsByGroupID implements the DatabaseInterface
func (m *MockDB) GetOrganizationsByGroupID(groupID string) ([]*database.Organization, error) {
	return m.GetOrganizationsByGroupIDFunc(groupID)
}

// GetAllOrganizations implements the DatabaseInterface
func (m *MockDB) GetAllOrganizations() ([]*database.Organization, error) {
	return m.GetAllOrganizationsFunc()
}

// Begin implements the DatabaseInterface
func (m *MockDB) Begin() (interface{}, error) {
	if m.BeginFunc != nil {
		return m.BeginFunc()
	}
	tx := &MockTransaction{
		ExecFunc: func(query string, args ...interface{}) (interface{}, error) {
			return nil, nil
		},
		CommitFunc: func() error {
			return nil
		},
		RollbackFunc: func() error {
			return nil
		},
	}
	return tx, nil
}

// MockTransaction is a mock implementation of TransactionInterface
type MockTransaction struct {
	ExecCalls      []MockExecCall
	ExecFunc       func(query string, args ...interface{}) (interface{}, error)
	CommitFunc     func() error
	RollbackFunc   func() error
	CommitCalled   bool
	RollbackCalled bool
}

func (m *MockTransaction) Exec(query string, args ...interface{}) (interface{}, error) {
	m.ExecCalls = append(m.ExecCalls, MockExecCall{Query: query, Args: args})
	return m.ExecFunc(query, args...)
}

func (m *MockTransaction) Commit() error {
	m.CommitCalled = true
	return m.CommitFunc()
}

func (m *MockTransaction) Rollback() error {
	m.RollbackCalled = true
	return m.RollbackFunc()
}

// Mock Client implementation
type MockClient struct {
	GetProjectsFunc             func(orgID string) ([]snyk.Project, error)
	GetIgnoresFunc              func(orgID, projectID string) ([]snyk.Ignore, error)
	GetProjectTargetFunc        func(orgID, targetID string) (*snyk.Target, error)
	GetSASTIssuesFunc           func(orgID, projectID string) ([]snyk.SASTIssue, error)
	GetOrganizationsInGroupFunc func(groupID string) ([]snyk.Organization, error)
	CreatePolicyFunc            func(orgID string, attributes snyk.CreatePolicyAttributes, meta map[string]interface{}) (*snyk.Policy, error)
	RetestProjectFunc           func(orgID string, target *snyk.Target) error
	DeleteIgnoreFunc            func(orgID, projectID, ignoreID string) error
	CreateIgnoreFunc            func(orgID, projectID string, ignore snyk.Ignore) error
	DeletePolicyFunc            func(orgID string, policyID string) error
}

func NewMockClient() *MockClient {
	return &MockClient{
		GetProjectsFunc:             func(orgID string) ([]snyk.Project, error) { return []snyk.Project{}, nil },
		GetIgnoresFunc:              func(orgID, projectID string) ([]snyk.Ignore, error) { return []snyk.Ignore{}, nil },
		GetProjectTargetFunc:        func(orgID, targetID string) (*snyk.Target, error) { return &snyk.Target{}, nil },
		GetSASTIssuesFunc:           func(orgID, projectID string) ([]snyk.SASTIssue, error) { return []snyk.SASTIssue{}, nil },
		GetOrganizationsInGroupFunc: func(groupID string) ([]snyk.Organization, error) { return []snyk.Organization{}, nil },
		CreatePolicyFunc: func(orgID string, attributes snyk.CreatePolicyAttributes, meta map[string]interface{}) (*snyk.Policy, error) {
			return &snyk.Policy{ID: "mock-policy-id"}, nil
		},
		RetestProjectFunc: func(orgID string, target *snyk.Target) error { return nil },
		DeleteIgnoreFunc:  func(orgID, projectID, ignoreID string) error { return nil },
		CreateIgnoreFunc:  func(orgID, projectID string, ignore snyk.Ignore) error { return nil },
		DeletePolicyFunc:  func(orgID string, policyID string) error { return nil },
	}
}

func (m *MockClient) GetProjects(orgID string) ([]snyk.Project, error) {
	return m.GetProjectsFunc(orgID)
}

func (m *MockClient) GetIgnores(orgID, projectID string) ([]snyk.Ignore, error) {
	return m.GetIgnoresFunc(orgID, projectID)
}

func (m *MockClient) GetProjectTarget(orgID, targetID string) (*snyk.Target, error) {
	return m.GetProjectTargetFunc(orgID, targetID)
}

func (m *MockClient) GetSASTIssues(orgID, projectID string) ([]snyk.SASTIssue, error) {
	return m.GetSASTIssuesFunc(orgID, projectID)
}

// GetOrganizationsInGroup implements the ClientInterface
func (m *MockClient) GetOrganizationsInGroup(groupID string) ([]snyk.Organization, error) {
	return m.GetOrganizationsInGroupFunc(groupID)
}

// CreatePolicy implements the ClientInterface
func (m *MockClient) CreatePolicy(orgID string, attributes snyk.CreatePolicyAttributes, meta map[string]interface{}) (*snyk.Policy, error) {
	return m.CreatePolicyFunc(orgID, attributes, meta)
}

// RetestProject implements the ClientInterface
func (m *MockClient) RetestProject(orgID string, target *snyk.Target) error {
	return m.RetestProjectFunc(orgID, target)
}

// DeleteIgnore implements the ClientInterface
func (m *MockClient) DeleteIgnore(orgID, projectID, ignoreID string) error {
	return m.DeleteIgnoreFunc(orgID, projectID, ignoreID)
}

// DeletePolicy implements the ClientInterface
func (m *MockClient) DeletePolicy(orgID string, policyID string) error {
	return m.DeletePolicyFunc(orgID, policyID)
}

// CreateIgnore implements the ClientInterface
func (m *MockClient) CreateIgnore(orgID string, projectID string, ignore snyk.Ignore) error {
	return m.CreateIgnoreFunc(orgID, projectID, ignore)
}
