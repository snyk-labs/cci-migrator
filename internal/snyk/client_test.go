package snyk

import (
	"encoding/json"
	"fmt"
	"io"
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
		// Default server setup for GetProjects, can be overridden in specific Describe blocks
		server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// This is a generic handler, specific tests might override this.
			// For GetProjects initial setup:
			if r.URL.Path == "/orgs/test-org/projects" {
				Expect(r.Method).To(Equal("GET"))
				Expect(r.Header.Get("Authorization")).To(Equal("token test-token"))
				Expect(r.Header.Get("Accept")).To(Equal("application/vnd.api+json"))
				query := r.URL.Query()
				Expect(query.Get("version")).To(Equal("2024-10-15"))
				Expect(query.Get("types")).To(Equal("sast"))

				response := ProjectsResponse{
					Data: []ProjectResponse{
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
							Relationships: struct {
								Target struct {
									Data struct {
										Type string `json:"type"`
										ID   string `json:"id"`
									} `json:"data"`
								} `json:"target"`
							}{
								Target: struct {
									Data struct {
										Type string `json:"type"`
										ID   string `json:"id"`
									} `json:"data"`
								}{
									Data: struct {
										Type string `json:"type"`
										ID   string `json:"id"`
									}{
										Type: "target",
										ID:   "test-target-id",
									},
								},
							},
						},
					},
				}
				w.Header().Set("Content-Type", "application/vnd.api+json")
				json.NewEncoder(w).Encode(response)
				return
			}

			// For GetIgnores initial setup:
			if r.URL.Path == "/org/test-org/project/test-project/ignores" {
				Expect(r.Method).To(Equal("GET"))
				Expect(r.Header.Get("Authorization")).To(Equal("token test-token"))

				// Create a response that matches the real-world format
				ignoreID := "fd9809b0-3482-4fb5-8785-25f61ec18cdd"
				response := map[string][]map[string]interface{}{
					ignoreID: {
						{
							"reason":             "doesn't matter",
							"created":            "2025-03-01T00:05:15.615Z",
							"reasonType":         "not-vulnerable",
							"disregardIfFixable": false,
							"ignoreScope":        "project",
							"ignoredBy": map[string]interface{}{
								"id":    "user-123",
								"name":  "Test User",
								"email": "test@example.com",
							},
							"path": []map[string]string{
								{
									"module": "*",
								},
							},
						},
					},
				}

				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(response)
				return
			}

			// Default to not found if no specific handler matches
			w.WriteHeader(http.StatusNotFound)
			fmt.Fprintf(w, "Endpoint %s not handled by this test server", r.URL.Path)
		}))

		client = &Client{
			HTTPClient:  http.DefaultClient,
			Token:       "test-token",
			V1BaseURL:   server.URL, // For older APIs if any
			RestBaseURL: server.URL,
		}
	})

	AfterEach(func() {
		server.Close()
	})

	Describe("GetProjects", func() {
		It("should retrieve projects successfully", func() {
			projects, err := client.GetProjects("test-org")
			Expect(err).NotTo(HaveOccurred())
			Expect(projects).To(HaveLen(1))

			project := projects[0]
			Expect(project.ID).To(Equal("test-project-id"))
			Expect(project.Name).To(Equal("Test Project"))
		})

		It("should correctly unmarshal complex JSON response", func() {
			server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				Expect(r.Method).To(Equal("GET"))
				Expect(r.Header.Get("Authorization")).To(Equal("token test-token"))
				Expect(r.Header.Get("Accept")).To(Equal("application/vnd.api+json"))

				rawResponse := `{
					"jsonapi": {
						"version": "1.0"
					},
					"data": [
						{
							"type": "project",
							"id": "d736dc68-45be-458b-b1af-426fc5cf79c8",
							"meta": {},
							"attributes": {
								"name": "goofy/nodejs-goof(main)",
								"type": "sast",
								"target_file": "",
								"target_reference": "main",
								"origin": "bitbucket-server",
								"created": "2025-03-20T16:33:54.128Z",
								"status": "active",
								"business_criticality": [],
								"environment": [],
								"lifecycle": [],
								"tags": []
							},
							"relationships": {
								"organization": {
									"data": {
										"type": "org",
										"id": "3f1f2737-d0f0-4222-805d-264bd94b87b0"
									}
								},
								"target": {
									"data": {
										"type": "target",
										"id": "cc3d2e15-63c6-46bf-8d0f-62f1fef44203"
									}
								}
							}
						}
					]
				}`

				w.Header().Set("Content-Type", "application/vnd.api+json")
				w.Write([]byte(rawResponse))
			})

			projects, err := client.GetProjects("test-org")
			Expect(err).NotTo(HaveOccurred())
			Expect(projects).To(HaveLen(1))

			project := projects[0]
			Expect(project.ID).To(Equal("d736dc68-45be-458b-b1af-426fc5cf79c8"))
			Expect(project.Name).To(Equal("goofy/nodejs-goof(main)"))
			Expect(project.Type).To(Equal("sast"))
			Expect(project.Origin).To(Equal("bitbucket-server"))
			Expect(project.Status).To(Equal("active"))
			Expect(project.Created).To(Equal(time.Date(2025, 3, 20, 16, 33, 54, 128000000, time.UTC)))
			Expect(project.BusinessCriticality).To(BeEmpty())
			Expect(project.Environment).To(BeEmpty())
			Expect(project.Lifecycle).To(BeEmpty())
			Expect(project.Tags).To(BeEmpty())
		})

		It("should correctly set target ID from relationships", func() {
			server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				Expect(r.Method).To(Equal("GET"))
				Expect(r.Header.Get("Authorization")).To(Equal("token test-token"))
				Expect(r.Header.Get("Accept")).To(Equal("application/vnd.api+json"))

				rawResponse := `{
					"jsonapi": {
						"version": "1.0"
					},
					"data": [
						{
							"type": "project",
							"id": "d736dc68-45be-458b-b1af-426fc5cf79c8",
							"meta": {},
							"attributes": {
								"name": "goofy/nodejs-goof(main)",
								"type": "sast",
								"target_file": "",
								"target_reference": "main",
								"origin": "bitbucket-server",
								"created": "2025-03-20T16:33:54.128Z",
								"status": "active",
								"target": {
									"id": "wrong-target-id",
									"name": "wrong-target-name"
								}
							},
							"relationships": {
								"target": {
									"data": {
										"type": "target",
										"id": "cc3d2e15-63c6-46bf-8d0f-62f1fef44203"
									}
								}
							}
						}
					]
				}`

				w.Header().Set("Content-Type", "application/vnd.api+json")
				w.Write([]byte(rawResponse))
			})

			projects, err := client.GetProjects("test-org")
			Expect(err).NotTo(HaveOccurred())
			Expect(projects).To(HaveLen(1))

			project := projects[0]
			Expect(project.Target.ID).To(Equal("cc3d2e15-63c6-46bf-8d0f-62f1fef44203"), "Target ID should be set from relationships, not attributes")
		})

		It("should ignore target information from attributes section", func() {
			server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				Expect(r.Method).To(Equal("GET"))
				Expect(r.Header.Get("Authorization")).To(Equal("token test-token"))
				Expect(r.Header.Get("Accept")).To(Equal("application/vnd.api+json"))

				rawResponse := `{
					"jsonapi": {
						"version": "1.0"
					},
					"data": [
						{
							"type": "project",
							"id": "d736dc68-45be-458b-b1af-426fc5cf79c8",
							"meta": {},
							"attributes": {
								"name": "goofy/nodejs-goof(main)",
								"type": "sast",
								"target_file": "",
								"target_reference": "main",
								"origin": "bitbucket-server",
								"created": "2025-03-20T16:33:54.128Z",
								"status": "active",
								"target": {
									"id": "wrong-target-id",
									"name": "wrong-target-name",
									"branch": "wrong-branch",
									"owner": "wrong-owner",
									"repo": "wrong-repo",
									"url": "wrong-url",
									"origin": "wrong-origin",
									"source": "wrong-source"
								}
							}
						}
					]
				}`

				w.Header().Set("Content-Type", "application/vnd.api+json")
				w.Write([]byte(rawResponse))
			})

			projects, err := client.GetProjects("test-org")
			Expect(err).NotTo(HaveOccurred())
			Expect(projects).To(HaveLen(1))

			project := projects[0]
			Expect(project.Target.ID).To(BeEmpty(), "Target ID should be empty since it was only in attributes")
			Expect(project.Target.Name).To(BeEmpty(), "Target name should be empty since it was only in attributes")
			Expect(project.Target.Branch).To(BeEmpty(), "Target branch should be empty since it was only in attributes")
			Expect(project.Target.Owner).To(BeEmpty(), "Target owner should be empty since it was only in attributes")
			Expect(project.Target.Repo).To(BeEmpty(), "Target repo should be empty since it was only in attributes")
			Expect(project.Target.URL).To(BeEmpty(), "Target URL should be empty since it was only in attributes")
			Expect(project.Target.Origin).To(BeEmpty(), "Target origin should be empty since it was only in attributes")
			Expect(project.Target.Source).To(BeEmpty(), "Target source should be empty since it was only in attributes")
		})

		It("should retrieve ignores successfully", func() {
			ignores, err := client.GetIgnores("test-org", "test-project")
			Expect(err).NotTo(HaveOccurred())
			Expect(ignores).To(HaveLen(1))
			Expect(ignores[0].ID).To(Equal("fd9809b0-3482-4fb5-8785-25f61ec18cdd"))
			Expect(ignores[0].Reason).To(Equal("doesn't matter"))
			Expect(ignores[0].ReasonType).To(Equal("not-vulnerable"))
			Expect(ignores[0].DisregardIfFixable).To(BeFalse())
			Expect(ignores[0].IgnoreScope).To(Equal("project"))
			Expect(ignores[0].IgnoredBy.ID).To(Equal("user-123"))
			Expect(ignores[0].Path).To(HaveLen(1))
			Expect(ignores[0].Path[0].Module).To(Equal("*"))
		})
	})

	Describe("RetestProject", func() {
		var target *Target

		BeforeEach(func() {
			target = &Target{
				Owner:         "test-owner",
				Repo:          "test-repo",
				Branch:        "main",
				IntegrationID: "test-integration-id",
			}
		})

		It("should create payload and retest successfully", func() {
			server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				Expect(r.Method).To(Equal("POST"))
				Expect(r.URL.Path).To(Equal("/org/test-org/integrations/test-integration-id/import"))
				Expect(r.Header.Get("Authorization")).To(Equal("token test-token"))
				Expect(r.Header.Get("Content-Type")).To(Equal("application/json"))

				body, _ := io.ReadAll(r.Body)
				var payload map[string]interface{}
				json.Unmarshal(body, &payload)

				targetPayload := payload["target"].(map[string]interface{})
				Expect(targetPayload["owner"]).To(Equal("test-owner"))
				Expect(targetPayload["name"]).To(Equal("test-repo"))
				Expect(targetPayload["branch"]).To(Equal("main"))

				w.WriteHeader(http.StatusOK)
			})

			err := client.RetestProject("test-org", target)
			Expect(err).NotTo(HaveOccurred())
		})

		It("should return error when integration_id is missing", func() {
			target.IntegrationID = ""
			err := client.RetestProject("test-org", target)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("target missing integration_id"))
		})

		It("should return error when import API call fails", func() {
			server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusBadRequest)
			})

			err := client.RetestProject("test-org", target)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("unexpected status code: 400"))
		})
	})

	Describe("DeleteIgnore", func() {
		BeforeEach(func() {
			server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				Expect(r.Method).To(Equal("DELETE"))
				Expect(r.URL.Path).To(Equal("/org/test-org/project/test-project/ignore/test-ignore-id"))
				Expect(r.Header.Get("Authorization")).To(Equal("token test-token"))

				w.WriteHeader(http.StatusNoContent)
			})
		})

		It("should delete an ignore successfully", func() {
			err := client.DeleteIgnore("test-org", "test-project", "test-ignore-id")
			Expect(err).NotTo(HaveOccurred())
		})
	})

	Describe("GetPolicies", func() {
		BeforeEach(func() {
			server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				Expect(r.Method).To(Equal("GET"))
				Expect(r.Header.Get("Authorization")).To(Equal("token test-token"))
				Expect(r.Header.Get("Accept")).To(Equal("application/vnd.api+json"))
				Expect(r.URL.Path).To(Equal("/orgs/test-org/policies"))
				Expect(r.URL.Query().Get("version")).To(Equal("2024-10-15"))

				now := time.Now().UTC().Truncate(time.Second) // Ensure consistent time for comparison
				response := PoliciesResponse{
					Data: []PolicyResponse{
						{
							ID:   "test-policy-id-1",
							Type: "policy",
							Attributes: Policy{
								Name: "Policy One",
								Action: Action{
									Data: ActionData{
										IgnoreType: "wont-fix",
										Reason:     "Reason for policy one",
									},
								},
								ActionType: "ignore",
								ConditionsGroup: ConditionsGroup{
									Conditions: []Condition{
										{
											Field:    "snyk/asset/finding/v1",
											Operator: "includes",
											Value:    "CVE-2023-12345",
										},
									},
									LogicalOperator: "and",
								},
								CreatedAt: now,
								CreatedBy: UserIdentity{
									ID:    "user-creator-id",
									Email: "creator@example.com",
									Name:  "Creator User",
								},
								Review:    "pending",
								UpdatedAt: now,
							},
						},
					},
				}
				w.Header().Set("Content-Type", "application/vnd.api+json")
				json.NewEncoder(w).Encode(response)
			})
		})

		It("should retrieve policies successfully", func() {
			policies, err := client.GetPolicies("test-org", nil)
			Expect(err).NotTo(HaveOccurred())
			Expect(policies).To(HaveLen(1))

			policy := policies[0]
			Expect(policy.ID).To(Equal("test-policy-id-1"))
			Expect(policy.Name).To(Equal("Policy One"))
			Expect(policy.ActionType).To(Equal("ignore"))
			Expect(policy.Action.Data.IgnoreType).To(Equal("wont-fix"))
			Expect(policy.Action.Data.Reason).To(Equal("Reason for policy one"))
			Expect(policy.ConditionsGroup.Conditions).To(HaveLen(1))
			Expect(policy.ConditionsGroup.Conditions[0].Value).To(Equal("CVE-2023-12345"))
			Expect(policy.CreatedBy.ID).To(Equal("user-creator-id"))
			Expect(policy.Review).To(Equal("pending"))
			Expect(policy.CreatedAt).To(BeTemporally("~", time.Now().UTC(), time.Second))
			Expect(policy.UpdatedAt).To(BeTemporally("~", time.Now().UTC(), time.Second))
		})
	})

	Describe("GetPolicy", func() {
		BeforeEach(func() {
			server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				Expect(r.Method).To(Equal("GET"))
				Expect(r.URL.Path).To(Equal("/orgs/test-org/policies/test-policy-id-fetch"))

				now := time.Now().UTC().Truncate(time.Second)
				expires := now.Add(7 * 24 * time.Hour)
				response := struct {
					Data PolicyResponse `json:"data"`
				}{
					Data: PolicyResponse{
						ID:   "test-policy-id-fetch",
						Type: "policy",
						Attributes: Policy{
							Name: "Fetched Policy",
							Action: Action{
								Data: ActionData{
									Expires:    &expires,
									IgnoreType: "not-vulnerable",
									Reason:     "Reason for fetched policy",
								},
							},
							ActionType: "ignore",
							ConditionsGroup: ConditionsGroup{
								Conditions: []Condition{
									{
										Field:    "snyk/org/id/v1",
										Operator: "equals",
										Value:    "test-org",
									},
								},
								LogicalOperator: "and",
							},
							CreatedAt: now,
							CreatedBy: UserIdentity{
								ID:    "user-fetcher-id",
								Email: "fetcher@example.com",
								Name:  "Fetcher User",
							},
							Review:    "approved",
							UpdatedAt: now,
						},
					},
				}
				w.Header().Set("Content-Type", "application/vnd.api+json")
				json.NewEncoder(w).Encode(response)
			})
		})

		It("should retrieve a specific policy successfully", func() {
			policy, err := client.GetPolicy("test-org", "test-policy-id-fetch")
			Expect(err).NotTo(HaveOccurred())
			Expect(policy).NotTo(BeNil())

			Expect(policy.ID).To(Equal("test-policy-id-fetch"))
			Expect(policy.Name).To(Equal("Fetched Policy"))
			Expect(policy.Action.Data.IgnoreType).To(Equal("not-vulnerable"))
			Expect(policy.Action.Data.Expires).NotTo(BeNil())
			Expect(*policy.Action.Data.Expires).To(BeTemporally("~", time.Now().UTC().Add(7*24*time.Hour), time.Second))
			Expect(policy.Review).To(Equal("approved"))
		})
	})

	Describe("CreatePolicy", func() {
		var (
			expiresAtTime time.Time
			createAttrs   CreatePolicyAttributes
			meta          map[string]interface{}
		)
		BeforeEach(func() {
			expiresAtTime = time.Now().UTC().Add(30 * 24 * time.Hour).Truncate(time.Second)
			createAttrs = CreatePolicyAttributes{
				Name: "New Test Policy",
				Action: Action{
					Data: ActionData{
						Expires:    &expiresAtTime,
						IgnoreType: "wont-fix",
						Reason:     "This is a test reason for creation.",
					},
				},
				ActionType: "ignore",
				ConditionsGroup: ConditionsGroup{
					Conditions: []Condition{
						{
							Field:    "snyk/asset/finding/v1",
							Operator: "includes",
							Value:    "SNYK-TEST-123",
						},
					},
					LogicalOperator: "and",
				},
			}
			meta = map[string]interface{}{"source": "ginkgo-test"}

			server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				Expect(r.Method).To(Equal("POST"))
				Expect(r.URL.Path).To(Equal("/orgs/test-org/policies"))
				Expect(r.Header.Get("Content-Type")).To(Equal("application/vnd.api+json"))

				var payload CreatePolicyPayload
				err := json.NewDecoder(r.Body).Decode(&payload)
				Expect(err).NotTo(HaveOccurred())

				Expect(payload.Data.Type).To(Equal("policy"))
				Expect(payload.Data.Attributes.Name).To(Equal(createAttrs.Name))
				Expect(payload.Data.Attributes.Action.Data.IgnoreType).To(Equal(createAttrs.Action.Data.IgnoreType))
				Expect(payload.Data.Attributes.Action.Data.Reason).To(Equal(createAttrs.Action.Data.Reason))
				Expect(*payload.Data.Attributes.Action.Data.Expires).To(BeTemporally("~", expiresAtTime, time.Second))
				Expect(payload.Data.Attributes.ActionType).To(Equal(createAttrs.ActionType))
				Expect(payload.Data.Attributes.ConditionsGroup.LogicalOperator).To(Equal(createAttrs.ConditionsGroup.LogicalOperator))
				Expect(payload.Data.Attributes.ConditionsGroup.Conditions).To(HaveLen(1))
				Expect(payload.Data.Attributes.ConditionsGroup.Conditions[0].Value).To(Equal(createAttrs.ConditionsGroup.Conditions[0].Value))
				Expect(payload.Data.Meta["source"]).To(Equal(meta["source"]))

				now := time.Now().UTC().Truncate(time.Second)
				response := struct {
					Data PolicyResponse `json:"data"`
				}{
					Data: PolicyResponse{
						ID:   "new-policy-id-from-test",
						Type: "policy",
						Attributes: Policy{
							Name:            createAttrs.Name,
							Action:          createAttrs.Action, // Echo back the action
							ActionType:      createAttrs.ActionType,
							ConditionsGroup: createAttrs.ConditionsGroup,
							CreatedAt:       now,
							CreatedBy: UserIdentity{
								ID:    "test-user-id",
								Email: "testuser@example.com",
								Name:  "Test User",
							},
							Review:    "pending",
							UpdatedAt: now,
						},
					},
				}
				w.WriteHeader(http.StatusCreated)
				w.Header().Set("Content-Type", "application/vnd.api+json")
				json.NewEncoder(w).Encode(response)
			})
		})

		It("should create a policy successfully", func() {
			createdPolicy, err := client.CreatePolicy("test-org", createAttrs, meta)
			Expect(err).NotTo(HaveOccurred())
			Expect(createdPolicy).NotTo(BeNil())

			Expect(createdPolicy.ID).To(Equal("new-policy-id-from-test"))
			Expect(createdPolicy.Name).To(Equal(createAttrs.Name))
			Expect(createdPolicy.Action.Data.Reason).To(Equal(createAttrs.Action.Data.Reason))
			Expect(createdPolicy.ActionType).To(Equal(createAttrs.ActionType))
			Expect(createdPolicy.Review).To(Equal("pending"))
			Expect(createdPolicy.CreatedBy.ID).To(Equal("test-user-id"))
			Expect(createdPolicy.CreatedAt).To(BeTemporally("~", time.Now().UTC(), time.Second))
		})
	})

	Describe("UpdatePolicy", func() {
		var (
			policyIDToUpdate string
			updateAttrs      UpdatePolicyAttributes
			meta             map[string]interface{}
			updatedExpiresAt time.Time
		)
		BeforeEach(func() {
			policyIDToUpdate = "existing-policy-id-for-update"
			updatedReason := "This reason has been updated."
			updatedExpiresAt = time.Now().UTC().Add(60 * 24 * time.Hour).Truncate(time.Second)
			updateAttrs = UpdatePolicyAttributes{
				Action: &Action{
					Data: ActionData{
						Expires:    &updatedExpiresAt,
						IgnoreType: "wont-fix", // Assuming ignore_type is not updatable or we send it again
						Reason:     updatedReason,
					},
				},
			}
			meta = map[string]interface{}{"update_source": "ginkgo-patch-test"}

			server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				Expect(r.Method).To(Equal("PATCH"))
				Expect(r.URL.Path).To(Equal("/orgs/test-org/policies/" + policyIDToUpdate))
				Expect(r.Header.Get("Content-Type")).To(Equal("application/vnd.api+json"))

				var payload UpdatePolicyPayload
				err := json.NewDecoder(r.Body).Decode(&payload)
				Expect(err).NotTo(HaveOccurred())

				Expect(payload.Data.Type).To(Equal("policy"))
				Expect(payload.Data.ID).To(Equal(policyIDToUpdate))
				Expect(payload.Data.Attributes.Action).NotTo(BeNil())
				Expect(payload.Data.Attributes.Action.Data.Reason).To(Equal(updatedReason))
				Expect(*payload.Data.Attributes.Action.Data.Expires).To(BeTemporally("~", updatedExpiresAt, time.Second))
				Expect(payload.Data.Meta["update_source"]).To(Equal(meta["update_source"]))

				now := time.Now().UTC().Truncate(time.Second)
				response := struct {
					Data PolicyResponse `json:"data"`
				}{
					Data: PolicyResponse{
						ID:   policyIDToUpdate,
						Type: "policy",
						Attributes: Policy{
							Name: "Original Policy Name (Not Updated)", // Assuming name wasn't part of this update
							Action: Action{
								Data: ActionData{
									Expires:    &updatedExpiresAt,
									IgnoreType: "wont-fix",
									Reason:     updatedReason,
								},
							},
							ActionType:      "ignore", // Assuming not updatable or sent again
							ConditionsGroup: ConditionsGroup{ /* ... original conditions ... */ },
							CreatedAt:       now.Add(-24 * time.Hour), // Some time in the past
							CreatedBy: UserIdentity{
								ID: "original-creator-id",
							},
							Review:    "approved", // Assume review status changed or was set
							UpdatedAt: now,
						},
					},
				}
				w.Header().Set("Content-Type", "application/vnd.api+json")
				json.NewEncoder(w).Encode(response)
			})
		})

		It("should update a policy successfully", func() {
			updatedPolicy, err := client.UpdatePolicy("test-org", policyIDToUpdate, updateAttrs, meta)
			Expect(err).NotTo(HaveOccurred())
			Expect(updatedPolicy).NotTo(BeNil())

			Expect(updatedPolicy.ID).To(Equal(policyIDToUpdate))
			Expect(updatedPolicy.Action.Data.Reason).To(Equal("This reason has been updated."))
			Expect(updatedPolicy.Action.Data.Expires).NotTo(BeNil())
			Expect(*updatedPolicy.Action.Data.Expires).To(BeTemporally("~", updatedExpiresAt, time.Second))
			Expect(updatedPolicy.Review).To(Equal("approved")) // Assuming this is what server returned
			Expect(updatedPolicy.UpdatedAt).To(BeTemporally("~", time.Now().UTC(), time.Second))
		})
	})

	Describe("DeletePolicy", func() {
		BeforeEach(func() {
			server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				Expect(r.Method).To(Equal("DELETE"))
				Expect(r.URL.Path).To(Equal("/orgs/test-org/policies/test-policy-id-delete"))
				Expect(r.Header.Get("Authorization")).To(Equal("token test-token"))
				Expect(r.Header.Get("Accept")).To(Equal("application/vnd.api+json"))
				Expect(r.URL.Query().Get("version")).To(Equal("2024-10-15"))

				w.WriteHeader(http.StatusNoContent)
			})
		})

		It("should delete a policy successfully", func() {
			err := client.DeletePolicy("test-org", "test-policy-id-delete")
			Expect(err).NotTo(HaveOccurred())
		})
	})

	Describe("GetOrganizationsInGroup", func() {
		It("should retrieve organizations successfully without pagination", func() {
			server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				Expect(r.Method).To(Equal("GET"))
				Expect(r.URL.Path).To(Equal("/groups/test-group-id/orgs"))
				Expect(r.Header.Get("Authorization")).To(Equal("token test-token"))
				Expect(r.Header.Get("Accept")).To(Equal("application/vnd.api+json"))
				Expect(r.URL.Query().Get("version")).To(Equal("2024-10-15"))
				Expect(r.URL.Query().Get("limit")).To(Equal("100"))

				response := OrganizationsResponse{
					Data: []OrganizationResponse{
						{
							ID:   "org-1",
							Type: "organization",
							Attributes: Organization{
								Name:                  "Test Organization 1",
								Slug:                  "test-org-1",
								GroupID:               "test-group-id",
								IsPersonal:            false,
								CreatedAt:             time.Now(),
								UpdatedAt:             time.Now(),
								AccessRequestsEnabled: true,
							},
						},
						{
							ID:   "org-2",
							Type: "organization",
							Attributes: Organization{
								Name:                  "Test Organization 2",
								Slug:                  "test-org-2",
								GroupID:               "test-group-id",
								IsPersonal:            false,
								CreatedAt:             time.Now(),
								UpdatedAt:             time.Now(),
								AccessRequestsEnabled: false,
							},
						},
					},
					JSONAPI: struct {
						Version string `json:"version"`
					}{
						Version: "1.0",
					},
					Links: struct {
						First string `json:"first,omitempty"`
						Last  string `json:"last,omitempty"`
						Next  string `json:"next,omitempty"`
						Prev  string `json:"prev,omitempty"`
						Self  string `json:"self,omitempty"`
					}{
						Self: "/groups/test-group-id/orgs",
					},
				}

				w.Header().Set("Content-Type", "application/vnd.api+json")
				json.NewEncoder(w).Encode(response)
			})

			orgs, err := client.GetOrganizationsInGroup("test-group-id")
			Expect(err).NotTo(HaveOccurred())
			Expect(orgs).To(HaveLen(2))

			Expect(orgs[0].ID).To(Equal("org-1"))
			Expect(orgs[0].Name).To(Equal("Test Organization 1"))
			Expect(orgs[0].Slug).To(Equal("test-org-1"))
			Expect(orgs[0].GroupID).To(Equal("test-group-id"))
			Expect(orgs[0].IsPersonal).To(BeFalse())
			Expect(orgs[0].AccessRequestsEnabled).To(BeTrue())

			Expect(orgs[1].ID).To(Equal("org-2"))
			Expect(orgs[1].Name).To(Equal("Test Organization 2"))
			Expect(orgs[1].Slug).To(Equal("test-org-2"))
			Expect(orgs[1].AccessRequestsEnabled).To(BeFalse())
		})

		It("should handle pagination correctly", func() {
			requestCount := 0
			server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				Expect(r.Method).To(Equal("GET"))
				Expect(r.Header.Get("Authorization")).To(Equal("token test-token"))
				Expect(r.Header.Get("Accept")).To(Equal("application/vnd.api+json"))

				requestCount++
				var response interface{}

				switch requestCount {
				case 1:
					// First page
					Expect(r.URL.Path).To(Equal("/groups/test-group-id/orgs"))
					Expect(r.URL.Query().Get("version")).To(Equal("2024-10-15"))
					Expect(r.URL.Query().Get("limit")).To(Equal("100"))

					response = map[string]interface{}{
						"data": []map[string]interface{}{
							{
								"id":   "org-page1-1",
								"type": "organization",
								"attributes": map[string]interface{}{
									"name":                    "Page 1 Org 1",
									"slug":                    "page1-org1",
									"group_id":                "test-group-id",
									"is_personal":             false,
									"created_at":              time.Now().Format(time.RFC3339),
									"updated_at":              time.Now().Format(time.RFC3339),
									"access_requests_enabled": true,
								},
							},
						},
						"links": map[string]interface{}{
							"next": "/groups/test-group-id/orgs?starting_after=cursor1&limit=100",
						},
						"jsonapi": map[string]interface{}{
							"version": "1.0",
						},
					}
				case 2:
					// Second page
					Expect(r.URL.Path).To(Equal("/groups/test-group-id/orgs"))
					Expect(r.URL.Query().Get("starting_after")).To(Equal("cursor1"))
					Expect(r.URL.Query().Get("limit")).To(Equal("100"))

					response = map[string]interface{}{
						"data": []map[string]interface{}{
							{
								"id":   "org-page2-1",
								"type": "organization",
								"attributes": map[string]interface{}{
									"name":                    "Page 2 Org 1",
									"slug":                    "page2-org1",
									"group_id":                "test-group-id",
									"is_personal":             false,
									"created_at":              time.Now().Format(time.RFC3339),
									"updated_at":              time.Now().Format(time.RFC3339),
									"access_requests_enabled": false,
								},
							},
						},
						"links": map[string]interface{}{
							// No next link - end of pagination
						},
						"jsonapi": map[string]interface{}{
							"version": "1.0",
						},
					}
				}

				w.Header().Set("Content-Type", "application/vnd.api+json")
				json.NewEncoder(w).Encode(response)
			})

			orgs, err := client.GetOrganizationsInGroup("test-group-id")
			Expect(err).NotTo(HaveOccurred())
			Expect(orgs).To(HaveLen(2))
			Expect(requestCount).To(Equal(2))

			// Verify first page org
			Expect(orgs[0].ID).To(Equal("org-page1-1"))
			Expect(orgs[0].Name).To(Equal("Page 1 Org 1"))
			Expect(orgs[0].AccessRequestsEnabled).To(BeTrue())

			// Verify second page org
			Expect(orgs[1].ID).To(Equal("org-page2-1"))
			Expect(orgs[1].Name).To(Equal("Page 2 Org 1"))
			Expect(orgs[1].AccessRequestsEnabled).To(BeFalse())
		})

		It("should handle 404 group not found error", func() {
			server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				Expect(r.Method).To(Equal("GET"))
				Expect(r.URL.Path).To(Equal("/groups/nonexistent-group/orgs"))

				w.WriteHeader(http.StatusNotFound)
				w.Write([]byte(`{"errors": [{"detail": "Group not found"}]}`))
			})

			orgs, err := client.GetOrganizationsInGroup("nonexistent-group")
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("unexpected status code: 404"))
			Expect(orgs).To(BeNil())
		})

		It("should handle rate limiting with retry", func() {
			requestCount := 0
			server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requestCount++

				if requestCount == 1 {
					// First request gets rate limited
					w.Header().Set("Retry-After", "1")
					w.WriteHeader(http.StatusTooManyRequests)
					return
				}

				// Second request succeeds
				Expect(r.Method).To(Equal("GET"))
				Expect(r.URL.Path).To(Equal("/groups/test-group-id/orgs"))

				response := map[string]interface{}{
					"data": []map[string]interface{}{
						{
							"id":   "org-after-retry",
							"type": "organization",
							"attributes": map[string]interface{}{
								"name":                    "Org After Retry",
								"slug":                    "org-after-retry",
								"group_id":                "test-group-id",
								"is_personal":             false,
								"created_at":              time.Now().Format(time.RFC3339),
								"updated_at":              time.Now().Format(time.RFC3339),
								"access_requests_enabled": true,
							},
						},
					},
					"jsonapi": map[string]interface{}{
						"version": "1.0",
					},
				}

				w.Header().Set("Content-Type", "application/vnd.api+json")
				json.NewEncoder(w).Encode(response)
			})

			orgs, err := client.GetOrganizationsInGroup("test-group-id")
			Expect(err).NotTo(HaveOccurred())
			Expect(orgs).To(HaveLen(1))
			Expect(orgs[0].ID).To(Equal("org-after-retry"))
			Expect(requestCount).To(Equal(2))
		})

		It("should handle empty group (no organizations)", func() {
			server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				Expect(r.Method).To(Equal("GET"))
				Expect(r.URL.Path).To(Equal("/groups/empty-group/orgs"))

				response := OrganizationsResponse{
					Data: []OrganizationResponse{},
					JSONAPI: struct {
						Version string `json:"version"`
					}{
						Version: "1.0",
					},
				}

				w.Header().Set("Content-Type", "application/vnd.api+json")
				json.NewEncoder(w).Encode(response)
			})

			orgs, err := client.GetOrganizationsInGroup("empty-group")
			Expect(err).NotTo(HaveOccurred())
			Expect(orgs).To(HaveLen(0))
		})
	})

})
