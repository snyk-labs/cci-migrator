package snyk

import (
	"encoding/json"
	"fmt"
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
	})

	Describe("GetIgnores", func() {
		BeforeEach(func() {
			server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				Expect(r.Method).To(Equal("GET"))
				Expect(r.Header.Get("Authorization")).To(Equal("token test-token"))
				Expect(r.URL.Path).To(Equal("/org/test-org/project/test-project/ignores"))

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
			})
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
})
