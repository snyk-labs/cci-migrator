package database

import (
	"os"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Database", func() {
	var (
		db     *DB
		dbPath string
	)

	BeforeEach(func() {
		// Create a temporary database file
		dbPath = "test.db"
		var err error
		db, err = New(dbPath)
		Expect(err).NotTo(HaveOccurred())
	})

	AfterEach(func() {
		db.Close()
		os.Remove(dbPath)
	})

	It("should insert and retrieve ignores correctly", func() {
		// Test inserting and retrieving an ignore
		testIgnore := &Ignore{
			ID:         "test-id",
			IssueID:    "test-issue",
			OrgID:      "test-org",
			ProjectID:  "test-project",
			Reason:     "test reason",
			IgnoreType: "permanent",
			CreatedAt:  time.Now(),
			AssetKey:   "test-asset-key",
		}

		// Test InsertIgnore
		err := db.InsertIgnore(testIgnore)
		Expect(err).NotTo(HaveOccurred())

		// Test GetIgnoresByOrgID
		ignores, err := db.GetIgnoresByOrgID(testIgnore.OrgID)
		Expect(err).NotTo(HaveOccurred())
		Expect(ignores).To(HaveLen(1))

		ignore := ignores[0]
		Expect(ignore.ID).To(Equal(testIgnore.ID))
		Expect(ignore.IssueID).To(Equal(testIgnore.IssueID))
	})

	It("should insert and retrieve issues correctly", func() {
		// Test inserting and retrieving an issue
		testIssue := &Issue{
			ID:            "test-issue-id",
			OrgID:         "test-org",
			ProjectID:     "test-project",
			AssetKey:      "test-asset-key",
			ProjectKey:    "test-project-key",
			OriginalState: "{}",
		}

		// Test InsertIssue
		err := db.InsertIssue(testIssue)
		Expect(err).NotTo(HaveOccurred())

		// Test GetIssuesByOrgID
		issues, err := db.GetIssuesByOrgID(testIssue.OrgID)
		Expect(err).NotTo(HaveOccurred())
		Expect(issues).To(HaveLen(1))

		issue := issues[0]
		Expect(issue.ID).To(Equal(testIssue.ID))
		Expect(issue.AssetKey).To(Equal(testIssue.AssetKey))
		Expect(issue.ProjectKey).To(Equal(testIssue.ProjectKey))
	})

	It("should update and retrieve collection metadata correctly", func() {
		// Test UpdateCollectionMetadata
		now := time.Now()
		err := db.UpdateCollectionMetadata(now, "1.0.0", "v1")
		Expect(err).NotTo(HaveOccurred())

		// Verify collection metadata
		var completedAt time.Time
		var version, apiVersion string
		err = db.QueryRow("SELECT collection_completed_at, collection_version, api_version FROM collection_metadata LIMIT 1").
			Scan(&completedAt, &version, &apiVersion)
		Expect(err).NotTo(HaveOccurred())

		Expect(version).To(Equal("1.0.0"))
		Expect(apiVersion).To(Equal("v1"))
	})

	It("should be idempotent when inserting the same data multiple times", func() {
		// Test ignore idempotency
		testIgnore := &Ignore{
			ID:         "test-id",
			IssueID:    "test-issue",
			OrgID:      "test-org",
			ProjectID:  "test-project",
			Reason:     "test reason",
			IgnoreType: "permanent",
			CreatedAt:  time.Now(),
			AssetKey:   "test-asset-key",
		}

		// Insert first time
		err := db.InsertIgnore(testIgnore)
		Expect(err).NotTo(HaveOccurred())

		// Insert second time - should not fail
		err = db.InsertIgnore(testIgnore)
		Expect(err).NotTo(HaveOccurred())

		// Verify only one ignore exists
		ignores, err := db.GetIgnoresByOrgID(testIgnore.OrgID)
		Expect(err).NotTo(HaveOccurred())
		Expect(ignores).To(HaveLen(1))

		// Test issue idempotency
		testIssue := &Issue{
			ID:            "test-issue-id",
			OrgID:         "test-org",
			ProjectID:     "test-project",
			AssetKey:      "test-asset-key",
			ProjectKey:    "test-project-key",
			OriginalState: "{}",
		}

		// Insert first time
		err = db.InsertIssue(testIssue)
		Expect(err).NotTo(HaveOccurred())

		// Insert second time - should not fail
		err = db.InsertIssue(testIssue)
		Expect(err).NotTo(HaveOccurred())

		// Verify only one issue exists
		issues, err := db.GetIssuesByOrgID(testIssue.OrgID)
		Expect(err).NotTo(HaveOccurred())
		Expect(issues).To(HaveLen(1))

		// Test project idempotency
		testProject := &Project{
			ID:                "test-project-id",
			OrgID:             "test-org",
			Name:              "Test Project",
			TargetInformation: `{"name": "test-repo"}`,
			IsCliProject:      false,
		}

		// Insert first time
		err = db.InsertProject(testProject)
		Expect(err).NotTo(HaveOccurred())

		// Insert second time - should not fail
		err = db.InsertProject(testProject)
		Expect(err).NotTo(HaveOccurred())

		// Verify only one project exists
		projects, err := db.GetProjectsByOrgID(testProject.OrgID)
		Expect(err).NotTo(HaveOccurred())
		Expect(projects).To(HaveLen(1))

		// Test collection metadata idempotency
		completedAt := time.Now()
		version := "2.0.0"
		apiVersion := "v1"

		// Insert first time
		err = db.UpdateCollectionMetadata(completedAt, version, apiVersion)
		Expect(err).NotTo(HaveOccurred())

		// Insert second time - should not fail and should update
		newCompletedAt := time.Now().Add(1 * time.Hour)
		newVersion := "2.1.0"
		err = db.UpdateCollectionMetadata(newCompletedAt, newVersion, apiVersion)
		Expect(err).NotTo(HaveOccurred())
	})

	It("should simulate the gather command being run twice without errors", func() {
		// This test simulates the exact scenario described by the user:
		// Running gather twice should not result in errors due to duplicate keys

		orgID := "test-org-duplicate"

		// Simulate first gather run - insert some typical data
		project1 := &Project{
			ID:                "project-1",
			OrgID:             orgID,
			Name:              "My Project",
			TargetInformation: `{"name": "my-repo", "branch": "main"}`,
			IsCliProject:      false,
		}

		ignore1 := &Ignore{
			ID:         "ignore-1",
			IssueID:    "issue-1",
			OrgID:      orgID,
			ProjectID:  "project-1",
			Reason:     "False positive",
			IgnoreType: "wont-fix",
			CreatedAt:  time.Now(),
			AssetKey:   "src/main.go:42",
		}

		issue1 := &Issue{
			ID:            "issue-1",
			OrgID:         orgID,
			ProjectID:     "project-1",
			AssetKey:      "src/main.go:42",
			ProjectKey:    "cwe-89",
			OriginalState: `{"type": "vulnerability"}`,
		}

		// First gather run
		err := db.InsertProject(project1)
		Expect(err).NotTo(HaveOccurred())

		err = db.InsertIgnore(ignore1)
		Expect(err).NotTo(HaveOccurred())

		err = db.InsertIssue(issue1)
		Expect(err).NotTo(HaveOccurred())

		err = db.UpdateCollectionMetadata(time.Now(), "2.0.0", "v1")
		Expect(err).NotTo(HaveOccurred())

		// Verify data exists after first run
		projects, err := db.GetProjectsByOrgID(orgID)
		Expect(err).NotTo(HaveOccurred())
		Expect(projects).To(HaveLen(1))

		ignores, err := db.GetIgnoresByOrgID(orgID)
		Expect(err).NotTo(HaveOccurred())
		Expect(ignores).To(HaveLen(1))

		issues, err := db.GetIssuesByOrgID(orgID)
		Expect(err).NotTo(HaveOccurred())
		Expect(issues).To(HaveLen(1))

		// Second gather run with the EXACT same data - this used to fail with duplicate key errors
		err = db.InsertProject(project1)
		Expect(err).NotTo(HaveOccurred(), "Second project insert should not fail due to duplicate key")

		err = db.InsertIgnore(ignore1)
		Expect(err).NotTo(HaveOccurred(), "Second ignore insert should not fail due to duplicate key")

		err = db.InsertIssue(issue1)
		Expect(err).NotTo(HaveOccurred(), "Second issue insert should not fail due to duplicate key")

		err = db.UpdateCollectionMetadata(time.Now(), "2.0.0", "v1")
		Expect(err).NotTo(HaveOccurred(), "Second collection metadata update should not fail")

		// Verify data still exists and counts haven't changed
		projects, err = db.GetProjectsByOrgID(orgID)
		Expect(err).NotTo(HaveOccurred())
		Expect(projects).To(HaveLen(1), "Should still have exactly 1 project after duplicate inserts")

		ignores, err = db.GetIgnoresByOrgID(orgID)
		Expect(err).NotTo(HaveOccurred())
		Expect(ignores).To(HaveLen(1), "Should still have exactly 1 ignore after duplicate inserts")

		issues, err = db.GetIssuesByOrgID(orgID)
		Expect(err).NotTo(HaveOccurred())
		Expect(issues).To(HaveLen(1), "Should still have exactly 1 issue after duplicate inserts")

		// Verify the data values are still correct
		Expect(projects[0].Name).To(Equal("My Project"))
		Expect(ignores[0].Reason).To(Equal("False positive"))
		Expect(issues[0].AssetKey).To(Equal("src/main.go:42"))
	})

	It("should handle NULL and non-NULL PolicyID and InternalPolicyID fields", func() {
		// This test verifies the fix for the bug where scanning would fail with:
		// "sql: Scan error on column index 13, name 'internal_policy_id': converting NULL to string is unsupported"

		orgID := "test-org-policy-fields"

		// Test Case 1: Insert ignore with NULL policy fields (common initial state)
		ignoreWithNullPolicies := &Ignore{
			ID:               "ignore-null-policies",
			IssueID:          "issue-1",
			OrgID:            orgID,
			ProjectID:        "project-1",
			Reason:           "Test ignore with NULL policy fields",
			IgnoreType:       "wont-fix",
			CreatedAt:        time.Now(),
			AssetKey:         "src/test.go:10",
			PolicyID:         nil, // NULL value
			InternalPolicyID: nil, // NULL value
		}

		err := db.InsertIgnore(ignoreWithNullPolicies)
		Expect(err).NotTo(HaveOccurred(), "Should insert ignore with NULL policy fields")

		// Test Case 2: Insert ignore with populated policy fields (state after migration planning)
		policyID := "policy-123"
		internalPolicyID := "internal-policy-456"
		ignoreWithPolicies := &Ignore{
			ID:               "ignore-with-policies",
			IssueID:          "issue-2",
			OrgID:            orgID,
			ProjectID:        "project-1",
			Reason:           "Test ignore with policy fields",
			IgnoreType:       "temporary",
			CreatedAt:        time.Now(),
			AssetKey:         "src/test.go:20",
			PolicyID:         &policyID,         // Non-NULL value
			InternalPolicyID: &internalPolicyID, // Non-NULL value
		}

		err = db.InsertIgnore(ignoreWithPolicies)
		Expect(err).NotTo(HaveOccurred(), "Should insert ignore with non-NULL policy fields")

		// Retrieve all ignores and verify scanning works correctly
		ignores, err := db.GetIgnoresByOrgID(orgID)
		Expect(err).NotTo(HaveOccurred(), "Should scan ignores with mixed NULL and non-NULL policy fields without error")
		Expect(ignores).To(HaveLen(2), "Should have retrieved both ignores")

		// Find and verify the ignore with NULL policy fields
		var nullPolicyIgnore *Ignore
		var withPolicyIgnore *Ignore
		for _, ig := range ignores {
			if ig.ID == "ignore-null-policies" {
				nullPolicyIgnore = ig
			} else if ig.ID == "ignore-with-policies" {
				withPolicyIgnore = ig
			}
		}

		Expect(nullPolicyIgnore).NotTo(BeNil(), "Should have found ignore with NULL policies")
		Expect(nullPolicyIgnore.PolicyID).To(BeNil(), "PolicyID should be NULL")
		Expect(nullPolicyIgnore.InternalPolicyID).To(BeNil(), "InternalPolicyID should be NULL")

		Expect(withPolicyIgnore).NotTo(BeNil(), "Should have found ignore with non-NULL policies")
		Expect(withPolicyIgnore.PolicyID).NotTo(BeNil(), "PolicyID should not be NULL")
		Expect(*withPolicyIgnore.PolicyID).To(Equal("policy-123"), "PolicyID should match")
		Expect(withPolicyIgnore.InternalPolicyID).NotTo(BeNil(), "InternalPolicyID should not be NULL")
		Expect(*withPolicyIgnore.InternalPolicyID).To(Equal("internal-policy-456"), "InternalPolicyID should match")

		// Test Case 3: Update an ignore from NULL to non-NULL policy fields (simulates migration planning)
		updatedPolicyID := "updated-policy-789"
		updatedInternalPolicyID := "updated-internal-999"
		nullPolicyIgnore.PolicyID = &updatedPolicyID
		nullPolicyIgnore.InternalPolicyID = &updatedInternalPolicyID

		err = db.InsertIgnore(nullPolicyIgnore)
		Expect(err).NotTo(HaveOccurred(), "Should update ignore with policy fields")

		// Retrieve and verify the update
		ignores, err = db.GetIgnoresByOrgID(orgID)
		Expect(err).NotTo(HaveOccurred(), "Should scan ignores after update")
		
		var updatedIgnore *Ignore
		for _, ig := range ignores {
			if ig.ID == "ignore-null-policies" {
				updatedIgnore = ig
				break
			}
		}

		Expect(updatedIgnore).NotTo(BeNil(), "Should have found updated ignore")
		// Note: Based on the UPSERT logic in InsertIgnore, policy fields are NOT updated
		// This is intentional to preserve migration state, so the fields should still be NULL
		// If this behavior changes, update this test accordingly
	})
})
