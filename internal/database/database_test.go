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
})
