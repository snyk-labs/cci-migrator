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
})
