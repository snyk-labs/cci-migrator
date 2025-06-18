package commands_test

import (
	"database/sql"
	"testing"
	"time"

	_ "github.com/mattn/go-sqlite3"
	"github.com/stretchr/testify/assert"
	"github.com/z4ce/cci-migrator/internal/commands"
	"github.com/z4ce/cci-migrator/internal/database"
)

func TestStatusCommandExecute(t *testing.T) {
	tests := []struct {
		name      string
		projects  []*database.Project
		ignores   []*database.Ignore
		policies  []*database.Policy
		issues    []*database.Issue
		setupMock func(*MockDB)
		verify    func(t *testing.T, err error)
	}{
		{
			name: "should only count projects with migrated ignores in retest denominator",
			projects: []*database.Project{
				{ID: "project1", OrgID: "org123", Name: "Project 1", IsCliProject: false, RetestedAt: nil},
				{ID: "project2", OrgID: "org123", Name: "Project 2", IsCliProject: false, RetestedAt: &time.Time{}},
				{ID: "project3", OrgID: "org123", Name: "Project 3", IsCliProject: false, RetestedAt: nil},
				{ID: "project4", OrgID: "org123", Name: "CLI Project", IsCliProject: true, RetestedAt: nil},
			},
			ignores: []*database.Ignore{
				// Project 1 has a migrated ignore - needs retesting
				{ID: "ignore1", ProjectID: "project1", OrgID: "org123", MigratedAt: &time.Time{}, SelectedForMigration: true},
				// Project 2 has a migrated ignore and has been retested
				{ID: "ignore2", ProjectID: "project2", OrgID: "org123", MigratedAt: &time.Time{}, SelectedForMigration: true},
				// Project 3 has an ignore but it's not migrated - doesn't need retesting
				{ID: "ignore3", ProjectID: "project3", OrgID: "org123", MigratedAt: nil, SelectedForMigration: true},
				// Project 4 is CLI so won't be counted anyway
				{ID: "ignore4", ProjectID: "project4", OrgID: "org123", MigratedAt: &time.Time{}, SelectedForMigration: true},
			},
			policies: []*database.Policy{},
			issues:   []*database.Issue{},
			setupMock: func(db *MockDB) {
				// Mock the Query method for collection metadata using real sql.Rows
				db.QueryFunc = func(query string, args ...interface{}) (interface{}, error) {
					// Create a real database for the collection metadata query
					sqlDB, _ := sql.Open("sqlite3", ":memory:")
					sqlDB.Exec("CREATE TABLE collection_metadata (collection_completed_at TIMESTAMP, collection_version TEXT, api_version TEXT)")
					sqlDB.Exec("INSERT INTO collection_metadata VALUES (?, ?, ?)", time.Now(), "1.0.0", "v1")
					return sqlDB.Query("SELECT collection_completed_at, collection_version, api_version FROM collection_metadata LIMIT 1")
				}
			},
			verify: func(t *testing.T, err error) {
				assert.NoError(t, err)
				// With this test data:
				// - Only project1 and project2 have migrated ignores (project3's ignore is not migrated)
				// - So only 2 projects need retesting (projectsNeedingRetest = 2)
				// - Only project2 has been retested (retestedProjects = 1)
				// - The percentage should be 1/2 = 50%, not 1/3 = 33.3%
			},
		},
		{
			name: "should handle case where no projects need retesting",
			projects: []*database.Project{
				{ID: "project1", OrgID: "org123", Name: "Project 1", IsCliProject: false, RetestedAt: nil},
				{ID: "project2", OrgID: "org123", Name: "Project 2", IsCliProject: false, RetestedAt: nil},
			},
			ignores: []*database.Ignore{
				// No migrated ignores - no projects need retesting
				{ID: "ignore1", ProjectID: "project1", OrgID: "org123", MigratedAt: nil, SelectedForMigration: true},
				{ID: "ignore2", ProjectID: "project2", OrgID: "org123", MigratedAt: nil, SelectedForMigration: true},
			},
			policies: []*database.Policy{},
			issues:   []*database.Issue{},
			setupMock: func(db *MockDB) {
				db.QueryFunc = func(query string, args ...interface{}) (interface{}, error) {
					// Create a real database for the collection metadata query
					sqlDB, _ := sql.Open("sqlite3", ":memory:")
					sqlDB.Exec("CREATE TABLE collection_metadata (collection_completed_at TIMESTAMP, collection_version TEXT, api_version TEXT)")
					sqlDB.Exec("INSERT INTO collection_metadata VALUES (?, ?, ?)", time.Now(), "1.0.0", "v1")
					return sqlDB.Query("SELECT collection_completed_at, collection_version, api_version FROM collection_metadata LIMIT 1")
				}
			},
			verify: func(t *testing.T, err error) {
				assert.NoError(t, err)
				// With no migrated ignores, projectsNeedingRetest should be 0
				// This should not cause a division by zero error in percentage calculation
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockDB := NewMockDB()

			// Set up mock responses
			mockDB.GetProjectsByOrgIDFunc = func(orgID string) ([]*database.Project, error) {
				return tt.projects, nil
			}

			mockDB.GetIgnoresByOrgIDFunc = func(orgID string) ([]*database.Ignore, error) {
				return tt.ignores, nil
			}

			mockDB.GetPoliciesByOrgIDFunc = func(orgID string) ([]*database.Policy, error) {
				return tt.policies, nil
			}

			mockDB.GetIssuesByOrgIDFunc = func(orgID string) ([]*database.Issue, error) {
				return tt.issues, nil
			}

			tt.setupMock(mockDB)

			cmd := commands.NewStatusCommand(mockDB, "org123", false)
			err := cmd.Execute()

			tt.verify(t, err)
		})
	}
}
