package commands_test

import (
	"database/sql"
	"errors"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/z4ce/cci-migrator/internal/commands"
)

func TestCleanupCommandExecute(t *testing.T) {
	tests := []struct {
		name              string
		setupMock         func(*MockDB, *MockClient)
		expectedError     bool
		expectedLogs      []string
		expectedTxCalls   int
		expectedCommits   int
		expectedRollbacks int
	}{
		{
			name: "Successfully cleanup ignores with transactions",
			setupMock: func(db *MockDB, client *MockClient) {
				// Set up mock responses for the initial query
				db.QueryFunc = func(query string, args ...interface{}) (interface{}, error) {
					if strings.Contains(query, "SELECT id, project_id") {
						return &MockRows{
							rows: [][]interface{}{
								{"ignore1", "project1"},
								{"ignore2", "project2"},
							},
						}, nil
					}
					return nil, nil
				}

				// Set up successful API deletions
				client.DeleteIgnoreFunc = func(orgID, projectID, ignoreID string) error {
					return nil
				}

				// Set up transaction mocks
				var txCallCount int
				db.BeginFunc = func() (interface{}, error) {
					txCallCount++
					return &MockTransaction{
						ExecFunc: func(query string, args ...interface{}) (interface{}, error) {
							return nil, nil
						},
						CommitFunc: func() error {
							return nil
						},
						RollbackFunc: func() error {
							return nil
						},
					}, nil
				}

				// Set up QueryRow responses for counting - create a real *sql.Row
				sqlDB, _ := sql.Open("sqlite3", ":memory:")
				db.QueryRowFunc = func(query string, args ...interface{}) *sql.Row {
					// Create a simple table and return a real sql.Row with count data
					sqlDB.Exec("CREATE TABLE IF NOT EXISTS temp_count (count INTEGER)")
					sqlDB.Exec("DELETE FROM temp_count")
					sqlDB.Exec("INSERT INTO temp_count VALUES (2)")
					return sqlDB.QueryRow("SELECT count FROM temp_count")
				}
			},
			expectedError:     false,
			expectedTxCalls:   2, // One transaction per ignore
			expectedCommits:   2,
			expectedRollbacks: 0,
		},
		{
			name: "Handle API deletion failures",
			setupMock: func(db *MockDB, client *MockClient) {
				// Set up mock responses for the initial query
				db.QueryFunc = func(query string, args ...interface{}) (interface{}, error) {
					if strings.Contains(query, "SELECT id, project_id") {
						return &MockRows{
							rows: [][]interface{}{
								{"ignore1", "project1"},
								{"ignore2", "project2"},
							},
						}, nil
					}
					return nil, nil
				}

				// Set up failing API deletions
				client.DeleteIgnoreFunc = func(orgID, projectID, ignoreID string) error {
					return errors.New("API delete failed")
				}

				// Set up QueryRow responses for counting - create a real *sql.Row
				sqlDB, _ := sql.Open("sqlite3", ":memory:")
				db.QueryRowFunc = func(query string, args ...interface{}) *sql.Row {
					sqlDB.Exec("CREATE TABLE IF NOT EXISTS temp_count (count INTEGER)")
					sqlDB.Exec("DELETE FROM temp_count")
					sqlDB.Exec("INSERT INTO temp_count VALUES (2)")
					return sqlDB.QueryRow("SELECT count FROM temp_count")
				}
			},
			expectedError:     false, // Should not error out, just log warnings
			expectedTxCalls:   0,     // No transactions if API calls fail
			expectedCommits:   0,
			expectedRollbacks: 0,
		},
		{
			name: "Handle database transaction retry on locked error",
			setupMock: func(db *MockDB, client *MockClient) {
				// Set up mock responses for the initial query
				db.QueryFunc = func(query string, args ...interface{}) (interface{}, error) {
					if strings.Contains(query, "SELECT id, project_id") {
						return &MockRows{
							rows: [][]interface{}{
								{"ignore1", "project1"},
							},
						}, nil
					}
					return nil, nil
				}

				// Set up successful API deletions
				client.DeleteIgnoreFunc = func(orgID, projectID, ignoreID string) error {
					return nil
				}

				// Set up transaction mocks with retry scenario
				var txCallCount int
				db.BeginFunc = func() (interface{}, error) {
					txCallCount++
					tx := &MockTransaction{
						ExecFunc: func(query string, args ...interface{}) (interface{}, error) {
							// First attempt fails with locked error, second succeeds
							if txCallCount == 1 {
								return nil, errors.New("database is locked")
							}
							return nil, nil
						},
						CommitFunc: func() error {
							if txCallCount == 1 {
								return errors.New("database is locked")
							}
							return nil
						},
						RollbackFunc: func() error {
							return nil
						},
					}
					return tx, nil
				}

				// Set up QueryRow responses for counting - create a real *sql.Row
				sqlDB, _ := sql.Open("sqlite3", ":memory:")
				db.QueryRowFunc = func(query string, args ...interface{}) *sql.Row {
					sqlDB.Exec("CREATE TABLE IF NOT EXISTS temp_count (count INTEGER)")
					sqlDB.Exec("DELETE FROM temp_count")
					sqlDB.Exec("INSERT INTO temp_count VALUES (1)")
					return sqlDB.QueryRow("SELECT count FROM temp_count")
				}
			},
			expectedError:     false,
			expectedTxCalls:   2, // Should retry once
			expectedCommits:   1, // Only second attempt succeeds
			expectedRollbacks: 1, // First attempt gets rolled back
		},
		{
			name: "Handle initial query failure",
			setupMock: func(db *MockDB, client *MockClient) {
				// Set up failing initial query
				db.QueryFunc = func(query string, args ...interface{}) (interface{}, error) {
					return nil, errors.New("query failed")
				}
			},
			expectedError:     true,
			expectedTxCalls:   0,
			expectedCommits:   0,
			expectedRollbacks: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockDB := NewMockDB()
			mockClient := NewMockClient()

			tt.setupMock(mockDB, mockClient)

			cmd := commands.NewCleanupCommand(mockDB, mockClient, "org123", false)
			err := cmd.Execute()

			if tt.expectedError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}

			// Additional verification can be added here for specific test cases
		})
	}
}
