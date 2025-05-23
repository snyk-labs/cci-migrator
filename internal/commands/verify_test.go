package commands_test

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/z4ce/cci-migrator/internal/commands"
	"github.com/z4ce/cci-migrator/internal/database"
	"github.com/z4ce/cci-migrator/internal/snyk"
)

func TestVerifyCommandExecute(t *testing.T) {
	tests := []struct {
		name          string
		setupMock     func(*MockDB, *MockClient)
		expectedError bool
	}{
		{
			name: "Successfully verify",
			setupMock: func(db *MockDB, client *MockClient) {
				// Set up mock responses
				db.GetIgnoresByOrgIDFunc = func(orgID string) ([]*database.Ignore, error) {
					return []*database.Ignore{
						{ID: "i1", OrgID: "org123", AssetKey: "key1"},
						{ID: "i2", OrgID: "org123", AssetKey: "key2"},
					}, nil
				}

				db.GetIssuesByOrgIDFunc = func(orgID string) ([]*database.Issue, error) {
					return []*database.Issue{
						{ID: "is1", OrgID: "org123", AssetKey: "key1"},
						{ID: "is2", OrgID: "org123", AssetKey: "key2"},
					}, nil
				}

				db.GetProjectsByOrgIDFunc = func(orgID string) ([]*database.Project, error) {
					return []*database.Project{
						{ID: "p1", OrgID: "org123", TargetInformation: "target-info-1"},
						{ID: "p2", OrgID: "org123", TargetInformation: "target-info-2"},
					}, nil
				}

				db.QueryFunc = func(query string, args ...interface{}) (interface{}, error) {
					return &MockRows{
						rows: [][]interface{}{
							{1},
						},
					}, nil
				}
			},
			expectedError: false,
		},
		{
			name: "Failed to get ignores",
			setupMock: func(db *MockDB, client *MockClient) {
				db.GetIgnoresByOrgIDFunc = func(orgID string) ([]*database.Ignore, error) {
					return nil, errors.New("database error")
				}
			},
			expectedError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockDB := NewMockDB()
			mockClient := NewMockClient()

			// Set up default implementations for required interface methods
			mockClient.CreatePolicyFunc = func(orgID string, attributes snyk.CreatePolicyAttributes, meta map[string]interface{}) (*snyk.Policy, error) {
				return &snyk.Policy{ID: "policy-id"}, nil
			}

			mockClient.RetestProjectFunc = func(orgID string, target *snyk.Target) error {
				return nil
			}

			mockClient.DeleteIgnoreFunc = func(orgID, projectID, ignoreID string) error {
				return nil
			}

			tt.setupMock(mockDB, mockClient)

			cmd := commands.NewVerifyCommand(mockDB, mockClient, "org123", false)
			err := cmd.Execute()

			if tt.expectedError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
