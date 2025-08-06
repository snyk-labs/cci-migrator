package commands_test

import (
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/z4ce/cci-migrator/internal/commands"
	"github.com/z4ce/cci-migrator/internal/database"
	"github.com/z4ce/cci-migrator/internal/snyk"
)

func TestRollbackCommandExecute_Success(t *testing.T) {
	mockDB := NewMockDB()
	mockClient := NewMockClient()

	// Mock policies to delete
	mockDB.GetPoliciesByOrgIDFunc = func(orgID string) ([]*database.Policy, error) {
		return []*database.Policy{
			{ExternalID: "pol1"},
			{ExternalID: "pol2"},
		}, nil
	}

	deleted := []string{}
	mockClient.DeletePolicyFunc = func(orgID, policyID string) error {
		deleted = append(deleted, policyID)
		return nil
	}

	// Mock ignores to recreate
	origIgnore := snyk.Ignore{ID: "ign1", Reason: "r", ReasonType: "t", CreatedAt: time.Now()}
	bs, err := json.Marshal(origIgnore)
	assert.NoError(t, err)
	mockDB.GetIgnoresByOrgIDFunc = func(orgID string) ([]*database.Ignore, error) {
		return []*database.Ignore{{ID: "ign1", ProjectID: "proj1", OriginalState: string(bs)}}, nil
	}

	recreated := []string{}
	mockClient.CreateIgnoreFunc = func(orgID, projectID string, ignore snyk.Ignore) error {
		recreated = append(recreated, ignore.ID)
		return nil
	}

	cmd := commands.NewRollbackCommand(mockDB, mockClient, "org123", false)
	err = cmd.Execute()
	assert.NoError(t, err)
	assert.ElementsMatch(t, []string{"pol1", "pol2"}, deleted)
	assert.Equal(t, []string{"ign1"}, recreated)
}

func TestRollbackCommandExecute_PolicyFetchError(t *testing.T) {
	mockDB := NewMockDB()
	mockClient := NewMockClient()

	// Simulate DB error fetching policies
	mockDB.GetPoliciesByOrgIDFunc = func(orgID string) ([]*database.Policy, error) {
		return nil, errors.New("db error")
	}

	cmd := commands.NewRollbackCommand(mockDB, mockClient, "org123", false)
	err := cmd.Execute()
	assert.Error(t, err)
}
