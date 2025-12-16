package commands_test

import (
	"errors"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/z4ce/cci-migrator/internal/commands"
)

var _ = Describe("Plan Command", func() {
	var (
		mockDB *MockDB
		cmd    *commands.PlanCommand
	)

	BeforeEach(func() {
		mockDB = NewMockDB()
		cmd = commands.NewPlanCommand(mockDB, nil, "org123", false)
	})

	Describe("Execute", func() {
		Context("when cleanup fails", func() {
			It("should return error if DeletePoliciesByOrgID fails", func() {
				mockDB.DeletePoliciesByOrgIDFunc = func(orgID string) error {
					return errors.New("DeletePoliciesByOrgID failed")
				}

				err := cmd.Execute()
				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(ContainSubstring("failed to delete existing policies"))
			})

			It("should return error if reset flags fails", func() {
				mockDB.DeletePoliciesByOrgIDFunc = func(orgID string) error {
					return nil
				}

				var execCallCount int
				mockDB.ExecFunc = func(query string, args ...interface{}) (interface{}, error) {
					execCallCount++
					// Debug: print the actual query to see what we're getting
					if execCallCount == 1 {
						// This should be the reset flags query
						return nil, errors.New("Reset flags failed")
					}
					return nil, nil
				}

				err := cmd.Execute()
				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(ContainSubstring("failed to reset ignore flags"))
			})
		})

		Context("when cleanup succeeds", func() {
			It("should call DeletePoliciesByOrgID and reset flags", func() {
				var deletePoliciesCalled bool
				var execCallCount int

				mockDB.DeletePoliciesByOrgIDFunc = func(orgID string) error {
					deletePoliciesCalled = true
					Expect(orgID).To(Equal("org123"))
					return nil
				}

				mockDB.ExecFunc = func(query string, args ...interface{}) (interface{}, error) {
					execCallCount++
					if execCallCount == 1 {
						// This should be the reset flags query
						Expect(args[0]).To(Equal("org123"))
					}
					return nil, nil
				}

				// Mock Query to return an error to stop execution after cleanup
				mockDB.QueryFunc = func(query string, args ...interface{}) (interface{}, error) {
					return nil, errors.New("Query failed - this is expected to stop execution after cleanup")
				}

				err := cmd.Execute()

				// Verify cleanup was performed
				Expect(deletePoliciesCalled).To(BeTrue(), "DeletePoliciesByOrgID should have been called")
				Expect(execCallCount).To(Equal(1), "Exec should have been called once for reset flags")

				// The command should fail after cleanup due to our mock error, but cleanup should have happened
				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(ContainSubstring("Query failed"))
			})
		})
	})
})
