package commands_test

import (
	"errors"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/z4ce/cci-migrator/internal/commands"
)

var _ = Describe("Plan Command", func() {
	var (
		mockDB  *MockDB
		cmd     *commands.PlanCommand
		mockTx  *MockTransaction
	)

	BeforeEach(func() {
		mockDB = NewMockDB()
		mockTx = &MockTransaction{
			ExecFunc: func(query string, args ...interface{}) (interface{}, error) {
				return nil, nil
			},
			CommitFunc: func() error {
				return nil
			},
			RollbackFunc: func() error {
				return nil
			},
		}
		cmd = commands.NewPlanCommand(mockDB, nil, "org123", false)
	})

	Describe("Execute", func() {
		Context("when transaction fails", func() {
			It("should return error if Begin fails", func() {
				mockDB.BeginFunc = func() (interface{}, error) {
					return nil, errors.New("Begin failed")
				}

				err := cmd.Execute()
				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(ContainSubstring("failed to begin transaction"))
			})
		})

		Context("when cleanup fails", func() {
			It("should return error and rollback if DELETE policies fails", func() {
				callCount := 0
				mockTx.ExecFunc = func(query string, args ...interface{}) (interface{}, error) {
					callCount++
					// First call is DELETE policies
					if callCount == 1 {
						return nil, errors.New("DELETE failed")
					}
					return nil, nil
				}

				mockDB.BeginFunc = func() (interface{}, error) {
					return mockTx, nil
				}

				err := cmd.Execute()
				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(ContainSubstring("failed to delete existing policies"))
				Expect(mockTx.RollbackCalled).To(BeTrue())
				Expect(mockTx.CommitCalled).To(BeFalse())
			})

			It("should return error and rollback if UPDATE reset flags fails", func() {
				callCount := 0
				mockTx.ExecFunc = func(query string, args ...interface{}) (interface{}, error) {
					callCount++
					// First call succeeds (DELETE)
					if callCount == 1 {
						return nil, nil
					}
					// Second call fails (UPDATE)
					return nil, errors.New("UPDATE failed")
				}

				mockDB.BeginFunc = func() (interface{}, error) {
					return mockTx, nil
				}

				err := cmd.Execute()
				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(ContainSubstring("failed to reset ignore flags"))
				Expect(mockTx.RollbackCalled).To(BeTrue())
				Expect(mockTx.CommitCalled).To(BeFalse())
			})

			It("should return error and rollback if Commit fails", func() {
				mockTx.CommitFunc = func() error {
					return errors.New("Commit failed")
				}

				mockDB.BeginFunc = func() (interface{}, error) {
					return mockTx, nil
				}

				err := cmd.Execute()
				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(ContainSubstring("failed to commit cleanup transaction"))
				Expect(mockTx.RollbackCalled).To(BeTrue())
				Expect(mockTx.CommitCalled).To(BeTrue())
			})
		})

		Context("when cleanup succeeds", func() {
			It("should execute DELETE and UPDATE within a transaction and commit", func() {
				mockDB.BeginFunc = func() (interface{}, error) {
					return mockTx, nil
				}

				// Mock Query to return an error to stop execution after cleanup
				mockDB.QueryFunc = func(query string, args ...interface{}) (interface{}, error) {
					return nil, errors.New("Query failed - this is expected to stop execution after cleanup")
				}

				err := cmd.Execute()

				// Verify transaction operations
				Expect(mockTx.ExecCalls).To(HaveLen(2), "Transaction should have 2 Exec calls (DELETE and UPDATE)")
				
				// Verify DELETE call
				Expect(mockTx.ExecCalls[0].Query).To(ContainSubstring("DELETE FROM policies"))
				Expect(mockTx.ExecCalls[0].Args[0]).To(Equal("org123"))

				// Verify UPDATE call
				Expect(mockTx.ExecCalls[1].Query).To(ContainSubstring("UPDATE ignores"))
				Expect(mockTx.ExecCalls[1].Args[0]).To(Equal("org123"))

				// Verify transaction was committed
				Expect(mockTx.CommitCalled).To(BeTrue(), "Transaction should be committed")
				Expect(mockTx.RollbackCalled).To(BeFalse(), "Transaction should not be rolled back on success")

				// The command should fail after cleanup due to our mock error, but cleanup should have happened
				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(ContainSubstring("Query failed"))
			})
		})
	})
})
