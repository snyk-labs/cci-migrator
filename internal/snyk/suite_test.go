package snyk

import (
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestSnyk(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Snyk Suite")
}
