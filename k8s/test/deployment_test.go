package k8s_test

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"path/filepath"
)

var _ = Describe("Deployment", func() {
	var deploymentPath, valuesPath string

	BeforeEach(func() {
		deploymentPath = pathToTemplate("deployment.yml")
		valuesPath = pathToTemplate(filepath.Join("values", "values.yml"))
	})

	It("Constructs the YAML from a set of files", func() {
		ctx := NewRenderingContext(deploymentPath, valuesPath)

		Expect(ctx).To(ProduceYAML(RepresentingContainer("uaa")))
	})
})
