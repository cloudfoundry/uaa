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

	When("Parsing YAML", func() {
		It("Constructs the YAML from a set of files", func() {
			ctx := NewRenderingContext(deploymentPath, valuesPath)

			Expect(ctx).To(ProduceYAML(
				RepresentingContainer("uaa").RunningImage("cfidentity/uaa@sha256:93b70b26fbb3de88d93728b0daf1ea7b001fde89a24e283c3db36bf4c6af087c"),
			))
		})

		It("Constructs YAML from a set of files and command line values ", func() {
			ctx := NewRenderingContext(deploymentPath, valuesPath).WithData(map[string]string{
				"image_sha": "other",
			})

			Expect(ctx).To(ProduceYAML(RepresentingContainer("uaa").RunningImage("cfidentity/uaa@sha256:other")))
		})
	})

	When("Using YTT test overlays", func() {
		It("Constructs the YAML from a set of files", func() {
			ctx := NewRenderingContext(deploymentPath, valuesPath)
			Expect(ctx).To(SatisfyTestOverlay(pathToTestOverlay("image_test.yml")))
		})

		It("Constructs YAML from a set of files and command line values ", func() {
			ctx := NewRenderingContext(deploymentPath, valuesPath).WithData(map[string]string{
				"image_sha": "other",
			})

			Expect(ctx).To(SatisfyTestOverlay(pathToTestOverlay("image_override_test.yml")))
		})
	})
})
