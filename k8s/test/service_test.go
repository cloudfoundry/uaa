package k8s_test

import (
	. "github.com/cloudfoundry/uaa/matchers"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"path/filepath"
)

var _ = Describe("Service", func() {
	var templates []string

	BeforeEach(func() {
		templates = []string{
			pathToFile("service.yml"),
		}
	})

	It("Renders common labels", func() {
		templates = append(templates, pathToFile("metadata.yml"))
		templates = append(templates, pathToFile(filepath.Join("values", "_values.yml")))
		ctx := NewRenderingContext(templates...).WithData(map[string]string{
			"version": "version for service metadata label",
		})

		labels := map[string]string{
			"app.kubernetes.io/name":       "uaa",
			"app.kubernetes.io/instance":   "uaa-standalone",
			"app.kubernetes.io/version":    "version for service metadata label",
			"app.kubernetes.io/component":  "authorization_server",
			"app.kubernetes.io/part-of":    "uaa",
			"app.kubernetes.io/managed-by": "kubectl",
		}
		Expect(ctx).To(
			ProduceYAML(RepresentingService().WithLabels(labels).WithNamespace("default")),
		)
	})
})
