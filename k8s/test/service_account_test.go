package k8s_test

import (
	. "github.com/cloudfoundry/uaa/matchers"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"path/filepath"
)

var _ = Describe("Service Account", func() {
	var templates []string

	BeforeEach(func() {
		templates = []string{
			pathToFile("service_account.yml"),
			pathToFile(filepath.Join("values", "_values.yml")),
			pathToFile(filepath.Join("values", "version.yml")),
		}
	})

	It("Renders a service account for the UAA", func() {
		templates = append(templates, pathToFile("metadata.yml"))
		ctx := NewRenderingContext(templates...)
		version := LoadVersionFromValues()

		Expect(ctx).To(
			ProduceYAML(
				RepresentingServiceAccount().
					WithName("uaa").
					WithAutomountServiceAccountToken(false).
					WithLabels(map[string]string{
						"app.kubernetes.io/name":       "uaa",
						"app.kubernetes.io/instance":   "uaa-standalone",
						"app.kubernetes.io/version":    version,
						"app.kubernetes.io/component":  "authorization_server",
						"app.kubernetes.io/part-of":    "uaa",
						"app.kubernetes.io/managed-by": "kubectl",
					}),
			),
		)
	})

	When("AutomountServiceAccountToken is true", func() {
		It("Renders a service account with AutomountServiceAccountToken set to true", func() {
			templates = append(templates, filepath.Join("..", "test_fixtures", "enable-automount-service-account-token.yml"))
			ctx := NewRenderingContext(templates...)

			Expect(ctx).To(
				ProduceYAML(
					RepresentingServiceAccount().
						WithName("uaa").
						WithAutomountServiceAccountToken(true)))
		})
	})
})
