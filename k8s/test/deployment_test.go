package k8s_test

import (
	. "github.com/cloudfoundry/uaa/matchers"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"path/filepath"
)

var _ = Describe("Deployment", func() {
	var templates []string

	BeforeEach(func() {
		templates = []string{
			pathToTemplate("deployment.yml"),
			pathToTemplate(filepath.Join("values", "_values.yml")),
			pathToTemplate(filepath.Join("values", "image.yml")),
			pathToTemplate(filepath.Join("values", "version.yml")),
			pathToTemplate("deployment_functions.star"),
		}
	})

	It("Renders a deployment for the UAA", func() {
		ctx := NewRenderingContext(templates...)

		Expect(ctx).To(
			ProduceYAML(
				RepresentingDeployment().WithPodMatching(func(pod *PodMatcher) {
					pod.WithContainerMatching(func(container *ContainerMatcher) {
						container.WithName("uaa")
						container.WithImageContaining("cfidentity/uaa@sha256:")
						container.WithEnvVar("spring_profiles", "default,hsqldb")
						container.WithEnvVar("UAA_CONFIG_PATH", "/etc/config")
					})
				}),
			),
		)
	})

	It("Renders a custom image for the UAA", func() {
		ctx := NewRenderingContext(templates...).WithData(
			map[string]string{"image": "image from testing"})

		Expect(ctx).To(
			ProduceYAML(
				RepresentingDeployment().WithPodMatching(func(pod *PodMatcher) {
					pod.WithContainerMatching(func(container *ContainerMatcher) {
						container.WithName("uaa")
						container.WithImage("image from testing")
					})
				}),
			),
		)
	})

	When("provided with custom values", func() {
		var (
			databaseScheme string
			ctx            RenderingContext
		)

		BeforeEach(func() {
			databaseScheme = "postgresql"
			ctx = NewRenderingContext(templates...).WithData(map[string]string{
				"database.scheme": databaseScheme,
			})
		})

		It("Renders a deployment with the custom values interpolated", func() {
			Expect(ctx).To(
				ProduceYAML(
					RepresentingDeployment().WithPodMatching(func(pod *PodMatcher) {
						pod.WithContainerMatching(func(container *ContainerMatcher) {
							container.WithName("uaa")
							container.WithEnvVar("spring_profiles", databaseScheme)
						})
					}),
				),
			)
		})
	})

	It("Renders common labels for the deployment", func() {
		ctx := NewRenderingContext(templates...).WithData(map[string]string{
			"version": "1.0.0",
		})

		Expect(ctx).To(
			ProduceYAML(RepresentingDeployment().WithLabels(map[string]string{
				"app.kubernetes.io/name":       "uaa",
				"app.kubernetes.io/instance":   "uaa-standalone",
				"app.kubernetes.io/version":    "1.0.0",
				"app.kubernetes.io/component":  "authorization-server",
				"app.kubernetes.io/part-of":    "uaa",
				"app.kubernetes.io/managed-by": "kapp",
			})),
		)
	})
})
