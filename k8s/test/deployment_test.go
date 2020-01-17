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
		valuesPath = pathToTemplate(filepath.Join("..", "values", "default-values.yml"))
	})

	It("Renders a deployment for the UAA", func() {
		ctx := NewRenderingContext(deploymentPath, valuesPath)

		Expect(ctx).To(
			ProduceYAML(
				RepresentingDeployment().WithPodMatching(func(pod *PodMatcher) {
					pod.WithContainerMatching(func(container *ContainerMatcher) {
						container.WithName("uaa")
						container.WithEnvVar("spring_profiles", "default,hsqldb")
						container.WithEnvVar("UAA_CONFIG_PATH", "/etc/config")
					})
				}),
			),
		)
	})
})
