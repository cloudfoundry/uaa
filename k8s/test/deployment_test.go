package k8s_test

import (
	. "github.com/cloudfoundry/uaa/matchers"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/gstruct"
	"path/filepath"
)

var _ = Describe("Deployment", func() {
	var templates []string

	databaseVolumeMountMatcher := gstruct.MatchFields(gstruct.IgnoreExtras, gstruct.Fields{
		"MountPath": Equal("/etc/secrets/database_credentials.yml"),
		"SubPath":   Equal("database_credentials.yml"),
		"ReadOnly":  Equal(true),
	})

	BeforeEach(func() {
		templates = []string{
			pathToFile("deployment.yml"),
			pathToFile(filepath.Join("values", "_values.yml")),
			pathToFile(filepath.Join("values", "image.yml")),
			pathToFile(filepath.Join("values", "version.yml")),
			pathToFile("deployment.star"),
		}
	})

	It("Renders a deployment for the UAA", func() {
		ctx := NewRenderingContext(templates...)

		Expect(ctx).To(
			ProduceYAML(
				RepresentingDeployment().WithPodMatching(func(pod *PodMatcher) {
					pod.WithServiceAccountMatching("uaa")
					pod.WithContainerMatching(func(container *ContainerMatcher) {
						container.WithName("uaa")
						container.WithImageContaining("cfidentity/uaa@sha256:")
						container.WithEnvVar("spring_profiles", "default,hsqldb")
						container.WithEnvVar("CLOUDFOUNDRY_CONFIG_PATH", "/etc/config")
						container.WithEnvVar("BPL_TOMCAT_ACCESS_LOGGING", "y")
						container.WithEnvVar("JAVA_OPTS", "-Djava.security.egd=file:/dev/./urandom -Dlogging.config=/etc/config/log4j2.properties -Dlog4j.configurationFile=/etc/config/log4j2.properties")
						container.WithEnvVar("SECRETS_DIR", "/etc/secrets")
						container.WithVolumeMount("uaa-config", Not(BeNil()))
						container.WithVolumeMount("database-credentials-file", databaseVolumeMountMatcher)
						container.WithResourceRequests("512Mi", "500m")
					})
					pod.WithVolume("uaa-config", Not(BeNil()))
					pod.WithVolume("database-credentials-file", Not(BeNil()))
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
						container.WithVolumeMount("uaa-config", Not(BeNil()))
						container.WithVolumeMount("database-credentials-file", databaseVolumeMountMatcher)
					})
					pod.WithVolume("uaa-config", Not(BeNil()))
					pod.WithVolume("database-credentials-file", Not(BeNil()))
				}),
			),
		)
	})

	It("Renders custom resource requests for the UAA", func() {
		ctx := NewRenderingContext(templates...).WithData(
			map[string]string{
				"resources.requests.memory": "888Mi",
				"resources.requests.cpu":    "999m",
			})

		Expect(ctx).To(
			ProduceYAML(
				RepresentingDeployment().WithPodMatching(func(pod *PodMatcher) {
					pod.WithContainerMatching(func(container *ContainerMatcher) {
						container.WithName("uaa")
						container.WithResourceRequests("888Mi", "999m")
						container.WithVolumeMount("uaa-config", Not(BeNil()))
						container.WithVolumeMount("database-credentials-file", databaseVolumeMountMatcher)
					})
					pod.WithVolume("uaa-config", Not(BeNil()))
					pod.WithVolume("database-credentials-file", Not(BeNil()))
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
				"database.scheme":   databaseScheme,
				"database.username": "database username",
				"database.password": "database password",
			})
		})

		It("Renders a deployment with the custom values interpolated", func() {
			Expect(ctx).To(
				ProduceYAML(
					RepresentingDeployment().WithPodMatching(func(pod *PodMatcher) {
						pod.WithContainerMatching(func(container *ContainerMatcher) {
							container.WithName("uaa")
							container.WithEnvVar("spring_profiles", databaseScheme)
							container.WithVolumeMount("uaa-config", Not(BeNil()))
							container.WithVolumeMount("database-credentials-file", databaseVolumeMountMatcher)
						})
						pod.WithVolume("uaa-config", Not(BeNil()))
						pod.WithVolume("database-credentials-file", Not(BeNil()))
					}),
				),
			)
		})
	})

	It("Renders common labels for the deployment", func() {
		templates = append(templates, pathToFile("metadata.yml"))
		ctx := NewRenderingContext(templates...).WithData(map[string]string{
			"version": "1.0.0",
		})

		labels := map[string]string{
			"app.kubernetes.io/name":       "uaa",
			"app.kubernetes.io/instance":   "uaa-standalone",
			"app.kubernetes.io/version":    "1.0.0",
			"app.kubernetes.io/component":  "authorization_server",
			"app.kubernetes.io/part-of":    "uaa",
			"app.kubernetes.io/managed-by": "kubectl",
		}
		Expect(ctx).To(
			ProduceYAML(RepresentingDeployment().
				WithLabels(labels).
				WithNamespace("default").
				WithPodMatching(func(pod *PodMatcher) {
					pod.WithLabels(labels)
					pod.WithVolume("uaa-config", Not(BeNil()))
					pod.WithVolume("database-credentials-file", Not(BeNil()))
				}),
			),
		)
	})
})
