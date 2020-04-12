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

	smtpVolumeMountMatcher := gstruct.MatchFields(gstruct.IgnoreExtras, gstruct.Fields{
		"MountPath": Equal("/etc/secrets/smtp_credentials.yml"),
		"SubPath":   Equal("smtp_credentials.yml"),
		"ReadOnly":  Equal(true),
	})

	adminCredentialsVolumeMountMatcher := gstruct.MatchFields(gstruct.IgnoreExtras, gstruct.Fields{
		"Name":      Equal("admin-client-credentials-file"),
		"MountPath": Equal("/etc/secrets/admin_client_credentials.yml"),
		"SubPath":   Equal("admin_client_credentials.yml"),
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

		expectedJavaOpts := "" +
			"-Dspring_profiles=hsqldb " +
			"-Djava.security.egd=file:/dev/./urandom " +
			"-Dlogging.config=/etc/config/log4j2.properties " +
			"-Dlog4j.configurationFile=/etc/config/log4j2.properties " +
			"-DCLOUDFOUNDRY_CONFIG_PATH=/etc/config " +
			"-DSECRETS_DIR=/etc/secrets"

		Expect(ctx).To(
			ProduceYAML(
				RepresentingDeployment().WithPodMatching(func(pod *PodMatcher) {
					pod.WithServiceAccountMatching("uaa")
					pod.WithContainerMatching(func(container *ContainerMatcher) {
						container.WithName("uaa")
						container.WithImageContaining("cfidentity/uaa@sha256:")
						container.WithEnvVar("BPL_TOMCAT_ACCESS_LOGGING", "y")
						container.WithEnvVar("JAVA_OPTS", expectedJavaOpts)
						container.WithVolumeMount("uaa-config", Not(BeNil()))
						container.WithVolumeMount("database-credentials-file", databaseVolumeMountMatcher)
						container.WithVolumeMount("smtp-credentials-file", smtpVolumeMountMatcher)
						container.WithVolumeMount("admin-client-credentials-file", adminCredentialsVolumeMountMatcher)
						container.WithResourceRequests("512Mi", "500m")
					})
					pod.WithVolume("uaa-config", Not(BeNil()))
					pod.WithVolume("database-credentials-file", Not(BeNil()))
					pod.WithVolume("smtp-credentials-file", Not(BeNil()))
					pod.WithVolume("admin-client-credentials-file", Not(BeNil()))
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
							container.WithEnvVarMatching("JAVA_OPTS", ContainSubstring("-Dspring_profiles=postgresql"))
						})
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
				}),
			),
		)
	})
})
