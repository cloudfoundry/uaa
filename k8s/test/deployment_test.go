package k8s_test

import (
	. "github.com/cloudfoundry/uaa/matchers"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/ginkgo/extensions/table"
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

	jwtTokensVolumeMountMatcher := gstruct.MatchFields(gstruct.IgnoreExtras, gstruct.Fields{
		"Name":      Equal("jwt-policy-signing-keys-file"),
		"MountPath": Equal("/etc/secrets/jwt_policy_signing_keys.yml"),
		"SubPath":   Equal("jwt_policy_signing_keys.yml"),
		"ReadOnly":  Equal(true),
	})

	truststoreVolumeMountMatcher := gstruct.MatchFields(gstruct.IgnoreExtras, gstruct.Fields{
		"Name":      Equal("truststore-file"),
		"MountPath": Equal("/etc/truststore"),
		"ReadOnly":  Equal(true),
	})

	BeforeEach(func() {
		templates = []string{
			pathToFile("deployment.yml"),
			pathToFile(filepath.Join("values", "_values.yml")),
			pathToFile(filepath.Join("values", "image.yml")),
			pathToFile(filepath.Join("values", "version.yml")),
			pathToFile("deployment.star"),
			"secrets/ca_certs.star=" + pathToFile(filepath.Join("secrets", "ca_certs.star")),
		}
	})

	It("Renders a deployment for the UAA", func() {
		ctx := NewRenderingContext(templates...).WithData(
			map[string]string{
				"database.scheme": "hsqldb",
			})

		expectedJavaOpts := "" +
			"-Dspring_profiles=hsqldb " +
			"-Djava.security.egd=file:/dev/./urandom " +
			"-Dlogging.config=/etc/config/log4j2.properties " +
			"-Dlog4j.configurationFile=/etc/config/log4j2.properties " +
			"-DCLOUDFOUNDRY_CONFIG_PATH=/etc/config " +
			"-DSECRETS_DIR=/etc/secrets " +
			"-Djavax.net.ssl.trustStore=/etc/truststore/uaa.pkcs12.truststore " +
			"-Djavax.net.ssl.trustStoreType=PKCS12 " +
			"-Djavax.net.ssl.trustStorePassword=changeit"

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
						container.WithVolumeMount("jwt-policy-signing-keys-file", jwtTokensVolumeMountMatcher)
						container.WithVolumeMount("truststore-file", truststoreVolumeMountMatcher)
						container.WithResourceRequests("512Mi", "500m")
					})
					pod.WithVolume("uaa-config", Not(BeNil()))
					pod.WithVolume("database-credentials-file", Not(BeNil()))
					pod.WithVolume("smtp-credentials-file", Not(BeNil()))
					pod.WithVolume("admin-client-credentials-file", Not(BeNil()))
					pod.WithVolume("jwt-policy-signing-keys-file", Not(BeNil()))
					pod.WithVolume("truststore-file", Not(BeNil()))
				}),
			),
		)
	})

	It("Renders a custom image for the UAA", func() {
		ctx := NewRenderingContext(templates...).WithData(
			map[string]string{
				"image":           "image from testing",
				"database.scheme": "hsqldb",
			})

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
				"database.scheme":           "hsqldb",
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
				"database.scheme": databaseScheme,
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
			"version":         "1.0.0",
			"database.scheme": "hsqldb",
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

	DescribeTable("Fails to render unless database.scheme is valid",
		func(databaseScheme string, shouldThrow bool) {
			ctx := NewRenderingContext(templates...).WithData(map[string]string{
				"database.scheme": databaseScheme,
			})

			if shouldThrow {
				Expect(ctx).To(ThrowError("database.scheme must be one of hsqldb, mysql, or postgresql"))
			} else {
				Expect(ctx).To(ProduceYAML(RepresentingDeployment()))
			}
		},
		Entry("database.scheme=", "", true),
		Entry("database.scheme=foobar", "foobar", true),
		Entry("database.scheme=mysql", "mysql", false),
		Entry("database.scheme=postgresql", "postgresql", false),
		Entry("database.scheme=hsqldb", "hsqldb", false),
	)

	It("Fails to render when database.scheme is not provided", func() {
		ctx := NewRenderingContext(templates...)
		Expect(ctx).To(ThrowError("database.scheme must be one of hsqldb, mysql, or postgresql"))
	})
})
