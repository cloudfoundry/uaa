package k8s_test

import (
	"path/filepath"
	"strings"

	. "github.com/cloudfoundry/uaa/matchers"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/gstruct"
	coreV1 "k8s.io/api/core/v1"
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

	samlKeysVolumeMountMatcher := gstruct.MatchFields(gstruct.IgnoreExtras, gstruct.Fields{
		"Name":      Equal("saml-keys-file"),
		"MountPath": Equal("/etc/secrets/saml_keys.yml"),
		"SubPath":   Equal("saml_keys.yml"),
		"ReadOnly":  Equal(true),
	})

	encryptionKeysVolumeMountMatcher := gstruct.MatchFields(gstruct.IgnoreExtras, gstruct.Fields{
		"Name":      Equal("encryption-keys-file"),
		"MountPath": Equal("/etc/secrets/encryption_keys.yml"),
		"SubPath":   Equal("encryption_keys.yml"),
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

	Describe("Prometheus metrics", func() {
		It("Renders the deployment with prometheus annotations", func() {
			ctx := NewRenderingContext(templates...).WithData(
				map[string]string{
					"database.scheme": "hsqldb",
				})

			annotationsMap := map[string]string{
				"prometheus.io/scrape": "true",
				"prometheus.io/port":   "9102",
				"prometheus.io/path":   "/metrics",
			}

			Expect(ctx).To(
				ProduceYAML(
					RepresentingDeployment().
						WithPodMatching(func(pod *PodMatcher) {
							pod.WithMetaMatching(func(metadata *ObjectMetaMatcher) {
								metadata.WithAnnotations(annotationsMap)
							})
						}),
				),
			)
		})

		It("Renders a container for StatsD Exporter", func() {
			ctx := NewRenderingContext(templates...).WithData(map[string]string{
				"database.scheme": "hsqldb",
			})

			Expect(ctx).To(
				ProduceYAML(RepresentingDeployment().
					WithPodMatching(func(pod *PodMatcher) {
						pod.WithContainerMatching(func(container *ContainerMatcher) {

							expectedPort := coreV1.ContainerPort{
								Name:          "metrics-uaa",
								ContainerPort: 9102,
								Protocol:      "TCP",
							}

							container.
								WithArgs([]string{"--statsd.listen-udp=:8125"}).
								WithPort(expectedPort).
								WithName("statsd-exporter").
								WithImageContaining("cloudfoundry/statsd_exporter").
								WithImagePullPolicy("Always")
						})
					}),
				),
			)
		})
	})

	It("Renders a deployment for the UAA", func() {
		ctx := NewRenderingContext(templates...).WithData(
			map[string]string{
				"database.scheme": "hsqldb",
			})

		expectedJavaOpts := []string{
			"-Dspring_profiles=hsqldb",
			"-Djava.security.egd=file:/dev/./urandom",
			"-Dlogging.config=/etc/config/log4j2.properties",
			"-Dlog4j.configurationFile=/etc/config/log4j2.properties",
			"-DCLOUDFOUNDRY_CONFIG_PATH=/etc/config",
			"-DSECRETS_DIR=/etc/secrets",
			"-Djavax.net.ssl.trustStore=/etc/truststore/uaa.pkcs12.truststore",
			"-Djavax.net.ssl.trustStoreType=PKCS12",
			"-Djavax.net.ssl.trustStorePassword=changeit",
			"-Dstatsd.enabled=true",
			"-Dservlet.session-store=database",
		}

		Expect(ctx).To(
			ProduceYAML(
				RepresentingDeployment().WithPodMatching(func(pod *PodMatcher) {
					pod.WithServiceAccountMatching("uaa")
					pod.WithContainerMatching(func(container *ContainerMatcher) {
						container.WithName("uaa")
						container.WithImageContaining("cloudfoundry/uaa@sha256:")
						container.WithEnvVar("BPL_TOMCAT_ACCESS_LOGGING", "y")
						container.WithEnvVar("JAVA_OPTS", strings.Join(expectedJavaOpts, " "))
						container.WithVolumeMount("uaa-config", Not(BeNil()))
						container.WithVolumeMount("database-credentials-file", databaseVolumeMountMatcher)
						container.WithVolumeMount("smtp-credentials-file", smtpVolumeMountMatcher)
						container.WithVolumeMount("admin-client-credentials-file", adminCredentialsVolumeMountMatcher)
						container.WithVolumeMount("jwt-policy-signing-keys-file", jwtTokensVolumeMountMatcher)
						container.WithVolumeMount("truststore-file", truststoreVolumeMountMatcher)
						container.WithVolumeMount("saml-keys-file", samlKeysVolumeMountMatcher)
						container.WithVolumeMount("encryption-keys-file", encryptionKeysVolumeMountMatcher)
						container.WithResources("512Mi", "50m", "2000Mi", "500m")
					})
					pod.WithVolume("uaa-config", Not(BeNil()))
					pod.WithVolume("database-credentials-file", Not(BeNil()))
					pod.WithVolume("smtp-credentials-file", Not(BeNil()))
					pod.WithVolume("admin-client-credentials-file", Not(BeNil()))
					pod.WithVolume("jwt-policy-signing-keys-file", Not(BeNil()))
					pod.WithVolume("truststore-file", Not(BeNil()))
					pod.WithVolume("saml-keys-file", Not(BeNil()))
					pod.WithVolume("encryption-keys-file", Not(BeNil()))
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
				"resources.uaa.requests.memory": "888Mi",
				"resources.uaa.requests.cpu":    "999m",
				"resources.uaa.limits.memory":   "1100Mi",
				"resources.uaa.limits.cpu":      "1200m",
				"database.scheme":               "hsqldb",
			})

		Expect(ctx).To(
			ProduceYAML(
				RepresentingDeployment().WithPodMatching(func(pod *PodMatcher) {
					pod.WithContainerMatching(func(container *ContainerMatcher) {
						container.WithName("uaa")
						container.WithResources("888Mi", "999m", "1100Mi", "1200m")
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
				WithMetaMatching(func(metadata *ObjectMetaMatcher) {
					metadata.WithLabels(labels)
					metadata.WithNamespace("default")
				}).
				WithPodMatching(func(pod *PodMatcher) {
					pod.WithMetaMatching(func(metadata *ObjectMetaMatcher) {
						metadata.WithLabels(labels)
					})
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
