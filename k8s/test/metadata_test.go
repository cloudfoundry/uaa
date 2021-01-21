package k8s_test

import (
	. "github.com/cloudfoundry/uaa/matchers"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"path/filepath"
)

var _ = Describe("Metadata", func() {
	var templates []string

	BeforeEach(func() {
		templates = []string{
			pathToFile("metadata.yml"),
		}
	})

	It("Renders common labels", func() {
		templates = append(templates, pathToFile("deployment.yml"))
		templates = append(templates, pathToFile("deployment.star"))
		templates = append(templates, "secrets/ca_certs.star="+pathToFile(filepath.Join("secrets", "ca_certs.star")))
		templates = append(templates, pathToFile(filepath.Join("values", "_values.yml")))
		ctx := NewRenderingContext(templates...).WithData(map[string]string{
			"labels.instance":  "instance-from-test",
			"labels.partOf":    "partOf-from-test",
			"labels.managedBy": "managedBy-from-test",
			"version":          "version-from-test",
			"namespace":        "namespace-from-test",
			"database.scheme":  "hsqldb",
		})

		labels := map[string]string{
			"app.kubernetes.io/name":       "uaa",
			"app.kubernetes.io/instance":   "uaa-instance-from-test",
			"app.kubernetes.io/version":    "version-from-test",
			"app.kubernetes.io/component":  "authorization_server",
			"app.kubernetes.io/part-of":    "partOf-from-test",
			"app.kubernetes.io/managed-by": "managedBy-from-test",
		}

		Expect(ctx).To(
			ProduceYAML(
				RepresentingDeployment().
					WithMetaMatching(func(metadata *ObjectMetaMatcher) {
						metadata.WithLabels(labels)
						metadata.WithNamespace("namespace-from-test")
					}).
					WithPodMatching(func(pod *PodMatcher) {
						pod.WithMetaMatching(func(metadata *ObjectMetaMatcher) {
							metadata.WithLabels(labels)
							metadata.WithNamespace("namespace-from-test")
						})
					}),
			),
		)
	})
})
