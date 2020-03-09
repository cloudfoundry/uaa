package k8s_test

import (
	. "github.com/cloudfoundry/uaa/matchers"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"path/filepath"
)

var _ = Describe("Secrets", func() {

	var templates []string

	BeforeEach(func() {
		templates = []string{
			pathToFile(filepath.Join("values", "_values.yml")),
			pathToFile("smtp_credentials.yml"),
		}
	})

	It("Renders with SMTP credentials", func() {
		renderingContext := NewRenderingContext(templates...).WithData(
			map[string]string{
				"smtp.user":     "my smtp username",
				"smtp.password": "my smtp password",
				"smtp.host":     "my smtp host",
				"smtp.port":     "my smtp port",
				"smtp.starttls": "my smtp starttls",
			})

		smtp_secrets := `smtp:
  user: my smtp username
  password: my smtp password
  host: my smtp host
  port: my smtp port
  starttls: my smtp starttls
`

		Expect(renderingContext).To(
			ProduceYAML(RepresentingASecret().
				WithStringData("smtp_credentials.yml", smtp_secrets)),
		)
	})
})
