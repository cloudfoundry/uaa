package k8s_test

import (
	. "github.com/cloudfoundry/uaa/matchers"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"path/filepath"
)

var _ = Describe("Secrets", func() {

	var templates []string

	It("Renders with SMTP credentials", func() {
		templates = []string{
			pathToFile(filepath.Join("values", "_values.yml")),
			pathToFile(filepath.Join("secrets", "smtp_credentials.yml")),
		}

		renderingContext := NewRenderingContext(templates...).WithData(
			map[string]string{
				"smtp.user":     "my smtp username",
				"smtp.password": "my smtp password",
			})

		smtp_secrets := `smtp:
  user: my smtp username
  password: my smtp password
`

		Expect(renderingContext).To(
			ProduceYAML(RepresentingASecret().
				WithName("uaa-smtp-credentials").
				WithStringData("smtp_credentials.yml", smtp_secrets)),
		)
	})

	It("Does not render with empty SMTP credentials", func() {
		templates = []string{
			pathToFile(filepath.Join("values", "_values.yml")),
			pathToFile(filepath.Join("secrets", "smtp_credentials.yml")),
		}

		renderingContext := NewRenderingContext(templates...)

		Expect(renderingContext).To(ProduceEmptyYAML())
	})

	It("Renders with Database credentials", func() {
		templates = []string{
			pathToFile(filepath.Join("values", "_values.yml")),
			pathToFile(filepath.Join("secrets", "database_credentials.yml")),
		}

		renderingContext := NewRenderingContext(templates...).WithData(
			map[string]string{
				"database.username": "my database username",
				"database.password": "my database password",
			})

		database_credentials := `database:
  username: my database username
  password: my database password
`

		Expect(renderingContext).To(
			ProduceYAML(RepresentingASecret().
				WithName("uaa-database-credentials").
				WithStringData("database_credentials.yml", database_credentials)),
		)
	})

	It("Renders with Different Database credentials", func() {
		templates = []string{
			pathToFile(filepath.Join("values", "_values.yml")),
			pathToFile(filepath.Join("secrets", "database_credentials.yml")),
		}

		renderingContext := NewRenderingContext(templates...).WithData(
			map[string]string{
				"database.username": "my other database username",
				"database.password": "my other database password",
			})

		database_credentials := `database:
  username: my other database username
  password: my other database password
`

		Expect(renderingContext).To(
			ProduceYAML(RepresentingASecret().
				WithName("uaa-database-credentials").
				WithStringData("database_credentials.yml", database_credentials)),
		)
	})

	It("Does Not Render with Missing Database credentials", func() {
		templates = []string{
			pathToFile(filepath.Join("values", "_values.yml")),
			pathToFile(filepath.Join("secrets", "database_credentials.yml")),
		}

		renderingContext := NewRenderingContext(templates...).WithData(
			map[string]string{
				"database.username": "",
				"database.password": "",
			})

		Expect(renderingContext).To(ProduceEmptyYAML())
	})

	It("Renders with admin client credentials", func() {
		templates = []string{
			pathToFile(filepath.Join("values", "_values.yml")),
			pathToFile(filepath.Join("secrets", "admin_client_credentials.yml")),
		}

		renderingContext := NewRenderingContext(templates...).WithData(
			map[string]string{
				"admin.client_secret": "my admin client secret",
			})

		adminClientCredentials := `oauth:
  clients:
    admin:
      secret: my admin client secret
`

		Expect(renderingContext).To(
			ProduceYAML(RepresentingASecret().
				WithName("uaa-admin-client-credentials").
				WithStringData("admin_client_credentials.yml", adminClientCredentials)),
		)
	})

})
