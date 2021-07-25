package k8s_test

import (
	. "github.com/cloudfoundry/uaa/matchers"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"path/filepath"
)

var _ = Describe("Secrets", func() {

	var templates []string

	Context("SMTP Credentials", func() {
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
	})

	Context("Database Credentials", func() {
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
	})

	Context("Admin Client Credentials", func() {
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

		It("Admin client credentials are required", func() {
			templates = []string{
				pathToFile(filepath.Join("values", "_values.yml")),
				pathToFile(filepath.Join("secrets", "admin_client_credentials.yml")),
			}

			renderingContext := NewRenderingContext(templates...)

			Expect(renderingContext).To(
				ThrowError("admin.client_secret is required"),
			)
		})
	})

	Context("JWT Policy Signing Keys", func() {
		It("Renders into secret", func() {
			templates = []string{
				pathToFile(filepath.Join("values", "_values.yml")),
				pathToFile(filepath.Join("secrets", "jwt_policy_signing_keys.yml")),
				pathToFile(filepath.Join("secrets", "jwt_policy_signing_keys.star")),
				pathToFile(filepath.Join("..", "test_fixtures", "signing-key-fixture1.yml")),
			}

			renderingContext := NewRenderingContext(templates...)

			jwtPolicySigningKeys := `jwt:
  token:
    policy:
      activeKeyId: my_active_key_id
      keys:
        my_active_key_id:
          signingKey: aaa
`

			Expect(renderingContext).To(
				ProduceYAML(RepresentingASecret().
					WithName("uaa-jwt-policy-signing-keys").
					WithStringData("jwt_policy_signing_keys.yml", jwtPolicySigningKeys)),
			)
		})

		It("Renders into secret with different values", func() {
			templates = []string{
				pathToFile(filepath.Join("values", "_values.yml")),
				pathToFile(filepath.Join("secrets", "jwt_policy_signing_keys.yml")),
				pathToFile(filepath.Join("secrets", "jwt_policy_signing_keys.star")),
				pathToFile(filepath.Join("..", "test_fixtures", "signing-key-fixture2.yml")),
			}

			renderingContext := NewRenderingContext(templates...)

			jwtPolicySigningKeys := `jwt:
  token:
    policy:
      activeKeyId: other_active_key2
      keys:
        other_active_key2:
          signingKey: |
            this
            is
            a
            multiline
            string
        unused_key_id:
          signingKey: unused_signing_key
`

			Expect(renderingContext).To(
				ProduceYAML(RepresentingASecret().
					WithName("uaa-jwt-policy-signing-keys").
					WithStringData("jwt_policy_signing_keys.yml", jwtPolicySigningKeys)),
			)
		})

		It("activeKeyId is required", func() {
			templates = []string{
				pathToFile(filepath.Join("values", "_values.yml")),
				pathToFile(filepath.Join("secrets", "jwt_policy_signing_keys.yml")),
				pathToFile(filepath.Join("secrets", "jwt_policy_signing_keys.star")),
			}

			renderingContext := NewRenderingContext(templates...)

			Expect(renderingContext).To(
				ThrowError("fail: jwt.policy.activeKeyId is required"),
			)
		})

		It("activeKeyId must be present in keys", func() {
			templates = []string{
				pathToFile(filepath.Join("values", "_values.yml")),
				pathToFile(filepath.Join("secrets", "jwt_policy_signing_keys.yml")),
				pathToFile(filepath.Join("secrets", "jwt_policy_signing_keys.star")),
				pathToFile(filepath.Join("..", "test_fixtures", "signing-key-fixture-missing-active-key-id1.yml")),
			}

			renderingContext := NewRenderingContext(templates...)

			Expect(renderingContext).To(
				ThrowError("fail: jwt.policy.keys must contain keyId matching jwt.policy.activeKeyId"),
			)
		})

		It("keys must be an object", func() {
			templates = []string{
				pathToFile(filepath.Join("values", "_values.yml")),
				pathToFile(filepath.Join("secrets", "jwt_policy_signing_keys.yml")),
				pathToFile(filepath.Join("secrets", "jwt_policy_signing_keys.star")),
			}

			renderingContext := NewRenderingContext(templates...).WithData(map[string]string{
				"jwt.policy.activeKeyId": "any value",
				"jwt.policy.keys":        "not a list",
			})

			Expect(renderingContext).To(
				ThrowError("fail: jwt.policy.keys must be an object"),
			)
		})
	})

	Context("CA Certs", func() {
		It("Renders when CA Certs are present", func() {
			templates = []string{
				pathToFile(filepath.Join("values", "_values.yml")),
				pathToFile(filepath.Join("secrets", "ca_certs.yml")),
				pathToFile(filepath.Join("secrets", "ca_certs.star")),
				pathToFile(filepath.Join("..", "test_fixtures", "ca_certs.yml")),
			}

			renderingContext := NewRenderingContext(templates...)

			cert0 :=
				`-----BEGIN CERTIFICATE-----
MIIEjjCCA3agAwIBAgIJAI33lwF8rywxMA0GCSqGSIb3DQEBBQUAMIGKMQswCQYD
...
ScMdzkIk7jUztpr7pubxydSf
-----END CERTIFICATE-----`
			cert1 :=
				`not
a
real
cert`
			cert2 := `i am a string`

			Expect(renderingContext).To(
				ProduceYAML(RepresentingASecret().
					WithName("uaa-ca-certs").
					WithData("uaa-ca-cert0.pem", []byte(cert0)).
					WithData("uaa-ca-cert1.pem", []byte(cert1)).
					WithData("uaa-ca-cert2.pem", []byte(cert2)),
				),
			)
		})

		It("Does not render when CA Certs are empty", func() {
			templates = []string{
				pathToFile(filepath.Join("values", "_values.yml")),
				pathToFile(filepath.Join("secrets", "ca_certs.yml")),
				pathToFile(filepath.Join("secrets", "ca_certs.star")),
			}

			renderingContext := NewRenderingContext(templates...)

			Expect(renderingContext).To(ProduceEmptyYAML())
		})
	})

	Context("SAML Keys", func() {
		It("Renders into secrets", func() {
			templates = []string{
				pathToFile(filepath.Join("values", "_values.yml")),
				pathToFile(filepath.Join("secrets", "saml_keys.yml")),
				pathToFile(filepath.Join("secrets", "saml_keys.star")),
				pathToFile(filepath.Join("..", "test_fixtures", "saml_keys_fixtures1.yml")),
			}

			renderingContext := NewRenderingContext(templates...)

			samlKeys := `login:
  saml:
    activeKeyId: key1
    keys:
      key1:
        key: private-key-here
        passphrase: passphrase-was-here
        certificate: certificate-goes-here
`

			Expect(renderingContext).To(
				ProduceYAML(RepresentingASecret().
					WithName("uaa-saml-keys").
					WithStringData("saml_keys.yml", samlKeys)))
		})

		It("Renders into secret with different values", func() {
			templates = []string{
				pathToFile(filepath.Join("values", "_values.yml")),
				pathToFile(filepath.Join("secrets", "saml_keys.yml")),
				pathToFile(filepath.Join("secrets", "saml_keys.star")),
				pathToFile(filepath.Join("..", "test_fixtures", "saml_keys_fixtures2.yml")),
			}

			renderingContext := NewRenderingContext(templates...)

			samlKeys := `login:
  saml:
    activeKeyId: keyWest
    keys:
      keyWest:
        key: different-private-key-here
        passphrase: different-passphrase-was-here
        certificate: different-certificate-goes-here
`

			Expect(renderingContext).To(
				ProduceYAML(RepresentingASecret().
					WithName("uaa-saml-keys").
					WithStringData("saml_keys.yml", samlKeys)),
			)
		})

		It("Requires an activeKeyId entry", func() {
			templates = []string{
				pathToFile(filepath.Join("values", "_values.yml")),
				pathToFile(filepath.Join("secrets", "saml_keys.yml")),
				pathToFile(filepath.Join("secrets", "saml_keys.star")),
				pathToFile(filepath.Join("..", "test_fixtures", "saml_keys_fixtures_missing_active_key_id_entry.yml")),
			}

			renderingContext := NewRenderingContext(templates...)

			Expect(renderingContext).To(
				ThrowError("fail: login.saml.activeKeyId is required"))
		})

		It("Requires a value for activeKeyId", func() {
			templates = []string{
				pathToFile(filepath.Join("values", "_values.yml")),
				pathToFile(filepath.Join("secrets", "saml_keys.yml")),
				pathToFile(filepath.Join("secrets", "saml_keys.star")),
				pathToFile(filepath.Join("..", "test_fixtures", "saml_keys_fixtures_no_key_set_as_active_key_id.yml")),
			}

			renderingContext := NewRenderingContext(templates...)

			Expect(renderingContext).To(
				ThrowError("fail: login.saml.activeKeyId is required"))
		})

		It("activeKeyId must be found in the list of keys", func() {
			templates = []string{
				pathToFile(filepath.Join("values", "_values.yml")),
				pathToFile(filepath.Join("secrets", "saml_keys.yml")),
				pathToFile(filepath.Join("secrets", "saml_keys.star")),
				pathToFile(filepath.Join("..", "test_fixtures", "saml_keys_fixtures_unmatched_active_key_id.yml")),
			}

			renderingContext := NewRenderingContext(templates...)

			Expect(renderingContext).To(
				ThrowError("fail: login.saml.activeKeyId must reference key in login.saml.keys"),
			)
		})

		It("keys must be an object", func() {
			templates = []string{
				pathToFile(filepath.Join("values", "_values.yml")),
				pathToFile(filepath.Join("secrets", "saml_keys.yml")),
				pathToFile(filepath.Join("secrets", "saml_keys.star")),
			}

			renderingContext := NewRenderingContext(templates...).WithData(map[string]string{
				"login.saml.activeKeyId": "any value",
				"login.saml.keys":        "not a list",
			})

			Expect(renderingContext).To(
				ThrowError("fail: login.saml.keys must be an object"),
			)
		})
	})

	Context("Encryption Keys", func() {
		It("Renders into secrets", func() {
			templates = []string{
				pathToFile(filepath.Join("secrets", "encryption_keys.yml")),
				pathToFile(filepath.Join("secrets", "encryption_keys.star")),
				pathToFile(filepath.Join("values", "_values.yml")),
				pathToFile(filepath.Join("..", "test_fixtures", "encryption_keys_fixtures.yml")),
			}

			renderingContext := NewRenderingContext(templates...)

			encryptionKeys := `encryption:
  active_key_label: CHANGED-KEY
  encryption_keys:
  - label: CHANGED-KEY
    passphrase: NEVERGONNAGUESS
`

			Expect(renderingContext).To(
				ProduceYAML(RepresentingASecret().
					WithName("encryption-keys").
					WithStringData("encryption_keys.yml", encryptionKeys)))
		})

		It("Requires an active_key_label entry", func() {
			templates = []string{
				pathToFile(filepath.Join("values", "_values.yml")),
				pathToFile(filepath.Join("secrets", "encryption_keys.yml")),
				pathToFile(filepath.Join("secrets", "encryption_keys.star")),
				pathToFile(filepath.Join("..", "test_fixtures", "encryption_keys_fixtures_no_active_key.yml")),
			}

			renderingContext := NewRenderingContext(templates...)

			Expect(renderingContext).To(
				ThrowError("fail: encryption.active_key_label is required"))
		})

		It("Requires a nonempty active_key_label entry", func() {
			templates = []string{
				pathToFile(filepath.Join("values", "_values.yml")),
				pathToFile(filepath.Join("secrets", "encryption_keys.yml")),
				pathToFile(filepath.Join("secrets", "encryption_keys.star")),
				pathToFile(filepath.Join("..", "test_fixtures", "encryption_keys_fixtures_empty_key.yml")),
			}

			renderingContext := NewRenderingContext(templates...)

			Expect(renderingContext).To(
				ThrowError("fail: encryption.active_key_label is required"))
		})

		It("active_key_label must be found in the list of keys", func() {
			templates = []string{
				pathToFile(filepath.Join("values", "_values.yml")),
				pathToFile(filepath.Join("secrets", "encryption_keys.yml")),
				pathToFile(filepath.Join("secrets", "encryption_keys.star")),
				pathToFile(filepath.Join("..", "test_fixtures", "encryption_keys_invalid_key_fixtures.yml")),
			}

			renderingContext := NewRenderingContext(templates...)

			Expect(renderingContext).To(
				ThrowError("fail: encryption.active_key_label must reference key in encryption.encryption_keys"),
			)
		})
	})
})
