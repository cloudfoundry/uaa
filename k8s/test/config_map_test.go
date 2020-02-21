package k8s_test

import (
	. "github.com/cloudfoundry/uaa/matchers"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	. "github.com/onsi/gomega/gstruct"

	"path/filepath"
)

const UaaYmlConfigKey = "uaa.yml"
const Log4j2PropertiesKey = "log4j2.properties"

var _ = Describe("Uaa ConfigMap", func() {
	var templates []string
	var database Database

	BeforeEach(func() {
		templates = []string{
			pathToFile("config.yml"),
			pathToFile("uaa.lib.yml"),
			pathToFile("uaa.lib.star"),
			pathToFile(filepath.Join("values", "_values.yml")),
			pathToFile("log4j2.properties"),
		}

		database = Database{
			Username: "sa",
			Password: "password",
			Url:      "jdbc:hsqldb:mem:uaa",
		}
	})

	Context("Renders a config map", func() {
		Context("with default values", func() {
			It("produces yml", func() {
				ctx := NewRenderingContext(templates...)

				Expect(ctx).To(
					ProduceYAML(
						RepresentingConfigMap().WithDataFieldMatching(UaaYmlConfigKey, func(uaaYml *DataFieldMatcher) {
							//							signingKey :=
							//								`-----BEGIN RSA PRIVATE KEY-----
							//MIICXgIBAAKBgQDfTLadf6QgJeS2XXImEHMsa+1O7MmIt44xaL77N2K+J/JGpfV3
							//AnkyB06wFZ02sBLB7hko42LIsVEOyTuUBird/3vlyHFKytG7UEt60Fl88SbAEfsU
							//JN1i1aSUlunPS/NCz+BKwwKFP9Ss3rNImE9Uc2LMvGy153LHFVW2zrjhTwIDAQAB
							//AoGBAJDh21LRcJITRBQ3CUs9PR1DYZPl+tUkE7RnPBMPWpf6ny3LnDp9dllJeHqz
							//a3ACSgleDSEEeCGzOt6XHnrqjYCKa42Z+Opnjx/OOpjyX1NAaswRtnb039jwv4gb
							//RlwT49Y17UAQpISOo7JFadCBoMG0ix8xr4ScY+zCSoG5v0BhAkEA8llNsiWBJF5r
							//LWQ6uimfdU2y1IPlkcGAvjekYDkdkHiRie725Dn4qRiXyABeaqNm2bpnD620Okwr
							//sf7LY+BMdwJBAOvgt/ZGwJrMOe/cHhbujtjBK/1CumJ4n2r5V1zPBFfLNXiKnpJ6
							//J/sRwmjgg4u3Anu1ENF3YsxYabflBnvOP+kCQCQ8VBCp6OhOMcpErT8+j/gTGQUL
							//f5zOiPhoC2zTvWbnkCNGlqXDQTnPUop1+6gILI2rgFNozoTU9MeVaEXTuLsCQQDC
							//AGuNpReYucwVGYet+LuITyjs/krp3qfPhhByhtndk4cBA5H0i4ACodKyC6Zl7Tmf
							//oYaZoYWi6DzbQQUaIsKxAkEA2rXQjQFsfnSm+w/9067ChWg46p4lq5Na2NpcpFgH
							//waZKhM1W0oB8MX78M+0fG3xGUtywTx0D4N7pr1Tk2GTgNw==
							//-----END RSA PRIVATE KEY-----
							//`

							//jwt := Jwt{
							//	Token: JwtToken{
							//		Policy: JwtTokenPolicy{
							//			ActiveKeyId: "sample_private_key_DO_NOT_USE",
							//			Keys: map[string]JwtTokenPolicySigningKey{
							//				"sample_private_key_DO_NOT_USE": {SigningKey: signingKey},
							//			},
							//		},
							//	},
							//}

							uaaYml.WithFields(Fields{
								"LoginSecret": Equal("loginsecret"),
								"Issuer":      Equal(Issuer{Uri: "http://localhost:8080/uaa"}),
								"Database": MatchFields(IgnoreExtras, Fields{
									"Username": Equal(database.Username),
									"Password": Equal(database.Password),
									"Url":      Equal(database.Url),
								}),
								//"Jwt": Equal(jwt),
							})
						}),
					))

				Expect(ctx).To(
					ProduceYAML(
						RepresentingConfigMap().WithDataValueMatching(Log4j2PropertiesKey, func(log4jMatcher *DataValueMatcher) {
							properties := `status = error
dest = err
name = UaaLog

property.log_pattern=[%d{yyyy-MM-dd HH:mm:ss.SSS}] uaa%X{context} - %pid [%t] .... %5p --- %c{1}: %replace{%m}{(?<=password=|client_secret=)([^&]*)}{<redacted>}%n

appender.uaaDefaultAppender.type = Console
appender.uaaDefaultAppender.name = UaaDefaultAppender
appender.uaaDefaultAppender.layout.type = PatternLayout
appender.uaaDefaultAppender.layout.pattern = [UAA] ${log_pattern}

appender.uaaAuditAppender.type = Console
appender.uaaAuditAppender.name = UaaAuditAppender
appender.uaaAuditAppender.layout.type = PatternLayout
appender.uaaAuditAppender.layout.pattern = [UAA_AUDIT] ${log_pattern}

rootLogger.level = info
rootLogger.appenderRef.uaaDefaultAppender.ref = UaaDefaultAppender

logger.UAAAudit.name = UAA.Audit
logger.UAAAudit.level = info
logger.UAAAudit.additivity = true
logger.UAAAudit.appenderRef.auditEventLog.ref = UaaAuditAppender

logger.cfIdentity.name = org.cloudfoundry.identity
logger.cfIdentity.level = info
logger.cfIdentity.additivity = false
logger.cfIdentity.appenderRef.uaaDefaultAppender.ref = UaaDefaultAppender`
							log4jMatcher.WithValue(properties)
						}),
					))
			})

			It("Renders common labels for the deployment", func() {
				templates = append(templates, pathToFile("metadata.yml"))
				ctx := NewRenderingContext(templates...).WithData(map[string]string{
					"version": "some version",
				})

				labels := map[string]string{
					"app.kubernetes.io/name":       "uaa",
					"app.kubernetes.io/instance":   "uaa-standalone",
					"app.kubernetes.io/version":    "some version",
					"app.kubernetes.io/component":  "authorization_server",
					"app.kubernetes.io/part-of":    "uaa",
					"app.kubernetes.io/managed-by": "kubectl",
				}
				Expect(ctx).To(
					ProduceYAML(RepresentingConfigMap().WithLabels(labels).WithNamespace("default")),
				)
			})
		})
		Context("with overriden values", func() {
			It("produces yaml", func() {
				database.Username = "database-username"
				database.Password = "database-password"
				database.Url = "jdbc:postgres://127.0.0.1:9000/database-name"

				ctx := NewRenderingContext(templates...).WithData(map[string]string{
					"database.username": database.Username,
					"database.password": database.Password,
					"database.scheme":   "postgres",
					"database.address":  "127.0.0.1",
					"database.port":     "9000",
					"database.name":     "database-name",
				})

				Expect(ctx).To(
					ProduceYAML(
						RepresentingConfigMap().WithDataFieldMatching(UaaYmlConfigKey, func(uaaYml *DataFieldMatcher) {
							uaaYml.WithFields(Fields{
								"LoginSecret": Equal("loginsecret"),
								"Issuer":      Equal(Issuer{Uri: "http://localhost:8080/uaa"}),
								"Database": MatchFields(IgnoreExtras, Fields{
									"Username": Equal(database.Username),
									"Password": Equal(database.Password),
									"Url":      Equal(database.Url),
								}),
							})
						}),
					))
			})

			Context("with postgres database", func() {

				It("renders database connection string", func() {
					database.Url = "jdbc:postgresql://127.0.0.1:9000/database-name?sslmode=disable"

					ctx := NewRenderingContext(templates...).WithData(map[string]string{
						"database.scheme":  "postgresql",
						"database.address": "127.0.0.1",
						"database.port":    "9000",
						"database.name":    "database-name",
					})

					Expect(ctx).To(
						ProduceYAML(
							RepresentingConfigMap().WithDataFieldMatching(UaaYmlConfigKey, func(uaaYml *DataFieldMatcher) {
								uaaYml.WithFields(Fields{
									"Database": MatchFields(IgnoreExtras, Fields{
										"Url": Equal(database.Url),
									}),
								})
							}),
						))
				})
			})

			Context("with mysql database", func() {
				It("renders database connection string", func() {
					database.Url = "jdbc:mysql://127.0.0.1:9000/database-name?useSSL=false"

					ctx := NewRenderingContext(templates...).WithData(map[string]string{
						"database.scheme":  "mysql",
						"database.address": "127.0.0.1",
						"database.port":    "9000",
						"database.name":    "database-name",
					})

					Expect(ctx).To(
						ProduceYAML(
							RepresentingConfigMap().WithDataFieldMatching(UaaYmlConfigKey, func(uaaYml *DataFieldMatcher) {
								uaaYml.WithFields(Fields{
									"Database": MatchFields(IgnoreExtras, Fields{
										"Url": Equal(database.Url),
									}),
								})
							}),
						))
				})
			})

			Context("with hsql database", func() {
				It("renders database connection string", func() {
					database.Url = "jdbc:hsqldb:mem:uaa"

					ctx := NewRenderingContext(templates...).WithData(map[string]string{"database.scheme": "hsqldb"})

					Expect(ctx).To(
						ProduceYAML(
							RepresentingConfigMap().WithDataFieldMatching(UaaYmlConfigKey, func(uaaYml *DataFieldMatcher) {
								uaaYml.WithFields(Fields{
									"Database": MatchFields(IgnoreExtras, Fields{
										"Url": Equal(database.Url),
									}),
								})
							}),
						))
				})
			})
		})
	})
})
