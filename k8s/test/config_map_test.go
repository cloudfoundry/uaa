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

	BeforeEach(func() {
		templates = []string{
			pathToFile("config.yml"),
			pathToFile("uaa.lib.yml"),
			pathToFile(filepath.Join("values", "_values.yml")),
			pathToFile("log4j2.properties"),
		}
	})

	Context("Renders a config map", func() {
		Context("with default values", func() {
			It("produces yml", func() {
				ctx := NewRenderingContext(templates...).WithData(map[string]string{
					"database.scheme": "hsqldb",
					"database.url":    "any database url",
				})

				Expect(ctx).To(
					ProduceYAML(
						RepresentingConfigMap().WithDataFieldMatching(UaaYmlConfigKey, func(uaaYml *DataFieldMatcher) {
							uaaYml.WithFields(Fields{
								"LoginSecret": Equal("loginsecret"),
								"Issuer":      Equal(Issuer{Uri: "http://localhost:8080/uaa"}),
								"Database": MatchFields(IgnoreExtras, Fields{
									"Username": BeEmpty(),
									"Password": BeEmpty(),
									"Url":      Equal("any database url"),
								}),
								"Smtp": MatchFields(IgnoreExtras, Fields{
									"Host":        BeEmpty(),
									"Port":        Equal("25"),
									"Starttls":    BeEmpty(),
									"FromAddress": BeEmpty(),
								}),
								"Oauth": MatchFields(0, Fields{
									"Client": MatchFields(0, Fields{
										"Override": Equal(true),
									}),
									"Clients": MatchFields(0, Fields{
										"Admin": MatchFields(0, Fields{
											"AuthorizedGrantTypes": Equal("client_credentials"),
											"Authorities":          Equal("clients.read,clients.write,clients.secret,uaa.admin,scim.read,scim.write,password.write"),
										}),
									}),
								}),
							})
						}),
					))

				Expect(ctx).To(
					ProduceYAML(
						RepresentingConfigMap().WithDataValueMatching(Log4j2PropertiesKey, func(log4jMatcher *DataValueMatcher) {
							properties := `status = error
dest = err
name = UaaLog

property.log_pattern=[%d{yyyy-MM-dd'T'HH:mm:ss.nnnnnn}{GMT+0}Z] uaa%X{context} - %pid [%t] .... %5p --- %c{1}: %replace{%m}{(?<=password=|client_secret=)([^&]*)}{<redacted>}%n

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
					"version":         "some version",
					"database.scheme": "hsqldb",
					"database.url":    "anything",
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
		Context("with overridden values", func() {
			It("produces yaml", func() {
				ctx := NewRenderingContext(templates...).WithData(map[string]string{
					"database.scheme":   "postgres",
					"database.url":      "any other database connection string",
					"smtp.host":         "smtp host",
					"smtp.port":         "smtp port",
					"smtp.starttls":     "smtp starttls",
					"smtp.from_address": "smtp from_address",
					"smtp.sslprotocols": "smtp sslprotocols",
					"issuer.uri":        "http://some.example.com/with/path",
				})

				Expect(ctx).To(
					ProduceYAML(
						RepresentingConfigMap().WithDataFieldMatching(UaaYmlConfigKey, func(uaaYml *DataFieldMatcher) {
							uaaYml.WithFields(Fields{
								"LoginSecret": Equal("loginsecret"),
								"Issuer":      Equal(Issuer{Uri: "http://some.example.com/with/path"}),
								"Database": MatchFields(IgnoreExtras, Fields{
									"Username": BeEmpty(),
									"Password": BeEmpty(),
									"Url":      Equal("any other database connection string"),
								}),
								"Smtp": MatchFields(IgnoreExtras, Fields{
									"Host":         Equal("smtp host"),
									"Port":         Equal("smtp port"),
									"Starttls":     Equal("smtp starttls"),
									"Sslprotocols": Equal("smtp sslprotocols"),
									"FromAddress":  Equal("smtp from_address"),
								}),
							})
						}),
					))
			})

			Context("with any database type", func() {

				It("renders database url", func() {
					databaseUrl := "jdbc:any-database-type://any-url:any-ip/any-database-name?any=params"

					ctx := NewRenderingContext(templates...).WithData(map[string]string{
						"database.scheme": "postgresql",
						"database.url":    databaseUrl,
					})

					Expect(ctx).To(
						ProduceYAML(
							RepresentingConfigMap().WithDataFieldMatching(UaaYmlConfigKey, func(uaaYml *DataFieldMatcher) {
								uaaYml.WithFields(Fields{
									"Database": MatchFields(IgnoreExtras, Fields{
										"Url": Equal(databaseUrl),
									}),
								})
							}),
						))
				})
			})

			Context("with mysql database", func() {
				It("renders database connection string", func() {
					databaseUrl := "jdbc:mysql://127.0.0.1:9000/database-name?useSSL=false"

					ctx := NewRenderingContext(templates...).WithData(map[string]string{
						"database.scheme": "mysql",
						"database.url":    databaseUrl,
					})

					Expect(ctx).To(
						ProduceYAML(
							RepresentingConfigMap().WithDataFieldMatching(UaaYmlConfigKey, func(uaaYml *DataFieldMatcher) {
								uaaYml.WithFields(Fields{
									"Database": MatchFields(IgnoreExtras, Fields{
										"Url": Equal(databaseUrl),
									}),
								})
							}),
						))
				})
			})

			It("fails without database.url", func() {
				ctx := NewRenderingContext(templates...)

				Expect(ctx).To(
					ThrowError("database.url is required"),
				)
			})
		})
	})
})
