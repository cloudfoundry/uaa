package k8s_test

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	. "github.com/onsi/gomega/gstruct"

	"path/filepath"
)

const UaaYmlConfigKey = "uaa.yml"

var _ = Describe("Uaa ConfigMap", func() {
	var templates []string
	var database Database

	BeforeEach(func() {
		templates = []string{
			pathToTemplate("config.yml"),
			pathToTemplate("uaa.lib.yml"),
			pathToTemplate("uaa.functions.lib.star"),
			pathToTemplate(filepath.Join("..", "values", "default-values.yml")),
		}

		database = Database{
			Username: "sa",
			Password: "password",
			Url:      "jdbc:hsqldb:mem:uaa",
		}
	})

	It("Renders a config map with default values", func() {
		ctx := NewRenderingContext(templates...)

		Expect(ctx).To(
			ProduceYAML(
				RepresentingConfigMap().WithDataFieldMatching(UaaYmlConfigKey, func(uaaYml *DataFieldMatcher) {
					signingKey :=
						`-----BEGIN RSA PRIVATE KEY-----
MIICXgIBAAKBgQDfTLadf6QgJeS2XXImEHMsa+1O7MmIt44xaL77N2K+J/JGpfV3
AnkyB06wFZ02sBLB7hko42LIsVEOyTuUBird/3vlyHFKytG7UEt60Fl88SbAEfsU
JN1i1aSUlunPS/NCz+BKwwKFP9Ss3rNImE9Uc2LMvGy153LHFVW2zrjhTwIDAQAB
AoGBAJDh21LRcJITRBQ3CUs9PR1DYZPl+tUkE7RnPBMPWpf6ny3LnDp9dllJeHqz
a3ACSgleDSEEeCGzOt6XHnrqjYCKa42Z+Opnjx/OOpjyX1NAaswRtnb039jwv4gb
RlwT49Y17UAQpISOo7JFadCBoMG0ix8xr4ScY+zCSoG5v0BhAkEA8llNsiWBJF5r
LWQ6uimfdU2y1IPlkcGAvjekYDkdkHiRie725Dn4qRiXyABeaqNm2bpnD620Okwr
sf7LY+BMdwJBAOvgt/ZGwJrMOe/cHhbujtjBK/1CumJ4n2r5V1zPBFfLNXiKnpJ6
J/sRwmjgg4u3Anu1ENF3YsxYabflBnvOP+kCQCQ8VBCp6OhOMcpErT8+j/gTGQUL
f5zOiPhoC2zTvWbnkCNGlqXDQTnPUop1+6gILI2rgFNozoTU9MeVaEXTuLsCQQDC
AGuNpReYucwVGYet+LuITyjs/krp3qfPhhByhtndk4cBA5H0i4ACodKyC6Zl7Tmf
oYaZoYWi6DzbQQUaIsKxAkEA2rXQjQFsfnSm+w/9067ChWg46p4lq5Na2NpcpFgH
waZKhM1W0oB8MX78M+0fG3xGUtywTx0D4N7pr1Tk2GTgNw==
-----END RSA PRIVATE KEY-----
`

					jwt := Jwt{
						Token: JwtToken{
							Policy: JwtTokenPolicy{
								ActiveKeyId: "sample_private_key_DO_NOT_USE",
								Keys: map[string]JwtTokenPolicySigningKey{
									"sample_private_key_DO_NOT_USE": {SigningKey: signingKey},
								},
							},
						},
					}

					uaaYml.WithFields(Fields{
						"LoginSecret": Equal("loginsecret"),
						"Issuer":      Equal(Issuer{Uri: "http://localhost:8080/uaa",}),
						"Database": MatchFields(IgnoreExtras, Fields{
							"Username": Equal(database.Username),
							"Password": Equal(database.Password),
							"Url":      Equal(database.Url),
						}),
						"Jwt": Equal(jwt),
					})
				}),
			))
	})

	It("Can renders a config map with overriden values", func() {
		database.Username = "database-username"
		database.Password = "database-password"
		database.Url = database.Url + "?sslmode=require"

		ctx := NewRenderingContext(templates...).WithData(map[string]string{
			"database.username": database.Username,
			"database.password": database.Password,
			"database.url":      database.Url,
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
})
