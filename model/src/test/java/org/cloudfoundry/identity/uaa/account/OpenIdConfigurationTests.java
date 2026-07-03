package org.cloudfoundry.identity.uaa.account;

import org.cloudfoundry.identity.uaa.test.JsonTranslation;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.json.BasicJsonTester;
import org.springframework.test.util.ReflectionTestUtils;

import java.lang.reflect.Field;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class OpenIdConfigurationTests extends JsonTranslation<OpenIdConfiguration> {
    private final BasicJsonTester json = new BasicJsonTester(getClass());

    @BeforeEach
    void setup() {
        OpenIdConfiguration subject = new OpenIdConfiguration("<context path>", "<issuer>");

        super.setUp(subject, OpenIdConfiguration.class, WithAllNullFields.DONT_CHECK);
    }

    @Test
    void defaultClaims() {
        OpenIdConfiguration defaultConfig = new OpenIdConfiguration("/uaa", "issuer");

        assertThat(defaultConfig.getIssuer()).isEqualTo("issuer");
        assertThat(defaultConfig.getAuthUrl()).isEqualTo("/uaa/oauth/authorize");
        assertThat(defaultConfig.getTokenUrl()).isEqualTo("/uaa/oauth/token");
        assertThat(defaultConfig.getTokenAMR()).containsExactly(new String[]{"client_secret_basic", "client_secret_post", "private_key_jwt", "tls_client_auth"});
        assertThat(defaultConfig.getTokenEndpointAuthSigningValues()).containsExactly(new String[]{"RS256", "HS256"});
        assertThat(defaultConfig.getUserInfoUrl()).isEqualTo("/uaa/userinfo");
        assertThat(defaultConfig.getJwksUri()).isEqualTo("/uaa/token_keys");
        assertThat(defaultConfig.getLogoutEndpoint()).isEqualTo("/uaa/logout.do");
        assertThat(defaultConfig.getScopes()).containsExactly(new String[]{"openid", "profile", "email", "phone", "roles", "user_attributes"});
        assertThat(defaultConfig.getResponseTypes()).containsExactly(new String[]{"code", "code id_token", "id_token", "token id_token"});
        assertThat(defaultConfig.getSubjectTypesSupported()).containsExactly(new String[]{"public"});
        assertThat(defaultConfig.getIdTokenSigningAlgValues()).containsExactly(new String[]{"RS256", "HS256"});
        assertThat(defaultConfig.getRequestObjectSigningAlgValues()).containsExactly(new String[]{"none"});
        assertThat(defaultConfig.getClaimTypesSupported()).containsExactly(new String[]{"normal"});
        assertThat(defaultConfig.getClaimsSupported()).containsExactly(new String[]{
                "sub", "user_name", "origin", "iss", "auth_time",
                "amr", "acr", "client_id", "aud", "zid", "grant_type",
                "user_id", "azp", "scope", "exp", "iat", "jti", "rev_sig",
                "cid", "given_name", "family_name", "phone_number", "email"});
        assertThat(defaultConfig.isClaimsParameterSupported()).isFalse();
        assertThat(defaultConfig.getServiceDocumentation()).isEqualTo("http://docs.cloudfoundry.org/api/uaa/");
        assertThat(defaultConfig.getUiLocalesSupported()).containsExactly(new String[]{"en-US"});
        assertThat(defaultConfig.getCodeChallengeMethodsSupported()).containsExactly(new String[]{"S256", "plain"});
    }

    @Test
    void allNulls() throws Exception {
        OpenIdConfiguration openIdConfiguration = new OpenIdConfiguration(null, null);

        for (Field field : OpenIdConfiguration.class.getDeclaredFields()) {
            if (boolean.class.equals(field.getType())) {
                ReflectionTestUtils.setField(openIdConfiguration, field.getName(), false);
                continue;
            }
            ReflectionTestUtils.setField(openIdConfiguration, field.getName(), null);
        }
        getObjectMapper().writeValueAsString(openIdConfiguration);

        assertThat(json.from("OpenIdConfiguration-nulls.json", this.getClass()))
                .hasEmptyJsonPathValue("issuer");
    }

    @Test
    void mtlsEndpointAliasesIsNullByDefault() {
        OpenIdConfiguration conf = new OpenIdConfiguration("/uaa", "https://uaa.example.com");
        assertThat(conf.getMtlsEndpointAliases()).isNull();
    }

    @Test
    void mtlsEndpointAliasesCanBeSet() {
        OpenIdConfiguration conf = new OpenIdConfiguration("/uaa", "https://uaa.example.com");
        conf.setMtlsEndpointAliases(Map.of("token_endpoint", "https://uaa.example.com/oauth/mtls/token"));
        assertThat(conf.getMtlsEndpointAliases())
                .containsEntry("token_endpoint", "https://uaa.example.com/oauth/mtls/token");
    }

    @Test
    void tlsClientAuthIsInSupportedAuthMethods() {
        OpenIdConfiguration conf = new OpenIdConfiguration("/uaa", "https://uaa.example.com");
        assertThat(conf.getTokenAMR()).contains("tls_client_auth");
    }

    @Test
    void tlsClientAuthIsExcludedWhenMtlsDisabled() {
        OpenIdConfiguration conf = new OpenIdConfiguration("/uaa", "https://uaa.example.com", false);
        assertThat(conf.getTokenAMR())
                .containsExactlyInAnyOrder("client_secret_basic", "client_secret_post", "private_key_jwt")
                .doesNotContain("tls_client_auth");
    }

    @Test
    void tlsClientAuthIsIncludedWhenMtlsEnabled() {
        OpenIdConfiguration conf = new OpenIdConfiguration("/uaa", "https://uaa.example.com", true);
        assertThat(conf.getTokenAMR())
                .containsExactlyInAnyOrder("client_secret_basic", "client_secret_post", "private_key_jwt", "tls_client_auth");
    }
}
