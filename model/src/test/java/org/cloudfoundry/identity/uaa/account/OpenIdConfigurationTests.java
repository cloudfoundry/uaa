package org.cloudfoundry.identity.uaa.account;

import com.fasterxml.jackson.core.JsonProcessingException;
import org.cloudfoundry.identity.uaa.test.JsonTranslation;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.test.util.ReflectionTestUtils;

import java.lang.reflect.Field;

import static org.cloudfoundry.identity.uaa.test.JsonMatcher.isJsonFile;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.jupiter.api.Assertions.*;

class OpenIdConfigurationTests extends JsonTranslation<OpenIdConfiguration> {

    @BeforeEach
    void setup() {
        OpenIdConfiguration subject = new OpenIdConfiguration("<context path>", "<issuer>");

        super.setUp(subject, OpenIdConfiguration.class, WithAllNullFields.DONT_CHECK);
    }

    @Test
    void defaultClaims() {
        OpenIdConfiguration defaultConfig = new OpenIdConfiguration("/uaa", "issuer");

        assertEquals("issuer", defaultConfig.getIssuer());
        assertEquals("/uaa/oauth/authorize", defaultConfig.getAuthUrl());
        assertEquals("/uaa/oauth/token", defaultConfig.getTokenUrl());
        assertArrayEquals(new String[]{"client_secret_basic", "client_secret_post"}, defaultConfig.getTokenAMR());
        assertArrayEquals(new String[]{"RS256", "HS256"}, defaultConfig.getTokenEndpointAuthSigningValues());
        assertEquals("/uaa/userinfo", defaultConfig.getUserInfoUrl());
        assertEquals("/uaa/token_keys", defaultConfig.getJwksUri());
        assertArrayEquals(new String[]{"openid", "profile", "email", "phone", "roles", "user_attributes"}, defaultConfig.getScopes());
        assertArrayEquals(new String[]{"code", "code id_token", "id_token", "token id_token"}, defaultConfig.getResponseTypes());
        assertArrayEquals(new String[]{"public"}, defaultConfig.getSubjectTypesSupported());
        assertArrayEquals(new String[]{"RS256", "HS256"}, defaultConfig.getIdTokenSigningAlgValues());
        assertArrayEquals(new String[]{"none"}, defaultConfig.getRequestObjectSigningAlgValues());
        assertArrayEquals(new String[]{"normal"}, defaultConfig.getClaimTypesSupported());
        assertArrayEquals(
                new String[]{
                        "sub", "user_name", "origin", "iss", "auth_time",
                        "amr", "acr", "client_id", "aud", "zid", "grant_type",
                        "user_id", "azp", "scope", "exp", "iat", "jti", "rev_sig",
                        "cid", "given_name", "family_name", "phone_number", "email"},
                defaultConfig.getClaimsSupported()
        );
        assertFalse(defaultConfig.isClaimsParameterSupported());
        assertEquals("http://docs.cloudfoundry.org/api/uaa/", defaultConfig.getServiceDocumentation());
        assertArrayEquals(new String[]{"en-US"}, defaultConfig.getUiLocalesSupported());
        assertArrayEquals(new String[]{"S256", "plain"}, defaultConfig.getCodeChallengeMethodsSupported());
    }

    @Test
    void allNulls() throws JsonProcessingException {
        OpenIdConfiguration openIdConfiguration = new OpenIdConfiguration(null, null);

        for (Field field : OpenIdConfiguration.class.getDeclaredFields()) {
            if (boolean.class.equals(field.getType())) {
                ReflectionTestUtils.setField(openIdConfiguration, field.getName(), false);
                continue;
            }
            ReflectionTestUtils.setField(openIdConfiguration, field.getName(), null);
        }

        String actual = getObjectMapper().writeValueAsString(openIdConfiguration);

        assertThat(actual, isJsonFile(this.getClass(), "OpenIdConfiguration-nulls.json"));

    }
}
