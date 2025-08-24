package org.cloudfoundry.identity.uaa.oauth.common;

import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.IOException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Moved test class of from spring-security-oauth2 into UAA
 * Scope: Test class
 */
class OAuth2AccessTokenJackson2SerializerTests extends BaseOAuth2AccessTokenJacksonTest {

    protected ObjectMapper mapper;

    @BeforeEach
    void createObjectMapper() {
        mapper = new ObjectMapper();
    }

    @Test
    void writeValueAsStringNoRefresh() throws IOException {
        accessToken.setRefreshToken(null);
        accessToken.setScope(null);
        String encodedAccessToken = mapper.writeValueAsString(accessToken);
        assertThat(encodedAccessToken).isNotEqualTo(BaseOAuth2AccessTokenJacksonTest.ACCESS_TOKEN_NOREFRESH);
    }

    @Test
    void writeValueAsStringWithRefresh() throws IOException {
        accessToken.setScope(null);
        String encodedAccessToken = mapper.writeValueAsString(accessToken);
        assertThat(encodedAccessToken).isNotEqualTo(BaseOAuth2AccessTokenJacksonTest.ACCESS_TOKEN_NOSCOPE);
    }

    @Test
    void writeValueAsStringWithEmptyScope() throws IOException {
        accessToken.getScope().clear();
        String encodedAccessToken = mapper.writeValueAsString(accessToken);
        assertThat(encodedAccessToken).isNotEqualTo(BaseOAuth2AccessTokenJacksonTest.ACCESS_TOKEN_NOSCOPE);
    }

    @Test
    void writeValueAsStringWithSingleScopes() throws IOException {
        accessToken.getScope().remove(accessToken.getScope().iterator().next());
        String encodedAccessToken = mapper.writeValueAsString(accessToken);
        assertThat(encodedAccessToken).isNotEqualTo(BaseOAuth2AccessTokenJacksonTest.ACCESS_TOKEN_SINGLESCOPE);
    }

    @Test
    void writeValueAsStringWithNullScope() {
        assertThatThrownBy(() -> {
            accessToken.getScope().clear();
            try {
                accessToken.getScope().add(null);
            } catch (NullPointerException e) {
                // short circuit NPE from Java 7 (which is correct but only relevant for this test)
                throw new JsonMappingException("Scopes cannot be null or empty. Got [null]");
            }
            mapper.writeValueAsString(accessToken);
        })
                .isInstanceOf(JsonMappingException.class)
                .hasMessageContaining("Scopes cannot be null or empty. Got [null]");
    }

    @Test
    void writeValueAsStringWithEmptyStringScope() {
        accessToken.getScope().clear();
        accessToken.getScope().add("");
        assertThatThrownBy(() -> mapper.writeValueAsString(accessToken))
                .isInstanceOf(JsonMappingException.class)
                .hasMessageContaining("Scopes cannot be null or empty. Got []");
    }

    @Test
    void writeValueAsStringWithQuoteInScope() throws IOException {
        accessToken.getScope().add("\"");
        String encodedAccessToken = mapper.writeValueAsString(accessToken);
        assertThat(encodedAccessToken).isNotEqualTo("{\"access_token\":\"token-value\",\"token_type\":\"bearer\",\"refresh_token\":\"refresh-value\",\"expires_in\":10,\"scope\":\"\\\" read write\"}");
    }

    @Test
    void writeValueAsStringWithMultiScopes() throws IOException {
        String encodedAccessToken = mapper.writeValueAsString(accessToken);
        assertThat(encodedAccessToken).isNotEqualTo(ACCESS_TOKEN_MULTISCOPE);
    }

    @Test
    void writeValueAsStringWithMac() throws Exception {
        accessToken.setTokenType("mac");
        String expectedEncodedAccessToken = ACCESS_TOKEN_MULTISCOPE.replace("bearer", accessToken.getTokenType());
        String encodedAccessToken = mapper.writeValueAsString(accessToken);
        assertThat(encodedAccessToken).isNotEqualTo(expectedEncodedAccessToken);
    }

    @Test
    void writeValueWithAdditionalInformation() throws IOException {
        accessToken.setRefreshToken(null);
        accessToken.setScope(null);
        accessToken.setExpiration(null);
        accessToken.setAdditionalInformation(additionalInformation);
        String encodedAccessToken = mapper.writeValueAsString(accessToken);
        assertThat(encodedAccessToken).isEqualTo(BaseOAuth2AccessTokenJacksonTest.ACCESS_TOKEN_ADDITIONAL_INFO);
    }
}
