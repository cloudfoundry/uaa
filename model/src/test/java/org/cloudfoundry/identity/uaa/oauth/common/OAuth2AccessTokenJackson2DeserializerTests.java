package org.cloudfoundry.identity.uaa.oauth.common;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.util.Date;
import java.util.HashSet;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Moved test class of from spring-security-oauth2 into UAA
 * Scope: Test class
 */
class OAuth2AccessTokenJackson2DeserializerTests extends BaseOAuth2AccessTokenJacksonTest {

    protected ObjectMapper mapper;

    @BeforeEach
    void createObjectMapper() {
        mapper = new ObjectMapper();
    }

    @Test
    void readValueNoRefresh() throws IOException {
        accessToken.setRefreshToken(null);
        accessToken.setScope(null);
        OAuth2AccessToken actual = mapper.readValue(ACCESS_TOKEN_NOREFRESH, OAuth2AccessToken.class);
        assertTokenEquals(accessToken, actual);
    }

    @Test
    void readValueWithRefresh() throws IOException {
        accessToken.setScope(null);
        OAuth2AccessToken actual = mapper.readValue(ACCESS_TOKEN_NOSCOPE, OAuth2AccessToken.class);
        assertTokenEquals(accessToken, actual);
    }

    @Test
    void readValueWithSingleScopes() throws IOException {
        accessToken.getScope().remove(accessToken.getScope().iterator().next());
        OAuth2AccessToken actual = mapper.readValue(ACCESS_TOKEN_SINGLESCOPE, OAuth2AccessToken.class);
        assertTokenEquals(accessToken, actual);
    }

    @Test
    void readValueWithEmptyStringScope() throws IOException {
        accessToken.setScope(new HashSet<>());
        OAuth2AccessToken actual = mapper.readValue(ACCESS_TOKEN_EMPTYSCOPE, OAuth2AccessToken.class);
        assertTokenEquals(accessToken, actual);
    }

    @Test
    void readValueWithBrokenExpiresIn() throws IOException {
        accessToken.setScope(new HashSet<>());
        OAuth2AccessToken actual = mapper.readValue(ACCESS_TOKEN_BROKENEXPIRES, OAuth2AccessToken.class);
        assertTokenEquals(accessToken, actual);
    }

    @Test
    void readValueWithMultiScopes() throws Exception {
        OAuth2AccessToken actual = mapper.readValue(ACCESS_TOKEN_MULTISCOPE, OAuth2AccessToken.class);
        assertTokenEquals(accessToken, actual);
    }

    @Test
    void readValueWithArrayScopes() throws Exception {
        OAuth2AccessToken actual = mapper.readValue(ACCESS_TOKEN_ARRAYSCOPE, OAuth2AccessToken.class);
        assertTokenEquals(accessToken, actual);
    }

    @Test
    void readValueWithMac() throws Exception {
        accessToken.setTokenType("mac");
        String encodedToken = ACCESS_TOKEN_MULTISCOPE.replace("bearer", accessToken.getTokenType());
        OAuth2AccessToken actual = mapper.readValue(encodedToken, OAuth2AccessToken.class);
        assertTokenEquals(accessToken, actual);
    }

    @Test
    void readValueWithAdditionalInformation() throws Exception {
        OAuth2AccessToken actual = mapper.readValue(ACCESS_TOKEN_ADDITIONAL_INFO, OAuth2AccessToken.class);
        accessToken.setAdditionalInformation(additionalInformation);
        accessToken.setRefreshToken(null);
        accessToken.setScope(null);
        accessToken.setExpiration(null);
        assertTokenEquals(accessToken, actual);
    }

    @Test
    void readValueWithZeroExpiresAsNotExpired() throws Exception {
        OAuth2AccessToken actual = mapper.readValue(ACCESS_TOKEN_ZERO_EXPIRES, OAuth2AccessToken.class);
        assertThat(actual.isExpired()).as("Token with expires_in:0 must be treated as not expired.").isFalse();
    }

    private static void assertTokenEquals(OAuth2AccessToken expected, OAuth2AccessToken actual) {
        assertThat(actual.getTokenType()).isEqualTo(expected.getTokenType());
        assertThat(actual.getValue()).isEqualTo(expected.getValue());

        OAuth2RefreshToken expectedRefreshToken = expected.getRefreshToken();
        if (expectedRefreshToken == null) {
            assertThat(actual.getRefreshToken()).isNull();
        } else {
            assertThat(actual.getRefreshToken().getValue()).isEqualTo(expectedRefreshToken.getValue());
        }
        assertThat(actual.getScope()).isEqualTo(expected.getScope());
        Date expectedExpiration = expected.getExpiration();
        if (expectedExpiration == null) {
            assertThat(actual.getExpiration()).isNull();
        }
        assertThat(actual.getAdditionalInformation()).isEqualTo(expected.getAdditionalInformation());
    }
}
