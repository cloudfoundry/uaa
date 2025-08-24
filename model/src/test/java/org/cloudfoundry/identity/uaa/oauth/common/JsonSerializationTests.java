package org.cloudfoundry.identity.uaa.oauth.common;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.cloudfoundry.identity.uaa.oauth.common.exceptions.InvalidClientException;
import org.cloudfoundry.identity.uaa.oauth.common.exceptions.OAuth2Exception;
import org.junit.jupiter.api.Test;

import java.util.Date;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Moved test class of from spring-security-oauth2 into UAA
 * Scope: Test class
 */
class JsonSerializationTests {

    @Test
    void defaultSerialization() throws Exception {
        DefaultOAuth2AccessToken accessToken = new DefaultOAuth2AccessToken("FOO");
        accessToken.setExpiration(new Date(System.currentTimeMillis() + 10000));
        String result = new ObjectMapper().writeValueAsString(accessToken);
        // System.err.println(result);
        assertThat(result).as("Wrong token: " + result).contains("\"token_type\":\"bearer\"")
                .as("Wrong token: " + result).contains("\"access_token\":\"FOO\"")
                .as("Wrong token: " + result).contains("\"expires_in\":");
    }

    @Test
    void refreshSerialization() throws Exception {
        DefaultOAuth2AccessToken accessToken = new DefaultOAuth2AccessToken("FOO");
        accessToken.setRefreshToken(new DefaultOAuth2RefreshToken("BAR"));
        accessToken.setExpiration(new Date(System.currentTimeMillis() + 10000));
        String result = new ObjectMapper().writeValueAsString(accessToken);
        // System.err.println(result);
        assertThat(result).as("Wrong token: " + result).contains("\"token_type\":\"bearer\"")
                .as("Wrong token: " + result).contains("\"access_token\":\"FOO\"")
                .as("Wrong token: " + result).contains("\"refresh_token\":\"BAR\"")
                .as("Wrong token: " + result).contains("\"expires_in\":");
    }

    @Test
    void exceptionSerialization() throws Exception {
        InvalidClientException exception = new InvalidClientException("FOO");
        exception.addAdditionalInformation("foo", "bar");
        String result = new ObjectMapper().writeValueAsString(exception);
        // System.err.println(result);
        assertThat(result).as("Wrong result: " + result).contains("\"error\":\"invalid_client\"")
                .as("Wrong result: " + result).contains("\"error_description\":\"FOO\"")
                .as("Wrong result: " + result).contains("\"foo\":\"bar\"");
    }

    @Test
    void defaultDeserialization() throws Exception {
        String accessToken = "{\"access_token\": \"FOO\", \"expires_in\": 100, \"token_type\": \"mac\"}";
        OAuth2AccessToken result = new ObjectMapper().readValue(accessToken, OAuth2AccessToken.class);
        // System.err.println(result);
        assertThat(result.getValue()).isEqualTo("FOO");
        assertThat(result.getTokenType()).isEqualTo("mac");
        assertThat(result.getExpiration().getTime()).isGreaterThan(System.currentTimeMillis());
    }

    @Test
    void exceptionDeserialization() throws Exception {
        String exception = "{\"error\": \"invalid_client\", \"error_description\": \"FOO\", \"foo\": \"bar\"}";
        OAuth2Exception result = new ObjectMapper().readValue(exception, OAuth2Exception.class);
        // System.err.println(result);
        assertThat(result.getMessage()).isEqualTo("FOO");
        assertThat(result.getOAuth2ErrorCode()).isEqualTo("invalid_client");
        assertThat(result.getAdditionalInformation()).hasToString("{foo=bar}");
        assertThat(result).isInstanceOf(InvalidClientException.class);
    }
}
