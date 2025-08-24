package org.cloudfoundry.identity.uaa.oauth.common;

import org.cloudfoundry.identity.uaa.oauth.common.exceptions.InvalidClientException;
import org.cloudfoundry.identity.uaa.oauth.common.exceptions.InvalidGrantException;
import org.cloudfoundry.identity.uaa.oauth.common.exceptions.InvalidRequestException;
import org.cloudfoundry.identity.uaa.oauth.common.exceptions.InvalidScopeException;
import org.cloudfoundry.identity.uaa.oauth.common.exceptions.InvalidTokenException;
import org.cloudfoundry.identity.uaa.oauth.common.exceptions.OAuth2Exception;
import org.cloudfoundry.identity.uaa.oauth.common.exceptions.RedirectMismatchException;
import org.cloudfoundry.identity.uaa.oauth.common.exceptions.UnauthorizedClientException;
import org.cloudfoundry.identity.uaa.oauth.common.exceptions.UnsupportedGrantTypeException;
import org.cloudfoundry.identity.uaa.oauth.common.exceptions.UnsupportedResponseTypeException;
import org.cloudfoundry.identity.uaa.oauth.common.exceptions.UserDeniedAuthorizationException;
import org.junit.jupiter.api.Test;

import java.util.HashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Moved test class of from spring-security-oauth2 into UAA
 * Scope: Test class
 */
class DefaultOAuth2SerializationServiceTests {

    @Test
    void defaultDeserialization() {
        Map<String, String> accessToken = Map.of("access_token", "FOO", "expires_in", "100", "token_type", "mac", "scope", "test,ok", "refresh_token", "");
        OAuth2AccessToken result = DefaultOAuth2AccessToken.valueOf(accessToken);
        assertThat(result.getValue()).isEqualTo("FOO");
        assertThat(result.getTokenType()).isEqualTo("mac");
        assertThat(result.getExpiration().getTime()).isGreaterThan(System.currentTimeMillis());
    }

    @Test
    void defaultDeserializationException() {
        Map<String, String> accessToken = Map.of("access_token", "FOO", "expires_in", "x");
        DefaultOAuth2AccessToken result = (DefaultOAuth2AccessToken) DefaultOAuth2AccessToken.valueOf(accessToken);
        assertThat(result.getExpiration().getTime()).isNotZero();
        assertThat(result.getExpiresIn()).isZero();
        result.setExpiresIn(300);
        assertThat(result.getExpiresIn()).isZero();
        assertThat(result.hashCode()).isNotZero();
    }

    @Test
    void defaultDeserializationEquals() {
        Map<String, String> accessToken = Map.of("access_token", "FOO", "expires_in", "x");
        DefaultOAuth2AccessToken result = (DefaultOAuth2AccessToken) DefaultOAuth2AccessToken.valueOf(accessToken);
        DefaultOAuth2AccessToken result2 = new DefaultOAuth2AccessToken("bar");
        assertThat(result2).isNotEqualTo(result);
        result2.setValue("FOO");
        assertThat(result2).isEqualTo(result);
        DefaultOAuth2RefreshToken refreshToken = new DefaultOAuth2RefreshToken("bar");
        assertThat(result2).isNotEqualTo(refreshToken);
        assertThat(result2.hashCode()).isNotEqualTo(refreshToken.hashCode());
        assertThat(result2.toString()).isNotEqualTo(refreshToken.toString());
    }

    @Test
    void exceptionDeserialization() {
        Map<String, String> exception = MapBuilder.create("error", "invalid_client").add("error_description", "FOO")
                .build();
        OAuth2Exception result = OAuth2Exception.valueOf(exception);
        assertThat(result.getMessage()).isEqualTo("FOO");
        assertThat(result.getOAuth2ErrorCode()).isEqualTo("invalid_client");
        assertThat(result).isInstanceOf(InvalidClientException.class);
    }

    @Test
    void exceptionDeserialization2() {
        Map<String, String> exception = Map.of("error", "unauthorized_client", "error_description", "FOO");
        OAuth2Exception result = OAuth2Exception.valueOf(exception);
        assertThat(result.getSummary()).isNotNull();
        assertThat(result.getMessage()).isEqualTo("FOO");
        assertThat(result.getOAuth2ErrorCode()).isEqualTo("unauthorized_client");
        assertThat(result).isInstanceOf(UnauthorizedClientException.class);
    }

    @Test
    void exceptionDeserializationInvalidGrant() {
        Map<String, String> exception = Map.of("error", "invalid_grant", "error_description", "FOO");
        OAuth2Exception result = OAuth2Exception.valueOf(exception);
        result.addAdditionalInformation("hint", "unknown code");
        assertThat(result.getSummary()).isNotNull();
        assertThat(result.toString()).isNotNull();
        assertThat(result.getMessage()).isEqualTo("FOO");
        assertThat(result.getOAuth2ErrorCode()).isEqualTo("invalid_grant");
        assertThat(result).isInstanceOf(InvalidGrantException.class);
    }

    @Test
    void exceptionInvalidTokenException() {
        Map<String, String> exception = Map.of("error", "invalid_token", "error_description", "FOO");
        OAuth2Exception result = OAuth2Exception.valueOf(exception);
        assertThat(result.getSummary()).isNotNull();
        assertThat(result.getMessage()).isEqualTo("FOO");
        assertThat(result.getOAuth2ErrorCode()).isEqualTo("invalid_token");
        assertThat(result).isInstanceOf(InvalidTokenException.class);
    }

    @Test
    void exceptionInvalidRequestException() {
        Map<String, String> exception = Map.of("error", "invalid_request", "error_description", "FOO");
        OAuth2Exception result = OAuth2Exception.valueOf(exception);
        assertThat(result.getSummary()).isNotNull();
        assertThat(result.getMessage()).isEqualTo("FOO");
        assertThat(result.getOAuth2ErrorCode()).isEqualTo("invalid_request");
        assertThat(result).isInstanceOf(InvalidRequestException.class);
    }

    @Test
    void exceptionUnsupportedGrantTypeException() {
        Map<String, String> exception = Map.of("error", "unsupported_grant_type", "error_description", "FOO");
        OAuth2Exception result = OAuth2Exception.valueOf(exception);
        assertThat(result.getSummary()).isNotNull();
        assertThat(result.getMessage()).isEqualTo("FOO");
        assertThat(result.getOAuth2ErrorCode()).isEqualTo("unsupported_grant_type");
        assertThat(result).isInstanceOf(UnsupportedGrantTypeException.class);
    }

    @Test
    void exceptionUnsupportedResponseTypeException() {
        Map<String, String> exception = Map.of("error", "unsupported_response_type", "error_description", "FOO");
        OAuth2Exception result = OAuth2Exception.valueOf(exception);
        assertThat(result.getSummary()).isNotNull();
        assertThat(result.getMessage()).isEqualTo("FOO");
        assertThat(result.getOAuth2ErrorCode()).isEqualTo("unsupported_response_type");
        assertThat(result).isInstanceOf(UnsupportedResponseTypeException.class);
    }

    @Test
    void exceptionRedirectMismatchException() {
        Map<String, String> exception = Map.of("error", "redirect_uri_mismatch", "error_description", "FOO");
        OAuth2Exception result = OAuth2Exception.valueOf(exception);
        assertThat(result.getSummary()).isNotNull();
        assertThat(result.getMessage()).isEqualTo("FOO");
        assertThat(result.getOAuth2ErrorCode()).isEqualTo("invalid_grant");
        assertThat(result).isInstanceOf(RedirectMismatchException.class);
    }

    @Test
    void exceptionUserDeniedAuthorizationException() {
        Map<String, String> exception = Map.of("error", "access_denied", "error_description", "FOO");
        OAuth2Exception result = OAuth2Exception.valueOf(exception);
        assertThat(result.getSummary()).isNotNull();
        assertThat(result.getMessage()).isEqualTo("FOO");
        assertThat(result.getOAuth2ErrorCode()).isEqualTo("access_denied");
        assertThat(result).isInstanceOf(UserDeniedAuthorizationException.class);
    }

    @Test
    void exceptionInvalidScopeException() {
        Map<String, String> exception = Map.of("error", "invalid_scope", "error_description", "FOO");
        OAuth2Exception result = OAuth2Exception.valueOf(exception);
        assertThat(result.getSummary()).isNotNull();
        assertThat(result.getMessage()).isEqualTo("FOO");
        assertThat(result.getOAuth2ErrorCode()).isEqualTo("invalid_scope");
        assertThat(result).isInstanceOf(InvalidScopeException.class);
    }

    @Test
    void exceptionBadException() {
        Map<String, String> exception = Map.of("errortest", "xx", "bar", "FOO");
        OAuth2Exception result = OAuth2Exception.valueOf(exception);
        assertThat(result.getSummary()).isNotNull();
        assertThat(result.getMessage()).isEqualTo("OAuth Error");
        assertThat(result.getOAuth2ErrorCode()).isEqualTo("invalid_request");
        assertThat(result).isInstanceOf(OAuth2Exception.class);
    }

    private static final class MapBuilder {
        private final HashMap<String, String> map = new HashMap<>();

        private MapBuilder(String key, String value) {
            map.put(key, value);
        }

        public static MapBuilder create(String key, String value) {
            return new MapBuilder(key, value);
        }

        public MapBuilder add(String key, String value) {
            map.put(key, value);
            return this;
        }

        public Map<String, String> build() {
            return map;
        }
    }
}
