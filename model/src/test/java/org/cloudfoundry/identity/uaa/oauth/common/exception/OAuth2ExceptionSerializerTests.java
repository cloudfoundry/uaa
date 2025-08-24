package org.cloudfoundry.identity.uaa.oauth.common.exception;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.cloudfoundry.identity.uaa.oauth.common.exceptions.BadClientCredentialsException;
import org.cloudfoundry.identity.uaa.oauth.common.exceptions.InsufficientScopeException;
import org.cloudfoundry.identity.uaa.oauth.common.exceptions.InvalidClientException;
import org.cloudfoundry.identity.uaa.oauth.common.exceptions.InvalidGrantException;
import org.cloudfoundry.identity.uaa.oauth.common.exceptions.InvalidRequestException;
import org.cloudfoundry.identity.uaa.oauth.common.exceptions.InvalidScopeException;
import org.cloudfoundry.identity.uaa.oauth.common.exceptions.InvalidTokenException;
import org.cloudfoundry.identity.uaa.oauth.common.exceptions.OAuth2Exception;
import org.cloudfoundry.identity.uaa.oauth.common.exceptions.RedirectMismatchException;
import org.cloudfoundry.identity.uaa.oauth.common.exceptions.UnapprovedClientAuthenticationException;
import org.cloudfoundry.identity.uaa.oauth.common.exceptions.UnauthorizedClientException;
import org.cloudfoundry.identity.uaa.oauth.common.exceptions.UnsupportedGrantTypeException;
import org.cloudfoundry.identity.uaa.oauth.common.exceptions.UnsupportedResponseTypeException;
import org.cloudfoundry.identity.uaa.oauth.common.exceptions.UserDeniedAuthorizationException;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Moved test class of from spring-security-oauth2 into UAA
 * Scope: Test class
 */
class OAuth2ExceptionSerializerTests {

    private static final String DETAILS = "some detail";
    private static ObjectMapper mapper;
    private OAuth2Exception oauthException;

    @BeforeAll
    static void setUpClass() {
        mapper = new ObjectMapper();
    }

    @AfterEach
    void tearDown() {
        oauthException = null;
    }

    @Test
    void writeValueAsStringInvalidClient() throws Exception {
        oauthException = new InvalidClientException(DETAILS);
        String expected = createResponse(oauthException.getOAuth2ErrorCode());
        assertThat(mapper.writeValueAsString(oauthException)).isEqualTo(expected);
    }

    @Test
    void writeValueAsStringInvalidGrant() throws Exception {
        oauthException = new InvalidGrantException(DETAILS);
        String expected = createResponse(oauthException.getOAuth2ErrorCode());
        assertThat(mapper.writeValueAsString(oauthException)).isEqualTo(expected);
    }

    @Test
    void writeValueAsStringInvalidRequest() throws Exception {
        oauthException = new InvalidRequestException(DETAILS);
        String expected = createResponse(oauthException.getOAuth2ErrorCode());
        assertThat(mapper.writeValueAsString(oauthException)).isEqualTo(expected);
    }

    @Test
    void writeValueAsStringInvalidScope() throws Exception {
        oauthException = new InvalidScopeException(DETAILS);
        String expected = createResponse(oauthException.getOAuth2ErrorCode());
        assertThat(mapper.writeValueAsString(oauthException)).isEqualTo(expected);
    }

    @Test
    void writeValueAsStringUnsupportedGrantType() throws Exception {
        oauthException = new UnsupportedGrantTypeException(DETAILS);
        String expected = createResponse(oauthException.getOAuth2ErrorCode());
        assertThat(mapper.writeValueAsString(oauthException)).isEqualTo(expected);
    }

    @Test
    void writeValueAsStringUnauthorizedClient() throws Exception {
        oauthException = new UnauthorizedClientException(DETAILS);
        String expected = createResponse(oauthException.getOAuth2ErrorCode());
        assertThat(mapper.writeValueAsString(oauthException)).isEqualTo(expected);
    }

    @Test
    void writeValueAsStringAccessDenied() throws Exception {
        oauthException = new UserDeniedAuthorizationException(DETAILS);
        String expected = createResponse(oauthException.getOAuth2ErrorCode());
        assertThat(mapper.writeValueAsString(oauthException)).isEqualTo(expected);
    }

    @Test
    void writeValueAsStringUnapprovedClientAuthenticationException() {
        String expected = createResponse(new UnapprovedClientAuthenticationException(DETAILS, new Exception("")).getMessage());
        assertThat(expected).isNotNull();
    }

    @Test
    void writeValueAsStringRedirectUriMismatch() throws Exception {
        oauthException = new RedirectMismatchException(DETAILS);
        String expected = createResponse(oauthException.getOAuth2ErrorCode());
        assertThat(oauthException.getHttpErrorCode()).isEqualTo(400);
        assertThat(mapper.writeValueAsString(oauthException)).isEqualTo(expected);
    }

    @Test
    void writeValueAsStringInvalidToken() throws Exception {
        oauthException = new InvalidTokenException(DETAILS, new Exception(""));
        String expected = createResponse(oauthException.getOAuth2ErrorCode());
        assertThat(oauthException.getHttpErrorCode()).isEqualTo(401);
        assertThat(mapper.writeValueAsString(oauthException)).isEqualTo(expected);
    }

    @Test
    void writeValueAsStringBadCredentials() throws Exception {
        oauthException = new BadClientCredentialsException();
        assertThat(oauthException.getHttpErrorCode()).isEqualTo(401);
        assertThat(mapper.writeValueAsString(oauthException)).isEqualTo("{\"error\":\"invalid_client\",\"error_description\":\"Bad client credentials\"}");
    }

    @Test
    void writeValueAsStringInvalidClientException() throws Exception {
        oauthException = new InvalidClientException(DETAILS);
        assertThat(oauthException.getHttpErrorCode()).isEqualTo(401);
        String expected = createResponse(oauthException.getOAuth2ErrorCode());
        assertThat(mapper.writeValueAsString(oauthException)).isEqualTo(expected);
    }

    @Test
    void writeValueAsStringUnauthorizedClientException() throws Exception {
        oauthException = new UnauthorizedClientException(DETAILS, new Exception(""));
        assertThat(oauthException.getHttpErrorCode()).isEqualTo(401);
        String expected = createResponse(oauthException.getOAuth2ErrorCode());
        assertThat(mapper.writeValueAsString(oauthException)).isEqualTo(expected);
    }

    @Test
    void writeValueAsStringUnsupportedResponseTypeException() throws Exception {
        oauthException = new UnsupportedResponseTypeException(DETAILS);
        assertThat(oauthException.getHttpErrorCode()).isEqualTo(400);
        String expected = createResponse(oauthException.getOAuth2ErrorCode());
        assertThat(mapper.writeValueAsString(oauthException)).isEqualTo(expected);
    }

    @Test
    void writeValueAsStringInvalidScopeException() throws Exception {
        oauthException = new InvalidScopeException(DETAILS, Set.of("unknown"));
        assertThat(oauthException.getHttpErrorCode()).isEqualTo(400);
        assertThat(mapper.writeValueAsString(oauthException)).isNotNull();
    }

    @Test
    void writeValueAsStringInsufficientScopeException() throws Exception {
        oauthException = new InsufficientScopeException(DETAILS);
        assertThat(oauthException.getHttpErrorCode()).isEqualTo(403);
        String expected = createResponse(oauthException.getOAuth2ErrorCode());
        assertThat(mapper.writeValueAsString(oauthException)).isEqualTo(expected);
    }

    @Test
    void writeValueAsStringOAuth2Exception() throws Exception {
        oauthException = new OAuth2Exception(DETAILS);
        String expected = createResponse(oauthException.getOAuth2ErrorCode());
        assertThat(mapper.writeValueAsString(oauthException)).isEqualTo(expected);
    }

    @Test
    void writeValueAsStringWithAdditionalDetails() throws Exception {
        oauthException = new InvalidClientException(DETAILS);
        oauthException.addAdditionalInformation("foo", "bar");
        String expected = "{\"error\":\"invalid_client\",\"error_description\":\"some detail\",\"foo\":\"bar\"}";
        assertThat(mapper.writeValueAsString(oauthException)).isEqualTo(expected);
    }

    private String createResponse(String error) {
        return "{\"error\":\"" + error + "\",\"error_description\":\"some detail\"}";
    }
}
