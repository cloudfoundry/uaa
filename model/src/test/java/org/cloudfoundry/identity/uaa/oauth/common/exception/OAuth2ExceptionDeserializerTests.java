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
import org.cloudfoundry.identity.uaa.oauth.common.exceptions.UnauthorizedClientException;
import org.cloudfoundry.identity.uaa.oauth.common.exceptions.UnsupportedGrantTypeException;
import org.cloudfoundry.identity.uaa.oauth.common.exceptions.UserDeniedAuthorizationException;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Moved test class of from spring-security-oauth2 into UAA
 * Scope: Test class
 */
class OAuth2ExceptionDeserializerTests {
    private static final String DETAILS = "some detail";
    private static ObjectMapper mapper;

    @BeforeAll
    static void setUpClass() {
        mapper = new ObjectMapper();
    }

    @Test
    void readValueInvalidGrant() throws Exception {
        String accessToken = createResponse(OAuth2Exception.INVALID_GRANT);
        InvalidGrantException result = (InvalidGrantException) mapper.readValue(accessToken, OAuth2Exception.class);
        assertThat(result.getMessage()).isEqualTo(DETAILS);
        assertThat(result.getAdditionalInformation()).isNull();
    }

    @Test
    void readValueInvalidRequest() throws Exception {
        String accessToken = createResponse(OAuth2Exception.INVALID_REQUEST);
        InvalidRequestException result = (InvalidRequestException) mapper.readValue(accessToken, OAuth2Exception.class);
        assertThat(result.getMessage()).isEqualTo(DETAILS);
        assertThat(result.getAdditionalInformation()).isNull();
    }

    @Test
    void readValueInvalidScope() throws Exception {
        String accessToken = createResponse(OAuth2Exception.INVALID_SCOPE);
        InvalidScopeException result = (InvalidScopeException) mapper.readValue(accessToken, OAuth2Exception.class);
        assertThat(result.getMessage()).isEqualTo(DETAILS);
        assertThat(result.getAdditionalInformation()).isNull();
    }

    @Test
    void readValueIsufficientScope() throws Exception {
        String accessToken = "{\"error\": \"insufficient_scope\", \"error_description\": \"insufficient scope\", \"scope\": \"bar foo\"}";
        InsufficientScopeException result = (InsufficientScopeException) mapper.readValue(accessToken, OAuth2Exception.class);
        assertThat(result.getMessage()).isEqualTo("insufficient scope");
        assertThat(result.getAdditionalInformation()).containsEntry("scope", "bar foo");
    }

    @Test
    void readValueUnsupportedGrantType() throws Exception {
        String accessToken = createResponse(OAuth2Exception.UNSUPPORTED_GRANT_TYPE);
        UnsupportedGrantTypeException result = (UnsupportedGrantTypeException) mapper.readValue(accessToken,
                OAuth2Exception.class);
        assertThat(result.getMessage()).isEqualTo(DETAILS);
        assertThat(result.getAdditionalInformation()).isNull();
    }

    @Test
    void readValueUnauthorizedClient() throws Exception {
        String accessToken = createResponse(OAuth2Exception.UNAUTHORIZED_CLIENT);
        UnauthorizedClientException result = (UnauthorizedClientException) mapper.readValue(accessToken,
                OAuth2Exception.class);
        assertThat(result.getMessage()).isEqualTo(DETAILS);
        assertThat(result.getAdditionalInformation()).isNull();
    }

    @Test
    void readValueAccessDenied() throws Exception {
        String accessToken = createResponse(OAuth2Exception.ACCESS_DENIED);
        UserDeniedAuthorizationException result = (UserDeniedAuthorizationException) mapper.readValue(accessToken,
                OAuth2Exception.class);
        assertThat(result.getMessage()).isEqualTo(DETAILS);
        assertThat(result.getAdditionalInformation()).isNull();
    }

    @Test
    void readValueRedirectUriMismatch() throws Exception {
        String accessToken = createResponse(OAuth2Exception.INVALID_GRANT, "Redirect URI mismatch.");
        RedirectMismatchException result = (RedirectMismatchException) mapper.readValue(accessToken,
                OAuth2Exception.class);
        assertThat(result.getMessage()).isEqualTo("Redirect URI mismatch.");
        assertThat(result.getAdditionalInformation()).isNull();
    }

    @Test
    void readValueInvalidToken() throws Exception {
        String accessToken = createResponse(OAuth2Exception.INVALID_TOKEN);
        InvalidTokenException result = (InvalidTokenException) mapper.readValue(accessToken, OAuth2Exception.class);
        assertThat(result.getMessage()).isEqualTo(DETAILS);
        assertThat(result.getAdditionalInformation()).isNull();
    }

    @Test
    void readValueUndefinedException() throws Exception {
        String accessToken = createResponse("notdefinedcode");
        OAuth2Exception result = mapper.readValue(accessToken, OAuth2Exception.class);
        assertThat(result.getMessage()).isEqualTo(DETAILS);
        assertThat(result.getAdditionalInformation()).isNull();
    }

    @Test
    void readValueInvalidClient() throws Exception {
        String accessToken = createResponse(OAuth2Exception.INVALID_CLIENT);
        InvalidClientException result = (InvalidClientException) mapper.readValue(accessToken, OAuth2Exception.class);
        assertThat(result.getMessage()).isEqualTo(DETAILS);
        assertThat(result.getAdditionalInformation()).isNull();
    }

    @Test
    void readValueWithAdditionalDetails() throws Exception {
        String accessToken = "{\"error\": \"invalid_client\", \"error_description\": \"some detail\", \"foo\": \"bar\"}";
        InvalidClientException result = (InvalidClientException) mapper.readValue(accessToken, OAuth2Exception.class);
        assertThat(result.getMessage()).isEqualTo(DETAILS);
        assertThat(result.getAdditionalInformation()).hasToString("{foo=bar}");
    }

    @Test
    void readValueWithObjects() throws Exception {
        String accessToken = "{\"error\": [\"invalid\",\"client\"], \"error_description\": {\"some\":\"detail\"}, \"foo\": [\"bar\"]}";
        OAuth2Exception result = mapper.readValue(accessToken, OAuth2Exception.class);
        assertThat(result.getMessage()).isEqualTo("{some=detail}");
        assertThat(result.getAdditionalInformation()).hasToString("{foo=[bar]}");
    }

    @Test
    void readValueBadCredentials() throws Exception {
        String accessToken = createResponse(OAuth2Exception.INVALID_CLIENT);
        OAuth2Exception result = mapper.readValue(accessToken,
                BadClientCredentialsException.class);
        assertThat(result.getMessage()).isEqualTo(DETAILS);
        assertThat(result.getAdditionalInformation()).isNull();
    }

    private String createResponse(String error, String message) {
        return "{\"error\":\"" + error + "\",\"error_description\":\"" + message + "\"}";
    }

    private String createResponse(String error) {
        return createResponse(error, DETAILS);
    }

}
