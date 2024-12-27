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
import org.junit.After;
import org.junit.BeforeClass;
import org.junit.Test;

import java.util.Set;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

/**
 * Moved test class of from spring-security-oauth2 into UAA
 * Scope: Test class
 */
public class OAuth2ExceptionSerializerTests {

    private static final String DETAILS = "some detail";
    private static ObjectMapper mapper;
    private OAuth2Exception oauthException;

    @BeforeClass
    public static void setUpClass() {
        mapper = new ObjectMapper();
    }

    @After
    public void tearDown() {
        oauthException = null;
    }

    @Test
    public void writeValueAsStringInvalidClient() throws Exception {
        oauthException = new InvalidClientException(DETAILS);
        String expected = createResponse(oauthException.getOAuth2ErrorCode());
        assertEquals(expected, mapper.writeValueAsString(oauthException));
    }

    @Test
    public void writeValueAsStringInvalidGrant() throws Exception {
        oauthException = new InvalidGrantException(DETAILS);
        String expected = createResponse(oauthException.getOAuth2ErrorCode());
        assertEquals(expected, mapper.writeValueAsString(oauthException));
    }

    @Test
    public void writeValueAsStringInvalidRequest() throws Exception {
        oauthException = new InvalidRequestException(DETAILS);
        String expected = createResponse(oauthException.getOAuth2ErrorCode());
        assertEquals(expected, mapper.writeValueAsString(oauthException));
    }

    @Test
    public void writeValueAsStringInvalidScope() throws Exception {
        oauthException = new InvalidScopeException(DETAILS);
        String expected = createResponse(oauthException.getOAuth2ErrorCode());
        assertEquals(expected, mapper.writeValueAsString(oauthException));
    }

    @Test
    public void writeValueAsStringUnsupportedGrantType() throws Exception {
        oauthException = new UnsupportedGrantTypeException(DETAILS);
        String expected = createResponse(oauthException.getOAuth2ErrorCode());
        assertEquals(expected, mapper.writeValueAsString(oauthException));
    }

    @Test
    public void writeValueAsStringUnauthorizedClient() throws Exception {
        oauthException = new UnauthorizedClientException(DETAILS);
        String expected = createResponse(oauthException.getOAuth2ErrorCode());
        assertEquals(expected, mapper.writeValueAsString(oauthException));
    }

    @Test
    public void writeValueAsStringAccessDenied() throws Exception {
        oauthException = new UserDeniedAuthorizationException(DETAILS);
        String expected = createResponse(oauthException.getOAuth2ErrorCode());
        assertEquals(expected, mapper.writeValueAsString(oauthException));
    }

    @Test
    public void writeValueAsStringUnapprovedClientAuthenticationException() throws Exception {
        String expected = createResponse(new UnapprovedClientAuthenticationException(DETAILS, new Exception("")).getMessage());
        assertNotNull(expected);
    }

    @Test
    public void writeValueAsStringRedirectUriMismatch() throws Exception {
        oauthException = new RedirectMismatchException(DETAILS);
        String expected = createResponse(oauthException.getOAuth2ErrorCode());
        assertEquals(400, oauthException.getHttpErrorCode());
        assertEquals(expected, mapper.writeValueAsString(oauthException));
    }

    @Test
    public void writeValueAsStringInvalidToken() throws Exception {
        oauthException = new InvalidTokenException(DETAILS, new Exception(""));
        String expected = createResponse(oauthException.getOAuth2ErrorCode());
        assertEquals(401, oauthException.getHttpErrorCode());
        assertEquals(expected, mapper.writeValueAsString(oauthException));
    }

    @Test
    public void writeValueAsStringBadCredentials() throws Exception {
        oauthException = new BadClientCredentialsException();
        assertEquals(401, oauthException.getHttpErrorCode());
        assertEquals("{\"error\":\"invalid_client\",\"error_description\":\"Bad client credentials\"}", mapper.writeValueAsString(oauthException));
    }

    @Test
    public void writeValueAsStringInvalidClientException() throws Exception {
        oauthException = new InvalidClientException(DETAILS);
        assertEquals(401, oauthException.getHttpErrorCode());
        String expected = createResponse(oauthException.getOAuth2ErrorCode());
        assertEquals(expected, mapper.writeValueAsString(oauthException));
    }

    @Test
    public void writeValueAsStringUnauthorizedClientException() throws Exception {
        oauthException = new UnauthorizedClientException(DETAILS, new Exception(""));
        assertEquals(401, oauthException.getHttpErrorCode());
        String expected = createResponse(oauthException.getOAuth2ErrorCode());
        assertEquals(expected, mapper.writeValueAsString(oauthException));
    }

    @Test
    public void writeValueAsStringUnsupportedResponseTypeException() throws Exception {
        oauthException = new UnsupportedResponseTypeException(DETAILS);
        assertEquals(400, oauthException.getHttpErrorCode());
        String expected = createResponse(oauthException.getOAuth2ErrorCode());
        assertEquals(expected, mapper.writeValueAsString(oauthException));
    }

    @Test
    public void writeValueAsStringInvalidScopeException() throws Exception {
        oauthException = new InvalidScopeException(DETAILS, Set.of("unknown"));
        assertEquals(400, oauthException.getHttpErrorCode());
        String expected = createResponse(oauthException.getOAuth2ErrorCode());
        assertNotNull(mapper.writeValueAsString(oauthException));
    }

    @Test
    public void writeValueAsStringInsufficientScopeException() throws Exception {
        oauthException = new InsufficientScopeException(DETAILS);
        assertEquals(403, oauthException.getHttpErrorCode());
        String expected = createResponse(oauthException.getOAuth2ErrorCode());
        assertEquals(expected, mapper.writeValueAsString(oauthException));
    }

    @Test
    public void writeValueAsStringOAuth2Exception() throws Exception {
        oauthException = new OAuth2Exception(DETAILS);
        String expected = createResponse(oauthException.getOAuth2ErrorCode());
        assertEquals(expected, mapper.writeValueAsString(oauthException));
    }

    @Test
    public void writeValueAsStringWithAdditionalDetails() throws Exception {
        oauthException = new InvalidClientException(DETAILS);
        oauthException.addAdditionalInformation("foo", "bar");
        String expected = "{\"error\":\"invalid_client\",\"error_description\":\"some detail\",\"foo\":\"bar\"}";
        assertEquals(expected, mapper.writeValueAsString(oauthException));
    }

    private String createResponse(String error) {
        return "{\"error\":\"" + error + "\",\"error_description\":\"some detail\"}";
    }
}
