package org.cloudfoundry.identity.uaa.oauth.provider;

import org.cloudfoundry.identity.uaa.oauth.common.util.OAuth2Utils;
import org.cloudfoundry.identity.uaa.oauth.provider.implicit.ImplicitTokenRequest;
import org.junit.Before;
import org.junit.Test;

import java.util.Collections;
import java.util.Map;
import java.util.Set;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.mock;

/**
 * Moved test class of from spring-security-oauth2 into UAA
 * Scope: Test class
 */
public class OAuth2RequestTests {

    private OAuth2Request oAuth2Request;

    @Before
    public void setUp() throws Exception {

        oAuth2Request = new OAuth2Request(Map.of("client_id", "id"), "id", Collections.emptyList(), true, Set.of("client"),
                Set.of(), null, null, Map.of("extra", "param"));
    }

    @Test
    public void getRedirectUri() {
        assertNull(oAuth2Request.getRedirectUri());
    }

    @Test
    public void getResponseTypes() {
        assertEquals(Set.of(), oAuth2Request.getResponseTypes());
    }

    @Test
    public void getAuthorities() {
        assertEquals(Set.of(), oAuth2Request.getAuthorities());
    }

    @Test
    public void isApproved() {
        assertTrue(oAuth2Request.isApproved());
    }

    @Test
    public void getResourceIds() {
        assertEquals(Set.of(), oAuth2Request.getResourceIds());
    }

    @Test
    public void getExtensions() {
        assertEquals(Map.of("extra", "param"), oAuth2Request.getExtensions());
    }

    @Test
    public void createOAuth2Request() {
        OAuth2Request copyOf = new OAuth2Request(oAuth2Request);
        assertEquals(oAuth2Request, copyOf);
        OAuth2Request fromClient = new OAuth2Request("id");
        assertNotEquals(oAuth2Request, fromClient);
        assertNotEquals(oAuth2Request, new OAuth2Request());
        OAuth2Request paramCopy = oAuth2Request.createOAuth2Request(Map.of("extra", "param"));
        assertNotEquals(oAuth2Request, paramCopy);
    }

    @Test
    public void narrowScope() {
        OAuth2Request narrow = oAuth2Request.narrowScope(Set.of("scope1", "scope2"));
        assertEquals(Set.of("scope1", "scope2"), narrow.getScope());
    }

    @Test
    public void refresh() {
        OAuth2Request request = oAuth2Request.refresh(new ImplicitTokenRequest(mock(TokenRequest.class), mock(OAuth2Request.class)));
        assertEquals(Set.of("client"), request.getScope());
        assertEquals(oAuth2Request, request);
        assertNotNull(request.getRefreshTokenRequest());
    }

    @Test
    public void isRefresh() {
        OAuth2Request request = oAuth2Request.refresh(new ImplicitTokenRequest(mock(TokenRequest.class), mock(OAuth2Request.class)));
        assertTrue(request.isRefresh());
    }

    @Test
    public void getRefreshTokenRequest() {
        assertNull(oAuth2Request.getRefreshTokenRequest());
        assertNotNull(oAuth2Request.refresh(new ImplicitTokenRequest(mock(TokenRequest.class), mock(OAuth2Request.class))).getRefreshTokenRequest());
    }

    @Test
    public void getGrantType() {
        assertNull(oAuth2Request.getGrantType());
        oAuth2Request.setRequestParameters(Map.of(OAuth2Utils.GRANT_TYPE, "implicit"));
        assertEquals("implicit", oAuth2Request.getGrantType());
        oAuth2Request.setRequestParameters(Map.of(OAuth2Utils.RESPONSE_TYPE, "token"));
        assertEquals("implicit", oAuth2Request.getGrantType());
    }

    @Test
    public void getRequestParameters() {
        oAuth2Request.setRequestParameters(Map.of(OAuth2Utils.RESPONSE_TYPE, "token"));
        assertEquals("token", oAuth2Request.getRequestParameters().get("response_type"));
    }

    @Test
    public void testEquals() {
        OAuth2Request copyOf = new OAuth2Request(oAuth2Request);
        assertEquals(oAuth2Request, copyOf);
        assertEquals(oAuth2Request.hashCode(), copyOf.hashCode());
    }
}
