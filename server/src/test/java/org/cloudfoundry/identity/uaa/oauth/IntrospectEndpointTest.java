package org.cloudfoundry.identity.uaa.oauth;

import org.cloudfoundry.identity.uaa.oauth.token.IntrospectionClaims;
import org.cloudfoundry.identity.uaa.extensions.PollutionPreventionExtension;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.exceptions.InvalidTokenException;
import org.springframework.security.oauth2.provider.token.ResourceServerTokenServices;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

@ExtendWith(PollutionPreventionExtension.class)
@ExtendWith(MockitoExtension.class)
class IntrospectEndpointTest {

    private IntrospectEndpoint introspectEndpoint;

    @Mock
    private ResourceServerTokenServices resourceServerTokenServices;

    private String validToken = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IlVBQSB1c2VybmFtZSIsImlhdCI6MTUxNjIzOTAyMn0.jS74pusAMo7VBsEN08rzpxMrk57ZMoRH3QX_gNUopJ4";

    @BeforeEach
    void setUp() {
        introspectEndpoint = new IntrospectEndpoint(resourceServerTokenServices);
    }

    @Test
    void validToken() {
        OAuth2AccessToken token = mock(OAuth2AccessToken.class);

        when(resourceServerTokenServices.readAccessToken(validToken)).thenReturn(token);
        when(token.isExpired()).thenReturn(false);
        when(token.getValue()).thenReturn(validToken);

        IntrospectionClaims claims = introspectEndpoint.introspect(validToken);
        assertTrue(claims.isActive());

        verify(resourceServerTokenServices).readAccessToken(validToken);
        verify(resourceServerTokenServices).loadAuthentication(validToken);
        verify(token).isExpired();
    }

    @Test
    void expiredTokenIsInactive() {
        OAuth2AccessToken token = mock(OAuth2AccessToken.class);

        when(resourceServerTokenServices.readAccessToken(validToken)).thenReturn(token);
        when(token.isExpired()).thenReturn(true);

        IntrospectionClaims claims = introspectEndpoint.introspect(validToken);
        assertFalse(claims.isActive());
    }

    @Test
    void invalidToken_inReadAccessToken() {
        when(resourceServerTokenServices.readAccessToken(validToken)).thenThrow(new InvalidTokenException("Bla"));
        IntrospectionClaims claims = introspectEndpoint.introspect(validToken);
        assertFalse(claims.isActive());
    }

    @Test
    void invalidToken_inLoadAuthentication() {
        OAuth2AccessToken token = mock(OAuth2AccessToken.class);
        when(resourceServerTokenServices.readAccessToken(validToken)).thenReturn(token);
        when(resourceServerTokenServices.loadAuthentication(validToken)).thenThrow(new InvalidTokenException("Bla"));
        IntrospectionClaims claims = introspectEndpoint.introspect(validToken);
        assertFalse(claims.isActive());
    }

    @Test
    void claimsForValidToken() {
        OAuth2AccessToken token = mock(OAuth2AccessToken.class);
        when(resourceServerTokenServices.readAccessToken(validToken)).thenReturn(token);
        when(token.isExpired()).thenReturn(false);
        when(token.getValue()).thenReturn(validToken);

        IntrospectionClaims claimsResult = introspectEndpoint.introspect(validToken);

        assertTrue(claimsResult.isActive());
        assertEquals("UAA username", claimsResult.getName());
    }

    @Test
    void invalidJSONInClaims() {
        String invalidToken = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e3RoaXMgaXMgbm90IHZhbGlkIEpTT059.LFFpQ0Gc28vd1YIF4OlgVSi2PjCXtImDC6HlJn75sbQ";

        OAuth2AccessToken token = mock(OAuth2AccessToken.class);
        when(resourceServerTokenServices.readAccessToken(invalidToken)).thenReturn(token);
        when(token.isExpired()).thenReturn(false);
        when(token.getValue()).thenReturn(invalidToken);

        IntrospectionClaims claimsResult = introspectEndpoint.introspect(invalidToken);

        assertFalse(claimsResult.isActive());
        assertNull(claimsResult.getName());
    }
}