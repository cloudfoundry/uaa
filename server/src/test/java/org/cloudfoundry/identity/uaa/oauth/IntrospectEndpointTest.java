package org.cloudfoundry.identity.uaa.oauth;

import org.cloudfoundry.identity.uaa.oauth.jwt.Jwt;
import org.cloudfoundry.identity.uaa.oauth.jwt.JwtHelper;
import org.cloudfoundry.identity.uaa.oauth.token.IntrospectionClaims;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.powermock.api.mockito.PowerMockito;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.PowerMockRunner;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.exceptions.InvalidTokenException;
import org.springframework.security.oauth2.provider.token.ResourceServerTokenServices;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@RunWith(PowerMockRunner.class)
@PrepareForTest({JwtHelper.class, JsonUtils.class})
public class IntrospectEndpointTest {

    private IntrospectEndpoint introspectEndpoint;
    @Mock
    private ResourceServerTokenServices resourceServerTokenServices;

    @Before
    public void setUp() {
        introspectEndpoint = new IntrospectEndpoint();
        introspectEndpoint.setTokenServices(resourceServerTokenServices);

        Jwt jwt = mock(Jwt.class);
        IntrospectionClaims claims = new IntrospectionClaims();
        claims.setName("somename");

        when(jwt.getClaims()).thenReturn("claims");
        PowerMockito.mockStatic(JwtHelper.class);
        Mockito.when(JwtHelper.decode("valid-token")).thenReturn(jwt);

        PowerMockito.mockStatic(JsonUtils.class);
        Mockito.when(JsonUtils.readValue("claims", IntrospectionClaims.class)).thenReturn(claims);
    }

    @Test
    public void testValidToken() {
        OAuth2AccessToken token = mock(OAuth2AccessToken.class);

        when(resourceServerTokenServices.readAccessToken("valid-token")).thenReturn(token);
        when(token.isExpired()).thenReturn(false);
        when(token.getValue()).thenReturn("valid-token");

        IntrospectionClaims claims = introspectEndpoint.introspect("valid-token");
        Assert.assertTrue(claims.isActive());

        verify(resourceServerTokenServices).readAccessToken("valid-token");
        verify(resourceServerTokenServices).loadAuthentication("valid-token");
        verify(token).isExpired();
    }

    @Test
    public void testExpiredTokenIsInactive() {
        OAuth2AccessToken token = mock(OAuth2AccessToken.class);

        when(resourceServerTokenServices.readAccessToken("valid-token")).thenReturn(token);
        when(token.isExpired()).thenReturn(true);

        IntrospectionClaims claims = introspectEndpoint.introspect("valid-token");
        Assert.assertFalse(claims.isActive());
    }

    @Test
    public void testInvalidToken_inReadAccessToken() {
        when(resourceServerTokenServices.readAccessToken("valid-token")).thenThrow(new InvalidTokenException("Bla"));
        IntrospectionClaims claims = introspectEndpoint.introspect("valid-token");
        Assert.assertFalse(claims.isActive());
    }

    @Test
    public void testInvalidToken_inLoadAuthentication() {
        OAuth2AccessToken token = mock(OAuth2AccessToken.class);
        when(resourceServerTokenServices.readAccessToken("valid-token")).thenReturn(token);
        when(resourceServerTokenServices.loadAuthentication("valid-token")).thenThrow(new InvalidTokenException("Bla"));
        IntrospectionClaims claims = introspectEndpoint.introspect("valid-token");
        Assert.assertFalse(claims.isActive());
    }

    @Test
    public void testClaimsForValidToken() {
        OAuth2AccessToken token = mock(OAuth2AccessToken.class);
        when(resourceServerTokenServices.readAccessToken("valid-token")).thenReturn(token);
        when(token.isExpired()).thenReturn(false);
        when(token.getValue()).thenReturn("valid-token");

        IntrospectionClaims claimsResult = introspectEndpoint.introspect("valid-token");

        Assert.assertTrue(claimsResult.isActive());
        Assert.assertEquals("somename", claimsResult.getName());
    }

    @Test
    public void testInvalidJSONInClaims() {
        OAuth2AccessToken token = mock(OAuth2AccessToken.class);
        when(resourceServerTokenServices.readAccessToken("valid-token")).thenReturn(token);
        when(token.isExpired()).thenReturn(false);
        when(token.getValue()).thenReturn("valid-token");

        PowerMockito.mockStatic(JsonUtils.class);
        Mockito.when(JsonUtils.readValue("claims", IntrospectionClaims.class)).thenThrow(JsonUtils.JsonUtilException.class);

        IntrospectionClaims claimsResult = introspectEndpoint.introspect("valid-token");

        Assert.assertFalse(claimsResult.isActive());
        Assert.assertNull(claimsResult.getName());
    }
}