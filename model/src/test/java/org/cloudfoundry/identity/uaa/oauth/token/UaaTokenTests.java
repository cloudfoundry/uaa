package org.cloudfoundry.identity.uaa.oauth.token;

import org.cloudfoundry.identity.uaa.oauth.client.grant.AuthorizationCodeAccessTokenProvider;
import org.cloudfoundry.identity.uaa.oauth.client.grant.ClientCredentialsAccessTokenProvider;
import org.cloudfoundry.identity.uaa.oauth.client.http.AccessTokenRequiredException;
import org.cloudfoundry.identity.uaa.oauth.client.resource.AuthorizationCodeResourceDetails;
import org.cloudfoundry.identity.uaa.oauth.client.resource.BaseOAuth2ProtectedResourceDetails;
import org.cloudfoundry.identity.uaa.oauth.client.resource.ClientCredentialsResourceDetails;
import org.cloudfoundry.identity.uaa.oauth.client.resource.OAuth2AccessDeniedException;
import org.cloudfoundry.identity.uaa.oauth.common.AuthenticationScheme;
import org.cloudfoundry.identity.uaa.oauth.common.DefaultOAuth2RefreshToken;
import org.cloudfoundry.identity.uaa.oauth.common.util.OAuth2Utils;
import org.junit.Before;
import org.junit.Test;
import org.springframework.http.client.ClientHttpRequestFactory;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.cloudfoundry.identity.uaa.oauth.common.OAuth2AccessToken.BEARER_TYPE;
import static org.junit.Assert.*;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class UaaTokenTests {

    private CompositeToken persistToken;
    private BaseOAuth2ProtectedResourceDetails resourceDetails;
    private AuthorizationCodeAccessTokenProvider authorizationCodeAccessTokenProvider;

    @Before
    public void setUp() throws Exception {
        persistToken = new CompositeToken("token-value");
        persistToken.setScope(Set.of("admin", "read", "write"));
        persistToken.setTokenType(BEARER_TYPE.toLowerCase());
        persistToken.setExpiration(new Date(System.currentTimeMillis() + 10000));
        resourceDetails = new BaseOAuth2ProtectedResourceDetails();
        resourceDetails.setClientId("client-id");
        resourceDetails.setScope(List.of("admin", "read", "write"));
        resourceDetails.setAuthenticationScheme(AuthenticationScheme.form);
        authorizationCodeAccessTokenProvider = new AuthorizationCodeAccessTokenProvider();
    }

    @Test
    public void getIdTokenValue() {
        assertNull(persistToken.getIdTokenValue());
        assertNull(resourceDetails.getId());
    }

    @Test
    public void testHashCode() {
        CompositeToken copyToken = new CompositeToken(persistToken);
        assertEquals(copyToken.hashCode(), persistToken.hashCode());
        assertEquals(resourceDetails.hashCode(), new BaseOAuth2ProtectedResourceDetails().hashCode());
    }

    @Test
    public void testEquals() {
        CompositeToken copyToken = new CompositeToken(persistToken);
        assertEquals(copyToken, persistToken);
        assertEquals(resourceDetails, new BaseOAuth2ProtectedResourceDetails());
    }

    @Test
    public void testOAuth2AccessDeniedException() {
        OAuth2AccessDeniedException oAuth2AccessDeniedException = new OAuth2AccessDeniedException();
        assertEquals(oAuth2AccessDeniedException.toString(), new OAuth2AccessDeniedException((BaseOAuth2ProtectedResourceDetails) null).toString());
        assertNotEquals(oAuth2AccessDeniedException.toString(), new OAuth2AccessDeniedException("", resourceDetails).toString());
        assertEquals("access_denied", oAuth2AccessDeniedException.getOAuth2ErrorCode());
        assertEquals(403, oAuth2AccessDeniedException.getHttpErrorCode());
    }

    @Test
    public void testAccessTokenRequiredException() {
        AccessTokenRequiredException accessTokenRequiredException = new AccessTokenRequiredException(resourceDetails);
        assertEquals(accessTokenRequiredException.toString(), new AccessTokenRequiredException(null).toString());
        assertNotEquals(accessTokenRequiredException.toString(), new AccessTokenRequiredException("", resourceDetails).toString());
        assertEquals(accessTokenRequiredException.toString(), new AccessTokenRequiredException("OAuth2 access denied.", resourceDetails, null).toString());
        assertNotNull(accessTokenRequiredException.getResource());
    }

    @Test
    public void testAccessTokenProviderChain() {
        AccessTokenProviderChain accessTokenProviderChain = new AccessTokenProviderChain(Collections.emptyList());
        ClientCredentialsAccessTokenProvider clientCredentialsAccessTokenProvider = new ClientCredentialsAccessTokenProvider();
        assertFalse(accessTokenProviderChain.supportsResource(resourceDetails));
        assertFalse(accessTokenProviderChain.supportsRefresh(resourceDetails));
        accessTokenProviderChain = new AccessTokenProviderChain(Arrays.asList(clientCredentialsAccessTokenProvider));
        assertTrue(accessTokenProviderChain.supportsResource(new ClientCredentialsResourceDetails()));
        assertFalse(accessTokenProviderChain.supportsRefresh(new ClientCredentialsResourceDetails()));
        assertTrue(authorizationCodeAccessTokenProvider.supportsRefresh(new AuthorizationCodeResourceDetails()));
    }

    @Test(expected = OAuth2AccessDeniedException.class)
    public void testAccessTokenProviderChainException() {
        ClientCredentialsAccessTokenProvider clientCredentialsAccessTokenProvider = new ClientCredentialsAccessTokenProvider();
        AccessTokenProviderChain accessTokenProviderChain = new AccessTokenProviderChain(Arrays.asList(clientCredentialsAccessTokenProvider));
        accessTokenProviderChain.refreshAccessToken(new ClientCredentialsResourceDetails(), new DefaultOAuth2RefreshToken(""), null);
    }

    @Test
    public void testDefaultAccessTokenRequest() {
        DefaultAccessTokenRequest accessTokenRequest = new DefaultAccessTokenRequest();
        MultiValueMap parameters = new LinkedMultiValueMap();
        parameters.add("empty", "");
        accessTokenRequest.setCookie("cookie-value");
        accessTokenRequest.setHeaders(null);
        // maintain
        assertTrue(accessTokenRequest.isEmpty());
        accessTokenRequest.set("key", "value");
        assertFalse(accessTokenRequest.isEmpty());
        accessTokenRequest.addAll(parameters);
        accessTokenRequest.clear();
        accessTokenRequest.add("key", "value");
        assertEquals(Set.of("key"), accessTokenRequest.keySet());
        assertEquals(List.of(List.of("value")).toString(), accessTokenRequest.values().toString());

        // parameters
        accessTokenRequest.clear();
        assertTrue(accessTokenRequest.isEmpty());
        accessTokenRequest.addAll("key", List.of("value"));
        accessTokenRequest.setAll(parameters);
        accessTokenRequest.putAll(parameters);
        accessTokenRequest.put("key", List.of("value"));
        assertFalse(accessTokenRequest.isEmpty());

        // object compare
        accessTokenRequest.clear();
        parameters = new LinkedMultiValueMap();
        parameters.addAll("key", List.of("value"));
        assertEquals(accessTokenRequest, new DefaultAccessTokenRequest(null));
        DefaultAccessTokenRequest newAccessTokenRequest = new DefaultAccessTokenRequest(Map.of("scope", new String[]{"x"}, "client_id", new String[]{"x"}));
        assertNotEquals(accessTokenRequest, newAccessTokenRequest);
        assertNotEquals(accessTokenRequest.toString(), newAccessTokenRequest.toString());
        assertNotEquals(accessTokenRequest.hashCode(), newAccessTokenRequest.hashCode());
        for (Map.Entry<String, List<String>> entry : accessTokenRequest.entrySet()) {
            assertNotNull(entry.getKey());
        }
        accessTokenRequest.remove("key");
        assertNull(accessTokenRequest.get("key"));
        assertFalse(accessTokenRequest.containsKey("key"));
        assertFalse(accessTokenRequest.containsValue("value"));
    }

    @Test(expected = NullPointerException.class)
    public void testAuthorizationCodeAccessTokenProvider() {
        ClientHttpRequestFactory clientHttpRequestFactory = mock(ClientHttpRequestFactory.class);
        AccessTokenRequest request = mock(AccessTokenRequest.class);
        AuthorizationCodeResourceDetails authorizationCodeResourceDetails = new AuthorizationCodeResourceDetails();
        authorizationCodeResourceDetails.setScope(List.of("admin"));
        when(request.getHeaders()).thenReturn(new HashMap<>(Map.of(OAuth2Utils.USER_OAUTH_APPROVAL, List.of("true"))));
        when(request.containsKey(OAuth2Utils.USER_OAUTH_APPROVAL)).thenReturn(true);
        authorizationCodeAccessTokenProvider.setRequestFactory(clientHttpRequestFactory);
        authorizationCodeAccessTokenProvider.obtainAuthorizationCode(authorizationCodeResourceDetails, request);
    }
}
