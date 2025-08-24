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
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.client.ClientHttpRequestFactory;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.AssertionsForClassTypes.assertThatExceptionOfType;
import static org.cloudfoundry.identity.uaa.oauth.common.OAuth2AccessToken.BEARER_TYPE;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class UaaTokenTests {

    private CompositeToken persistToken;
    private BaseOAuth2ProtectedResourceDetails resourceDetails;
    private AuthorizationCodeAccessTokenProvider authorizationCodeAccessTokenProvider;

    @BeforeEach
    void setUp() throws Exception {
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
    void getIdTokenValue() {
        assertThat(persistToken.getIdTokenValue()).isNull();
        assertThat(resourceDetails.getId()).isNull();
    }

    @Test
    void testHashCode() {
        CompositeToken copyToken = new CompositeToken(persistToken);
        assertThat(persistToken).hasSameHashCodeAs(copyToken);
        assertThat(new BaseOAuth2ProtectedResourceDetails()).hasSameHashCodeAs(resourceDetails);
    }

    @Test
    void equals() {
        CompositeToken copyToken = new CompositeToken(persistToken);
        assertThat(persistToken).isEqualTo(copyToken);
        assertThat(new BaseOAuth2ProtectedResourceDetails()).isEqualTo(resourceDetails);
    }

    @Test
    void oAuth2AccessDeniedException() {
        OAuth2AccessDeniedException oAuth2AccessDeniedException = new OAuth2AccessDeniedException();
        assertThat(new OAuth2AccessDeniedException((BaseOAuth2ProtectedResourceDetails) null)).hasToString(oAuth2AccessDeniedException.toString());
        assertThat(new OAuth2AccessDeniedException("", resourceDetails).toString()).isNotEqualTo(oAuth2AccessDeniedException.toString());
        assertThat(oAuth2AccessDeniedException.getOAuth2ErrorCode()).isEqualTo("access_denied");
        assertThat(oAuth2AccessDeniedException.getHttpErrorCode()).isEqualTo(403);
    }

    @Test
    void accessTokenRequiredException() {
        AccessTokenRequiredException accessTokenRequiredException = new AccessTokenRequiredException(resourceDetails);
        assertThat(new AccessTokenRequiredException(null)).hasToString(accessTokenRequiredException.toString());
        assertThat(new AccessTokenRequiredException("", resourceDetails).toString()).isNotEqualTo(accessTokenRequiredException.toString());
        assertThat(new AccessTokenRequiredException("OAuth2 access denied.", resourceDetails, null)).hasToString(accessTokenRequiredException.toString());
        assertThat(accessTokenRequiredException.getResource()).isNotNull();
    }

    @Test
    void accessTokenProviderChain() {
        AccessTokenProviderChain accessTokenProviderChain = new AccessTokenProviderChain(Collections.emptyList());
        ClientCredentialsAccessTokenProvider clientCredentialsAccessTokenProvider = new ClientCredentialsAccessTokenProvider();
        assertThat(accessTokenProviderChain.supportsResource(resourceDetails)).isFalse();
        assertThat(accessTokenProviderChain.supportsRefresh(resourceDetails)).isFalse();
        accessTokenProviderChain = new AccessTokenProviderChain(List.of(clientCredentialsAccessTokenProvider));
        assertThat(accessTokenProviderChain.supportsResource(new ClientCredentialsResourceDetails())).isTrue();
        assertThat(accessTokenProviderChain.supportsRefresh(new ClientCredentialsResourceDetails())).isFalse();
        assertThat(authorizationCodeAccessTokenProvider.supportsRefresh(new AuthorizationCodeResourceDetails())).isTrue();
    }

    @Test
    void accessTokenProviderChainException() {
        ClientCredentialsAccessTokenProvider clientCredentialsAccessTokenProvider = new ClientCredentialsAccessTokenProvider();
        AccessTokenProviderChain accessTokenProviderChain = new AccessTokenProviderChain(List.of(clientCredentialsAccessTokenProvider));
        assertThatExceptionOfType(OAuth2AccessDeniedException.class).isThrownBy(() ->
                accessTokenProviderChain.refreshAccessToken(new ClientCredentialsResourceDetails(), new DefaultOAuth2RefreshToken(""), null));
    }

    @Test
    void defaultAccessTokenRequest() {
        DefaultAccessTokenRequest accessTokenRequest = new DefaultAccessTokenRequest();
        MultiValueMap parameters = new LinkedMultiValueMap<>();
        parameters.add("empty", "");
        accessTokenRequest.setCookie("cookie-value");
        accessTokenRequest.setHeaders(null);
        // maintain
        assertThat(accessTokenRequest).isEmpty();
        accessTokenRequest.set("key", "value");
        assertThat(accessTokenRequest).isNotEmpty();
        accessTokenRequest.addAll(parameters);
        accessTokenRequest.clear();
        accessTokenRequest.add("key", "value");
        assertThat(accessTokenRequest.keySet()).isEqualTo(Set.of("key"));
        assertThat(accessTokenRequest.values()).hasToString(List.of(List.of("value")).toString());

        // parameters
        accessTokenRequest.clear();
        assertThat(accessTokenRequest).isEmpty();
        accessTokenRequest.addAll("key", List.of("value"));
        accessTokenRequest.setAll(parameters);
        accessTokenRequest.putAll(parameters);
        accessTokenRequest.put("key", List.of("value"));
        assertThat(accessTokenRequest).isNotEmpty();

        // object compare
        accessTokenRequest.clear();
        parameters = new LinkedMultiValueMap<>();
        parameters.addAll("key", List.of("value"));
        assertThat(new DefaultAccessTokenRequest(null)).isEqualTo(accessTokenRequest);
        DefaultAccessTokenRequest newAccessTokenRequest = new DefaultAccessTokenRequest(Map.of("scope", new String[]{"x"}, "client_id", new String[]{"x"}));
        assertThat(newAccessTokenRequest).isNotEqualTo(accessTokenRequest);
        assertThat(newAccessTokenRequest.toString()).isNotEqualTo(accessTokenRequest.toString());
        assertThat(newAccessTokenRequest.hashCode()).isNotEqualTo(accessTokenRequest.hashCode());
        for (Map.Entry<String, List<String>> entry : accessTokenRequest.entrySet()) {
            assertThat(entry.getKey()).isNotNull();
        }
        accessTokenRequest.remove("key");
        assertThat(accessTokenRequest).doesNotContainKey("key")
                .doesNotContainKey("key");
        assertThat(accessTokenRequest.containsValue("value")).isFalse();
    }

    @Test
    void authorizationCodeAccessTokenProvider() {
        ClientHttpRequestFactory clientHttpRequestFactory = mock(ClientHttpRequestFactory.class);
        AccessTokenRequest request = mock(AccessTokenRequest.class);
        AuthorizationCodeResourceDetails authorizationCodeResourceDetails = new AuthorizationCodeResourceDetails();
        authorizationCodeResourceDetails.setScope(List.of("admin"));
        when(request.getHeaders()).thenReturn(new HashMap<>(Map.of(OAuth2Utils.USER_OAUTH_APPROVAL, List.of("true"))));
        when(request.containsKey(OAuth2Utils.USER_OAUTH_APPROVAL)).thenReturn(true);
        authorizationCodeAccessTokenProvider.setRequestFactory(clientHttpRequestFactory);
        assertThatExceptionOfType(NullPointerException.class).isThrownBy(() ->
                authorizationCodeAccessTokenProvider.obtainAuthorizationCode(authorizationCodeResourceDetails, request));
    }
}
