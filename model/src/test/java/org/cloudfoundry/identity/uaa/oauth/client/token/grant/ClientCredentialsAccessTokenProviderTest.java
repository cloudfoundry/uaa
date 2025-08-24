package org.cloudfoundry.identity.uaa.oauth.client.token.grant;

import org.cloudfoundry.identity.uaa.oauth.client.grant.ClientCredentialsAccessTokenProvider;
import org.cloudfoundry.identity.uaa.oauth.client.resource.ClientCredentialsResourceDetails;
import org.cloudfoundry.identity.uaa.oauth.client.resource.OAuth2ProtectedResourceDetails;
import org.cloudfoundry.identity.uaa.oauth.common.DefaultOAuth2AccessToken;
import org.cloudfoundry.identity.uaa.oauth.common.DefaultOAuth2RefreshToken;
import org.cloudfoundry.identity.uaa.oauth.common.OAuth2AccessToken;
import org.cloudfoundry.identity.uaa.oauth.token.AccessTokenRequest;
import org.cloudfoundry.identity.uaa.oauth.token.DefaultAccessTokenRequest;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

import java.util.Collections;
import java.util.Map;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

class ClientCredentialsAccessTokenProviderTest {

    private final MultiValueMap<String, String> params = new LinkedMultiValueMap<>();

    private final ClientCredentialsAccessTokenProvider provider = new ClientCredentialsAccessTokenProvider() {
        @Override
        protected OAuth2AccessToken retrieveToken(AccessTokenRequest request, OAuth2ProtectedResourceDetails resource,
                                                  MultiValueMap<String, String> form, HttpHeaders headers) {
            params.putAll(form);
            return new DefaultOAuth2AccessToken("FOO");
        }
    };

    @Test
    void supportsResource() {
        assertThat(provider.supportsResource(new ClientCredentialsResourceDetails())).isTrue();
    }

    @Test
    void supportsRefresh() {
        assertThat(provider.supportsRefresh(new ClientCredentialsResourceDetails())).isFalse();
    }

    @Test
    void refreshAccessToken() {
        assertThat(provider.refreshAccessToken(new ClientCredentialsResourceDetails(), new DefaultOAuth2RefreshToken(""), new DefaultAccessTokenRequest(
                Collections.emptyMap()))).isNull();
    }

    @Test
    void obtainAccessToken() {
        ClientCredentialsResourceDetails details = new ClientCredentialsResourceDetails();
        details.setScope(Set.of("openid").stream().toList());
        assertThat(details.isClientOnly()).isTrue();
        assertThat(provider.obtainAccessToken(details, new DefaultAccessTokenRequest(Map.of("scope", new String[]{"x"})))).isNotNull();
    }
}
