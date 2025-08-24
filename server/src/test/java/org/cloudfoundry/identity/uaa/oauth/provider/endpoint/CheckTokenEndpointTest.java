package org.cloudfoundry.identity.uaa.oauth.provider.endpoint;

import org.cloudfoundry.identity.uaa.oauth.CheckTokenEndpoint;
import org.cloudfoundry.identity.uaa.oauth.common.OAuth2AccessToken;
import org.cloudfoundry.identity.uaa.oauth.provider.OAuth2Authentication;
import org.cloudfoundry.identity.uaa.oauth.provider.token.AccessTokenConverter;
import org.cloudfoundry.identity.uaa.oauth.provider.token.ResourceServerTokenServices;
import org.cloudfoundry.identity.uaa.oauth.token.Claims;
import org.cloudfoundry.identity.uaa.util.TimeServiceImpl;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;

import java.util.HashMap;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Moved test class of from spring-security-oauth2 into UAA
 * Scope: Test class
 */
class CheckTokenEndpointTest {
    private CheckTokenEndpoint checkTokenEndpoint;

    @BeforeEach
    void setUp() {
        ResourceServerTokenServices resourceServerTokenServices = mock(ResourceServerTokenServices.class);
        OAuth2AccessToken accessToken = mock(OAuth2AccessToken.class);
        OAuth2Authentication authentication = mock(OAuth2Authentication.class);
        when(resourceServerTokenServices.readAccessToken(anyString())).thenReturn(accessToken);
        when(accessToken.isExpired()).thenReturn(false);
        when(accessToken.getValue()).thenReturn("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c");
        when(resourceServerTokenServices.loadAuthentication(accessToken.getValue())).thenReturn(authentication);
        this.checkTokenEndpoint = new CheckTokenEndpoint(resourceServerTokenServices, new TimeServiceImpl());

        AccessTokenConverter accessTokenConverter = mock(AccessTokenConverter.class);
        when(accessTokenConverter.convertAccessToken(accessToken, authentication)).thenReturn(new HashMap());
    }

    // gh-1070
    @Test
    void checkTokenWhenTokenValidThenReturnActiveAttribute() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setParameter("token", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c");
        Claims claims = this.checkTokenEndpoint.checkToken(request);
        assertThat(claims).isNotNull();
    }
}
