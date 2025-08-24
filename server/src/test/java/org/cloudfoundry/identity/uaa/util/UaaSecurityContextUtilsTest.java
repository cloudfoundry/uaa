package org.cloudfoundry.identity.uaa.util;

import org.cloudfoundry.identity.uaa.oauth.provider.OAuth2Authentication;
import org.cloudfoundry.identity.uaa.oauth.provider.OAuth2Request;
import org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.core.context.SecurityContextHolder;

import java.util.HashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.CLIENT_AUTH_NONE;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class UaaSecurityContextUtilsTest {

    private OAuth2Request auth2Request;

    @BeforeEach
    void setUp() {
        OAuth2Authentication authentication = mock(OAuth2Authentication.class);
        SecurityContextHolder.getContext().setAuthentication(authentication);
        auth2Request = mock(OAuth2Request.class);
        when(auth2Request.getExtensions()).thenReturn(new HashMap<>());
        when(authentication.getOAuth2Request()).thenReturn(auth2Request);
    }

    @Test
    void getNoClientAuthenticationMethod() {
        assertThat(UaaSecurityContextUtils.getClientAuthenticationMethod()).isNull();
    }

    @Test
    void getNullClientAuthenticationMethod() {
        SecurityContextHolder.getContext().setAuthentication(null);
        assertThat(UaaSecurityContextUtils.getClientAuthenticationMethod()).isNull();
    }

    @Test
    void getClientAuthenticationMethod() {
        when(auth2Request.getExtensions()).thenReturn(Map.of(ClaimConstants.CLIENT_AUTH_METHOD, CLIENT_AUTH_NONE));
        assertThat(UaaSecurityContextUtils.getClientAuthenticationMethod()).isEqualTo(CLIENT_AUTH_NONE);
    }
}
