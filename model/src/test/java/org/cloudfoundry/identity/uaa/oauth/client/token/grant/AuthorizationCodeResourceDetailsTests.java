package org.cloudfoundry.identity.uaa.oauth.client.token.grant;

import org.cloudfoundry.identity.uaa.oauth.client.resource.AuthorizationCodeResourceDetails;
import org.cloudfoundry.identity.uaa.oauth.token.DefaultAccessTokenRequest;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Moved test class of from spring-security-oauth2 into UAA
 * Scope: Test class
 */
class AuthorizationCodeResourceDetailsTests {

    private final AuthorizationCodeResourceDetails details = new AuthorizationCodeResourceDetails();

    @Test
    void getDefaultRedirectUri() {
        details.setPreEstablishedRedirectUri("https://anywhere.com");
        DefaultAccessTokenRequest request = new DefaultAccessTokenRequest();
        request.setCurrentUri("https://nowhere.com");
        assertThat(details.getRedirectUri(request)).isEqualTo("https://nowhere.com");
    }

    @Test
    void getOverrideRedirectUri() {
        details.setPreEstablishedRedirectUri("https://anywhere.com");
        details.setUseCurrentUri(false);
        DefaultAccessTokenRequest request = new DefaultAccessTokenRequest();
        request.setCurrentUri("https://nowhere.com");
        assertThat(details.getRedirectUri(request)).isEqualTo("https://anywhere.com");
    }

}
