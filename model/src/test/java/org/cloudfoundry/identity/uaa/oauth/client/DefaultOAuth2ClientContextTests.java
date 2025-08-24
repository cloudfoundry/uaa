package org.cloudfoundry.identity.uaa.oauth.client;

import org.cloudfoundry.identity.uaa.oauth.common.DefaultOAuth2AccessToken;
import org.cloudfoundry.identity.uaa.oauth.common.OAuth2AccessToken;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Moved test class of from spring-security-oauth2 into UAA
 * Scope: Test class
 */
class DefaultOAuth2ClientContextTests {

    @Test
    void resetsState() {
        DefaultOAuth2ClientContext clientContext = new DefaultOAuth2ClientContext();
        clientContext.setPreservedState("state1", "some-state-1");
        clientContext.setPreservedState("state2", "some-state-2");
        clientContext.setPreservedState("state3", "some-state-3");
        assertThat(clientContext.removePreservedState("state1")).isNull();
        assertThat(clientContext.removePreservedState("state2")).isNull();
        assertThat(clientContext.removePreservedState("state3")).isEqualTo("some-state-3");
    }

    @Test
    void init() {
        OAuth2AccessToken token = new DefaultOAuth2AccessToken("token");
        DefaultOAuth2ClientContext clientContext = new DefaultOAuth2ClientContext(token);
        clientContext.setPreservedState("state1", "some-state-1");
        assertThat(clientContext.removePreservedState("state1")).isNotNull();
        assertThat(clientContext.getAccessToken()).isEqualTo(token);
        clientContext.setAccessToken(null);
        assertThat(clientContext.getAccessToken()).isNotEqualTo(token);
    }
}
