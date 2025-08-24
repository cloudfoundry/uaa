package org.cloudfoundry.identity.uaa.oauth.provider.config.xml;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Moved test class of from spring-security-oauth2 into UAA
 * Scope: Test class
 */
class OAuth2SecurityNamespaceHandlerTest {

    @Test
    void init() {
        OAuth2SecurityNamespaceHandler oAuth2SecurityNamespaceHandler = new OAuth2SecurityNamespaceHandler();
        oAuth2SecurityNamespaceHandler.init();
        assertThat(oAuth2SecurityNamespaceHandler).isNotNull();
    }
}
