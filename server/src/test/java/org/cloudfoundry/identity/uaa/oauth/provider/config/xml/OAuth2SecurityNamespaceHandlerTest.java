package org.cloudfoundry.identity.uaa.oauth.provider.config.xml;

import org.junit.Test;

import static org.junit.Assert.*;

/**
 * Moved test class of from spring-security-oauth2 into UAA
 * Scope: Test class
 */
public class OAuth2SecurityNamespaceHandlerTest {

    @Test
    public void init() {
        OAuth2SecurityNamespaceHandler oAuth2SecurityNamespaceHandler = new OAuth2SecurityNamespaceHandler();
        oAuth2SecurityNamespaceHandler.init();
        assertNotNull(oAuth2SecurityNamespaceHandler);
    }
}
