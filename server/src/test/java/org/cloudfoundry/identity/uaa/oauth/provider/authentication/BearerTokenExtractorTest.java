package org.cloudfoundry.identity.uaa.oauth.provider.authentication;

import org.cloudfoundry.identity.uaa.oauth.common.OAuth2AccessToken;
import org.junit.Before;
import org.junit.Test;
import org.springframework.mock.web.MockHttpServletRequest;

import static org.junit.Assert.*;

/**
 * Moved test class of from spring-security-oauth2 into UAA
 * Scope: Test class
 */
public class BearerTokenExtractorTest {

    private BearerTokenExtractor extractor;
    private MockHttpServletRequest request;

    @Before
    public void setUp() throws Exception {
        extractor = new BearerTokenExtractor();
        request = new MockHttpServletRequest();
    }

    @Test
    public void extract() {
        request.setParameter(OAuth2AccessToken.ACCESS_TOKEN, "token");
        assertNotNull(extractor.extract(request));
    }

    @Test
    public void extractNoToken() {
        assertNull(extractor.extract(request));
    }

    @Test
    public void extractHeaderToken() {
        request.addHeader("Authorization", "Bearer token,token");
        assertNotNull(extractor.extract(request));
    }

    @Test
    public void extractNoHeaderToken() {
        request.addHeader("Authorization", "nothing");
        assertNull(extractor.extract(request));
    }
}