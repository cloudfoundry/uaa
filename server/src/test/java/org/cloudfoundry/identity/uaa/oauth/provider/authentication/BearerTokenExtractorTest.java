package org.cloudfoundry.identity.uaa.oauth.provider.authentication;

import org.cloudfoundry.identity.uaa.oauth.common.OAuth2AccessToken;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Moved test class of from spring-security-oauth2 into UAA
 * Scope: Test class
 */
class BearerTokenExtractorTest {

    private BearerTokenExtractor extractor;
    private MockHttpServletRequest request;

    @BeforeEach
    void setUp() throws Exception {
        extractor = new BearerTokenExtractor();
        request = new MockHttpServletRequest();
    }

    @Test
    void extract() {
        request.setParameter(OAuth2AccessToken.ACCESS_TOKEN, "token");
        assertThat(extractor.extract(request)).isNotNull();
    }

    @Test
    void extractNoToken() {
        assertThat(extractor.extract(request)).isNull();
    }

    @Test
    void extractHeaderToken() {
        request.addHeader("Authorization", "Bearer token,token");
        assertThat(extractor.extract(request)).isNotNull();
    }

    @Test
    void extractNoHeaderToken() {
        request.addHeader("Authorization", "nothing");
        assertThat(extractor.extract(request)).isNull();
    }
}