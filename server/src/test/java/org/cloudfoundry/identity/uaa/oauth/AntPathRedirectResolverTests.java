/*
 * *****************************************************************************
 *      Cloud Foundry
 *      Copyright (c) [2009-2015] Pivotal Software, Inc. All Rights Reserved.
 *
 *      This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *      You may not use this product except in compliance with the License.
 *
 *      This product includes a number of subcomponents with
 *      separate copyright notices and license terms. Your use of these
 *      subcomponents is subject to the terms and conditions of the
 *      subcomponent's license, as noted in the LICENSE file.
 * *****************************************************************************
 */

package org.cloudfoundry.identity.uaa.oauth;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.common.exceptions.RedirectMismatchException;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;

import java.util.Collections;
import java.util.HashSet;

import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_AUTHORIZATION_CODE;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.Assert.*;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class AntPathRedirectResolverTests {

    private final AntPathRedirectResolver resolver = new AntPathRedirectResolver();

    @Nested
    @DisplayName("matching http://domain.com")
    class WhenMatchingAgainstJustTLD {
        private final String clientRedirectUri = "http://domain.com";

        @Test
        void allSubdomainsShouldMatch() {
            assertTrue(resolver.redirectMatches("http://subdomain.domain.com", clientRedirectUri));
            assertTrue(resolver.redirectMatches("http://another-subdomain.domain.com", clientRedirectUri));
            assertTrue(resolver.redirectMatches("http://one.two.domain.com", clientRedirectUri));
        }

        @Test
        void allPathsShouldMatch() {
            assertTrue(resolver.redirectMatches("http://domain.com/one", clientRedirectUri));
            assertTrue(resolver.redirectMatches("http://domain.com/another", clientRedirectUri));
            assertTrue(resolver.redirectMatches("http://domain.com/one/two", clientRedirectUri));
        }

        @Test
        void allPathsInAnySubdomainShouldMatch() {
            assertTrue(resolver.redirectMatches("http://subdomain.domain.com/one", clientRedirectUri));
            assertTrue(resolver.redirectMatches("http://subdomain.domain.com/another", clientRedirectUri));
            assertTrue(resolver.redirectMatches("http://subdomain.domain.com/one/two", clientRedirectUri));

            assertTrue(resolver.redirectMatches("http://another-subdomain.domain.com/one", clientRedirectUri));
            assertTrue(resolver.redirectMatches("http://another-subdomain.domain.com/another", clientRedirectUri));
            assertTrue(resolver.redirectMatches("http://another-subdomain.domain.com/one/two", clientRedirectUri));

            assertTrue(resolver.redirectMatches("http://one.two.domain.com/one", clientRedirectUri));
            assertTrue(resolver.redirectMatches("http://one.two.domain.com/another", clientRedirectUri));
            assertTrue(resolver.redirectMatches("http://one.two.domain.com/one/two", clientRedirectUri));
        }

        @Test
        void doesNotMatchDifferentTld() {
            assertFalse(resolver.redirectMatches("http://other-domain.com", clientRedirectUri));
            assertFalse(resolver.redirectMatches("http://domain.io", clientRedirectUri));
        }
        
        @Test
        void doesNotMatchDifferentProtocol() {
            assertFalse(resolver.redirectMatches("https://domain.com", clientRedirectUri));
            assertFalse(resolver.redirectMatches("ws://domain.com", clientRedirectUri));
        }
    }

    @Nested
    @DisplayName("matching http://domain.com/*")
    class WhenMatchingWithSinglePathPattern {
        private final String clientRedirectUri = "http://domain.com/*";

        @Test
        void shouldNotMatchSubdomains() {
            assertFalse(resolver.redirectMatches("http://subdomain.domain.com", clientRedirectUri));
            assertFalse(resolver.redirectMatches("http://another-subdomain.domain.com", clientRedirectUri));
            assertFalse(resolver.redirectMatches("http://one.two.domain.com", clientRedirectUri));
        }

        @Test
        void allPathsShouldMatch() {
            assertTrue(resolver.redirectMatches("http://domain.com/one", clientRedirectUri));
            assertTrue(resolver.redirectMatches("http://domain.com/another", clientRedirectUri));
            assertFalse(resolver.redirectMatches("http://domain.com/one/two", clientRedirectUri));
        }

        @Test
        void shouldNotMatchSubdomainsWithPaths() {
            assertFalse(resolver.redirectMatches("http://subdomain.domain.com/one", clientRedirectUri));
            assertFalse(resolver.redirectMatches("http://subdomain.domain.com/another", clientRedirectUri));
            assertFalse(resolver.redirectMatches("http://subdomain.domain.com/one/two", clientRedirectUri));

            assertFalse(resolver.redirectMatches("http://another-subdomain.domain.com/one", clientRedirectUri));
            assertFalse(resolver.redirectMatches("http://another-subdomain.domain.com/another", clientRedirectUri));
            assertFalse(resolver.redirectMatches("http://another-subdomain.domain.com/one/two", clientRedirectUri));

            assertFalse(resolver.redirectMatches("http://one.two.domain.com/one", clientRedirectUri));
            assertFalse(resolver.redirectMatches("http://one.two.domain.com/another", clientRedirectUri));
            assertFalse(resolver.redirectMatches("http://one.two.domain.com/one/two", clientRedirectUri));
        }

        @Test
        void doesNotMatchDifferentTld() {
            assertFalse(resolver.redirectMatches("http://other-domain.com", clientRedirectUri));
            assertFalse(resolver.redirectMatches("http://domain.io", clientRedirectUri));
        }

        @Test
        void doesNotMatchDifferentProtocol() {
            assertFalse(resolver.redirectMatches("https://domain.com", clientRedirectUri));
            assertFalse(resolver.redirectMatches("ws://domain.com", clientRedirectUri));
        }
    }

    @Nested
    @DisplayName("matching http://domain.com/**")
    class WhenMatchingWithAllSubPathsPattern {
        private final String clientRedirectUri = "http://domain.com/**";

        @Test
        void shouldNotMatchSubdomains() {
            assertFalse(resolver.redirectMatches("http://subdomain.domain.com", clientRedirectUri));
            assertFalse(resolver.redirectMatches("http://another-subdomain.domain.com", clientRedirectUri));
            assertFalse(resolver.redirectMatches("http://one.two.domain.com", clientRedirectUri));
        }

        @Test
        void allPathsShouldMatch() {
            assertTrue(resolver.redirectMatches("http://domain.com/one", clientRedirectUri));
            assertTrue(resolver.redirectMatches("http://domain.com/another", clientRedirectUri));
            assertTrue(resolver.redirectMatches("http://domain.com/one/two", clientRedirectUri));
        }

        @Test
        void shouldNotMatchSubdomainsWithPaths() {
            assertFalse(resolver.redirectMatches("http://subdomain.domain.com/one", clientRedirectUri));
            assertFalse(resolver.redirectMatches("http://subdomain.domain.com/another", clientRedirectUri));
            assertFalse(resolver.redirectMatches("http://subdomain.domain.com/one/two", clientRedirectUri));

            assertFalse(resolver.redirectMatches("http://another-subdomain.domain.com/one", clientRedirectUri));
            assertFalse(resolver.redirectMatches("http://another-subdomain.domain.com/another", clientRedirectUri));
            assertFalse(resolver.redirectMatches("http://another-subdomain.domain.com/one/two", clientRedirectUri));

            assertFalse(resolver.redirectMatches("http://one.two.domain.com/one", clientRedirectUri));
            assertFalse(resolver.redirectMatches("http://one.two.domain.com/another", clientRedirectUri));
            assertFalse(resolver.redirectMatches("http://one.two.domain.com/one/two", clientRedirectUri));
        }

        @Test
        void doesNotMatchDifferentTld() {
            assertFalse(resolver.redirectMatches("http://other-domain.com", clientRedirectUri));
            assertFalse(resolver.redirectMatches("http://domain.io", clientRedirectUri));
        }

        @Test
        void doesNotMatchDifferentProtocol() {
            assertFalse(resolver.redirectMatches("https://domain.com", clientRedirectUri));
            assertFalse(resolver.redirectMatches("ws://domain.com", clientRedirectUri));
        }
    }

    @Nested
    @DisplayName("redirectMatches")
    class RedirectMatches {

        private final String requestedRedirectHttp  = "http://subdomain.domain.com/path1/path2?query1=value1&query2=value2";
        private final String requestedRedirectHttps = "https://subdomain.domain.com/path1/path2?query1=value1&query2=value2";

        @Test
        void trailingSlash() {
            final String clientRedirectUri = "http://subdomain.domain.com/";

            assertTrue(resolver.redirectMatches("http://subdomain.domain.com/", clientRedirectUri));
            assertTrue(resolver.redirectMatches("http://subdomain.domain.com/one", clientRedirectUri));
            assertTrue(resolver.redirectMatches("http://subdomain.domain.com/one/", clientRedirectUri));
            assertTrue(resolver.redirectMatches("http://subdomain.domain.com/one/two", clientRedirectUri));
            assertTrue(resolver.redirectMatches("http://subdomain.domain.com/one/two/three", clientRedirectUri));
        }

        @Test
        void trailingPath() {
            final String clientRedirectUri = "http://subdomain.domain.com/one";

            assertFalse(resolver.redirectMatches("http://subdomain.domain.com/", clientRedirectUri));
            assertTrue(resolver.redirectMatches("http://subdomain.domain.com/one", clientRedirectUri));
            assertTrue(resolver.redirectMatches("http://subdomain.domain.com/one/", clientRedirectUri));
            assertTrue(resolver.redirectMatches("http://subdomain.domain.com/one/two", clientRedirectUri));
            assertTrue(resolver.redirectMatches("http://subdomain.domain.com/one/two/three", clientRedirectUri));
        }

        @Test
        void singleTrailingAsterisk() {
            final String clientRedirectUri = "http://subdomain.domain.com/*";

            assertTrue(resolver.redirectMatches("http://subdomain.domain.com/", clientRedirectUri));
            assertTrue(resolver.redirectMatches("http://subdomain.domain.com/one", clientRedirectUri));
            assertFalse(resolver.redirectMatches("http://subdomain.domain.com/one/", clientRedirectUri));
            assertFalse(resolver.redirectMatches("http://subdomain.domain.com/one/two", clientRedirectUri));
            assertFalse(resolver.redirectMatches("http://subdomain.domain.com/one/two/three", clientRedirectUri));
        }

        @Test
        void singleTrailingAsterisk_withPath() {
            final String clientRedirectUri = "http://subdomain.domain.com/one*";

            assertFalse(resolver.redirectMatches("http://subdomain.domain.com/", clientRedirectUri));
            assertTrue(resolver.redirectMatches("http://subdomain.domain.com/one", clientRedirectUri));
            assertTrue(resolver.redirectMatches("http://subdomain.domain.com/one-foo-bar", clientRedirectUri));
            assertFalse(resolver.redirectMatches("http://subdomain.domain.com/one/", clientRedirectUri));
            assertFalse(resolver.redirectMatches("http://subdomain.domain.com/one/two", clientRedirectUri));
            assertFalse(resolver.redirectMatches("http://subdomain.domain.com/one/two/three", clientRedirectUri));
        }

        @Test
        void singleAsterisk_insidePath() {
            String clientRedirectUri = "http://subdomain.domain.com/one/*/four";

            assertFalse(resolver.redirectMatches("http://subdomain.domain.com/one/four", clientRedirectUri));
            assertTrue(resolver.redirectMatches("http://subdomain.domain.com/one/middle/four", clientRedirectUri));
            assertFalse(resolver.redirectMatches("http://subdomain.domain.com/one/two/three/four", clientRedirectUri));
        }

        @Test
        void matchesEverything() {
            String clientRedirectUri = "**";

            assertTrue(resolver.redirectMatches(requestedRedirectHttp, clientRedirectUri));
            assertTrue(resolver.redirectMatches(requestedRedirectHttps, clientRedirectUri));
        }

        @Test
        void matchesSchemeWildcard() {
            String clientRedirectUri = "http*://subdomain.domain.com/**";

            assertTrue(resolver.redirectMatches(requestedRedirectHttp, clientRedirectUri));
            assertTrue(resolver.redirectMatches(requestedRedirectHttps, clientRedirectUri));
        }

        @Test
        void matchesSchemeHttp() {
            String clientRedirectUri = "http://subdomain.domain.com/**";

            assertTrue(resolver.redirectMatches(requestedRedirectHttp, clientRedirectUri));
            assertFalse(resolver.redirectMatches(requestedRedirectHttps, clientRedirectUri));
        }

        @Test
        void matchesSchemeHttps() {
            String clientRedirectUri = "https://subdomain.domain.com/**";

            assertFalse(resolver.redirectMatches(requestedRedirectHttp, clientRedirectUri));
            assertTrue(resolver.redirectMatches(requestedRedirectHttps, clientRedirectUri));
        }

        @Test
        void matchesPathContainingAntPathMatcher() {
            String clientRedirectUri = "http*://subdomain.domain.com/path1/path2**";

            assertTrue(resolver.redirectMatches(requestedRedirectHttp, clientRedirectUri));
            assertTrue(resolver.redirectMatches(requestedRedirectHttps, clientRedirectUri));

            clientRedirectUri = "http*://subdomain.domain.com/path1/<invalid>**";

            assertFalse(resolver.redirectMatches(requestedRedirectHttp, clientRedirectUri));
            assertFalse(resolver.redirectMatches(requestedRedirectHttps, clientRedirectUri));
        }

        @Test
        void matchesHashFragments() {
            assertTrue(resolver.redirectMatches("http://uaa.com/#fragment", "http://uaa.com"));
        }

        @Test
        void redirect_Subdomain() {
            String clientRedirectUri = "http*://*.domain.com/path1/path2**";

            assertTrue(resolver.redirectMatches(requestedRedirectHttps, clientRedirectUri));
            assertTrue(resolver.redirectMatches(requestedRedirectHttp, clientRedirectUri));

            clientRedirectUri = "http*://*.domain.com/path1/<invalid>**";

            assertFalse(resolver.redirectMatches(requestedRedirectHttps, clientRedirectUri));
            assertFalse(resolver.redirectMatches(requestedRedirectHttp, clientRedirectUri));
        }

    }

    @Nested
    @DisplayName("resolveRedirect")
    class ResolveRedirect {

        ClientDetails mockClientDetails;

        @BeforeEach
        void setUp() {
            mockClientDetails = mock(BaseClientDetails.class);
            when(mockClientDetails.getAuthorizedGrantTypes()).thenReturn(Collections.singleton(GRANT_TYPE_AUTHORIZATION_CODE));
        }

        @Test
        void clientWithValidRedirectUri_shouldResolve() {
            when(mockClientDetails.getRegisteredRedirectUri()).thenReturn(Collections.singleton("http://uaa.com"));

            String resolvedRedirect = resolver.resolveRedirect("http://uaa.com", mockClientDetails);
            assertThat(resolvedRedirect, equalTo("http://uaa.com"));
        }

        @Test
        void clientMissingRedirectUri() {
            when(mockClientDetails.getRegisteredRedirectUri()).thenReturn(new HashSet<>());

            RedirectMismatchException exception = assertThrows(RedirectMismatchException.class,
                    () -> resolver.resolveRedirect("http://somewhere.com", mockClientDetails));

            assertThat(exception.getMessage(), containsString("Client registration is missing redirect_uri"));
        }

        @Test
        void clientWithInvalidRedirectUri() {
            when(mockClientDetails.getRegisteredRedirectUri()).thenReturn(Collections.singleton("*, */*"));

            RedirectMismatchException exception = assertThrows(RedirectMismatchException.class,
                    () -> resolver.resolveRedirect("http://somewhere.com", mockClientDetails));

            assertThat(exception.getMessage(), containsString("Client registration contains invalid redirect_uri"));
            assertThat(exception.getMessage(), containsString("*, */*"));
        }

    }

}
