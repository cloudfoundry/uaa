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

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.common.exceptions.RedirectMismatchException;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;

import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_AUTHORIZATION_CODE;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.Assert.*;
import static org.junit.jupiter.api.Assertions.assertThrows;

public class AntPathRedirectResolverTests {

    private final String requestedRedirectHttp  = "http://subdomain.domain.com/path1/path2?query1=value1&query2=value2";
    private final String requestedRedirectHttps = "https://subdomain.domain.com/path1/path2?query1=value1&query2=value2";
    private final AntPathRedirectResolver resolver = new AntPathRedirectResolver();

    @Nested
    class WhenMatchingAgainstJustTLD {
        private final String clientRedirectUri = "http://domain.com";

        @Test
        public void allSubdomainsShouldMatch() {
            assertTrue(resolver.redirectMatches("http://subdomain.domain.com", clientRedirectUri));
            assertTrue(resolver.redirectMatches("http://another-subdomain.domain.com", clientRedirectUri));
            assertTrue(resolver.redirectMatches("http://one.two.domain.com", clientRedirectUri));
        }

        @Test
        public void allPathsShouldMatch() {
            assertTrue(resolver.redirectMatches("http://domain.com/one", clientRedirectUri));
            assertTrue(resolver.redirectMatches("http://domain.com/another", clientRedirectUri));
            assertTrue(resolver.redirectMatches("http://domain.com/one/two", clientRedirectUri));
        }

        @Test
        public void allPathsInAnySubdomainShouldMatch() {
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
        public void doesNotMatchDifferentTld() {
            assertFalse(resolver.redirectMatches("http://other-domain.com", clientRedirectUri));
            assertFalse(resolver.redirectMatches("http://domain.io", clientRedirectUri));
        }
        
        @Test
        public void doesNotMatchDifferentProtocol() {
            assertFalse(resolver.redirectMatches("https://domain.com", clientRedirectUri));
            assertFalse(resolver.redirectMatches("ws://domain.com", clientRedirectUri));
        }
    }

    @Nested
    class WhenMatchingWithSinglePathPattern {
        private final String clientRedirectUri = "http://domain.com/*";

        @Test
        public void shouldNotMatchSubdomains() {
            assertFalse(resolver.redirectMatches("http://subdomain.domain.com", clientRedirectUri));
            assertFalse(resolver.redirectMatches("http://another-subdomain.domain.com", clientRedirectUri));
            assertFalse(resolver.redirectMatches("http://one.two.domain.com", clientRedirectUri));
        }

        @Test
        public void allPathsShouldMatch() {
            assertTrue(resolver.redirectMatches("http://domain.com/one", clientRedirectUri));
            assertTrue(resolver.redirectMatches("http://domain.com/another", clientRedirectUri));
            assertFalse(resolver.redirectMatches("http://domain.com/one/two", clientRedirectUri));
        }

        @Test
        public void shouldNotMatchSubdomainsWithPaths() {
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
        public void doesNotMatchDifferentTld() {
            assertFalse(resolver.redirectMatches("http://other-domain.com", clientRedirectUri));
            assertFalse(resolver.redirectMatches("http://domain.io", clientRedirectUri));
        }

        @Test
        public void doesNotMatchDifferentProtocol() {
            assertFalse(resolver.redirectMatches("https://domain.com", clientRedirectUri));
            assertFalse(resolver.redirectMatches("ws://domain.com", clientRedirectUri));
        }
    }

    @Nested
    class WhenMatchingWithAllSubPathsPattern {
        private final String clientRedirectUri = "http://domain.com/**";

        @Test
        public void shouldNotMatchSubdomains() {
            assertFalse(resolver.redirectMatches("http://subdomain.domain.com", clientRedirectUri));
            assertFalse(resolver.redirectMatches("http://another-subdomain.domain.com", clientRedirectUri));
            assertFalse(resolver.redirectMatches("http://one.two.domain.com", clientRedirectUri));
        }

        @Test
        public void allPathsShouldMatch() {
            assertTrue(resolver.redirectMatches("http://domain.com/one", clientRedirectUri));
            assertTrue(resolver.redirectMatches("http://domain.com/another", clientRedirectUri));
            assertTrue(resolver.redirectMatches("http://domain.com/one/two", clientRedirectUri));
        }

        @Test
        public void shouldNotMatchSubdomainsWithPaths() {
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
        public void doesNotMatchDifferentTld() {
            assertFalse(resolver.redirectMatches("http://other-domain.com", clientRedirectUri));
            assertFalse(resolver.redirectMatches("http://domain.io", clientRedirectUri));
        }

        @Test
        public void doesNotMatchDifferentProtocol() {
            assertFalse(resolver.redirectMatches("https://domain.com", clientRedirectUri));
            assertFalse(resolver.redirectMatches("ws://domain.com", clientRedirectUri));
        }
    }

    @Nested
    @DisplayName("redirectMatches")
    class RedirectMatches {
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
        void redirect_Matches_Happy_Day() {
            String clientRedirectUri = "**";

            assertTrue(resolver.redirectMatches(requestedRedirectHttp, clientRedirectUri));
            assertTrue(resolver.redirectMatches(requestedRedirectHttps, clientRedirectUri));
        }

        @Test
        void redirect_Any_Scheme() {
            String clientRedirectUri = "http*://subdomain.domain.com/**";

            assertTrue(resolver.redirectMatches(requestedRedirectHttp, clientRedirectUri));
            assertTrue(resolver.redirectMatches(requestedRedirectHttps, clientRedirectUri));
        }

        @Test
        void redirect_Http_Only_Scheme() {
            String clientRedirectUri = "http://subdomain.domain.com/**";

            assertTrue(resolver.redirectMatches(requestedRedirectHttp, clientRedirectUri));
            assertFalse(resolver.redirectMatches(requestedRedirectHttps, clientRedirectUri));
        }

        @Test
        void redirect_Https_Only_Scheme() {
            String clientRedirectUri = "https://subdomain.domain.com/**";

            assertFalse(resolver.redirectMatches(requestedRedirectHttp, clientRedirectUri));
            assertTrue(resolver.redirectMatches(requestedRedirectHttps, clientRedirectUri));
        }

        @Test
        void redirect_Query_Path() {
            String clientRedirectUri = "http*://subdomain.domain.com/path1/path2**";

            assertTrue(resolver.redirectMatches(requestedRedirectHttp, clientRedirectUri));
            assertTrue(resolver.redirectMatches(requestedRedirectHttps, clientRedirectUri));

            clientRedirectUri = "http*://subdomain.domain.com/path1/<invalid>**";

            assertFalse(resolver.redirectMatches(requestedRedirectHttp, clientRedirectUri));
            assertFalse(resolver.redirectMatches(requestedRedirectHttps, clientRedirectUri));
        }

        @Test
        public void redirect_withHashFragments() {
            String clientRedirectUri = "http://test.example.org/redirect";

            assertTrue(resolver.redirectMatches(clientRedirectUri + "#fragment", clientRedirectUri));
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

        @Test
        void clientWithValidRedirectUri_shouldResolve() {
            ClientDetails clientDetails = new BaseClientDetails("client1", "", "openid", GRANT_TYPE_AUTHORIZATION_CODE, "", requestedRedirectHttp);
            String resolvedRedirect = resolver.resolveRedirect(requestedRedirectHttp, clientDetails);
            assertThat(resolvedRedirect, equalTo(requestedRedirectHttp));
        }

        @Test
        void clientMissingRedirectUri() {
            ClientDetails clientDetails = new BaseClientDetails("client1", "", "openid", GRANT_TYPE_AUTHORIZATION_CODE, "");

            RedirectMismatchException exception = assertThrows(RedirectMismatchException.class,
                    () -> resolver.resolveRedirect(requestedRedirectHttp, clientDetails));

            assertThat(exception.getMessage(), containsString("Client registration is missing redirect_uri"));
        }

        @Test
        void clientWithInvalidRedirectUri() {
            ClientDetails clientDetails = new BaseClientDetails("client1", "", "openid", GRANT_TYPE_AUTHORIZATION_CODE, "", "*, */*");

            RedirectMismatchException exception = assertThrows(RedirectMismatchException.class,
                    () -> resolver.resolveRedirect(requestedRedirectHttp, clientDetails));

            assertThat(exception.getMessage(), containsString("Client registration contains invalid redirect_uri"));
            assertThat(exception.getMessage(), containsString("*,  */*"));
        }

    }

}
