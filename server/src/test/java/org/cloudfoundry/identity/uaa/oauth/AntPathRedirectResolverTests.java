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

import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.core.LogEvent;
import org.apache.logging.log4j.core.LoggerContext;
import org.apache.logging.log4j.core.appender.AbstractAppender;
import org.hamcrest.Description;
import org.hamcrest.Matcher;
import org.hamcrest.TypeSafeMatcher;
import org.junit.jupiter.api.*;
import org.springframework.security.oauth2.common.exceptions.RedirectMismatchException;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;

import java.util.*;

import static com.google.common.collect.Lists.newArrayList;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_AUTHORIZATION_CODE;
import static org.hamcrest.Matchers.*;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.apache.logging.log4j.Level.WARN;

class AntPathRedirectResolverTests {

    private final AntPathRedirectResolver resolver = new AntPathRedirectResolver();

    private static ClientDetails createClient(String id, String... redirectUris) {
        BaseClientDetails clientDetails = new BaseClientDetails();
        clientDetails.setClientId(id);
        clientDetails.setAuthorizedGrantTypes(Collections.singleton(GRANT_TYPE_AUTHORIZATION_CODE));
        clientDetails.setRegisteredRedirectUri(new HashSet<>(Arrays.asList(redirectUris)));

        return clientDetails;
    }

    private static String expectedWarning(String clientId, String configured, String requested) {
        return String.format(AntPathRedirectResolver.MSG_TEMPLATE, clientId, configured, requested);
    }

    private static Matcher<LogEvent> warning(String msg) {
        return new LogEventMatcher(WARN, msg, "a warning about implicit redirect matching");
    }

    private static class LogEventMatcher extends TypeSafeMatcher<LogEvent> {
        private Level level;
        private Matcher<String> msgMatcher;
        private String matchFail;

        LogEventMatcher(Level level, String msg, String matchFail) {
            this.level = level;
            this.msgMatcher = is(msg);
            this.matchFail = matchFail;
        }

        @Override
        protected boolean matchesSafely(LogEvent event) {
            return event.getLevel().equals(level) && msgMatcher.matches(event.getMessage().getFormattedMessage());
        }

        @Override
        public void describeTo(Description description) {
            description.appendText(matchFail);
        }
    }

    @Nested
    class WithCapturedLogs {
        private List<LogEvent> logEvents;
        private AbstractAppender appender;

        @BeforeEach
        void setupLogger() {
            logEvents = new ArrayList<>();
            appender = new AbstractAppender("", null, null) {
                @Override
                public void append(LogEvent event) {
                    logEvents.add(event);
                }
            };
            appender.start();

            LoggerContext context = (LoggerContext) LogManager.getContext(false);
            context.getRootLogger().addAppender(appender);
        }

        @AfterEach
        void removeAppender() {
            LoggerContext context = (LoggerContext) LogManager.getContext(false);
            context.getRootLogger().removeAppender(appender);
        }

        @Test
        void warnsOnImplicitDomainExpansion() {
            final String configuredUri = "https://example.com";
            final String requestedUri = "https://subdomain.example.com";
            ClientDetails client = createClient("foo", configuredUri);

            resolver.resolveRedirect(requestedUri, client);
            assertThat(logEvents, hasItem(
                warning(expectedWarning(client.getClientId(), configuredUri, requestedUri)))
            );
        }

        @Test
        void warnsOnImplicitMultipleDomainExpansion() {
            final String configuredUri = "https://example.com";
            final String requestedUri = "https://another.subdomain.example.com";
            ClientDetails client = createClient("foo", configuredUri);

            resolver.resolveRedirect(requestedUri, client);
            assertThat(logEvents, hasItem(
                    warning(expectedWarning(client.getClientId(), configuredUri, requestedUri)))
            );
        }

        @Test
        void doesNotWarnOnExplicitDomainExpansion() {
            final String configuredRedirectUri = "https://*.example.com";
            final String requestedRedirectUri = "https://subdomain.example.com";
            ClientDetails clientDetails = createClient("foo", configuredRedirectUri);

            resolver.resolveRedirect(requestedRedirectUri, clientDetails);
            assertThat(logEvents, empty());
        }

        @Test
        void warnsOnImplicitPathExpansion() {
            final String configuredRedirectUri = "https://example.com/";
            final String requestedRedirectUri = "https://example.com/path";
            ClientDetails clientDetails = createClient("foo", configuredRedirectUri);

            resolver.resolveRedirect(requestedRedirectUri, clientDetails);
            assertThat(logEvents, hasItem(warning(expectedWarning(clientDetails.getClientId(), configuredRedirectUri, requestedRedirectUri))));
        }

        @Test
        void warnsOnImplicitMultiplePathExpansion() {
            final String configuredRedirectUri = "https://example.com/";
            final String requestedRedirectUri = "https://example.com/some/path";
            ClientDetails clientDetails = createClient("foo", configuredRedirectUri);

            resolver.resolveRedirect(requestedRedirectUri, clientDetails);
            assertThat(logEvents, hasItem(warning(expectedWarning(clientDetails.getClientId(), configuredRedirectUri, requestedRedirectUri))));
        }

        @Test
        void doesNotWarnOnExplicitPathExpansion() {
            final String configuredRedirectUri = "https://example.com/*";
            final String requestedRedirectUri = "https://example.com/path";
            ClientDetails clientDetails = createClient("foo", configuredRedirectUri);

            resolver.resolveRedirect(requestedRedirectUri, clientDetails);
            assertThat(logEvents, empty());
        }

        @Test
        void warnsOnPotentialImplicitWildcardMatch() {
            final String configuredExplicitRedirectUri = "https://*.example.com/";
            final String configuredImplicitRedirectUri = "https://example.com/";
            final String requestedRedirectUri = "https://an.example.com/";

            // the explicit redirect uri will match first, but we should still log
            ClientDetails clientDetails = createClient("foo", configuredExplicitRedirectUri, configuredImplicitRedirectUri);

            resolver.resolveRedirect(requestedRedirectUri, clientDetails);
            assertThat(logEvents, hasItem(warning(expectedWarning(clientDetails.getClientId(), configuredImplicitRedirectUri, requestedRedirectUri))));
        }

        @Test
        void redactsQueryParameterValues() {
            final String configuredRedirectUri = "https://example.com/";
            final String requestedRedirectUri = "https://example.com/path?foo=bar&foo=1234&baz=qux";

            ClientDetails client = createClient("foo", configuredRedirectUri);

            resolver.resolveRedirect(requestedRedirectUri, client);

            assertThat(logEvents, hasItem(
                warning(expectedWarning(client.getClientId(), configuredRedirectUri, "https://example.com/path?foo=REDACTED&foo=REDACTED&baz=REDACTED")))
            );
        }

        @Test
        void redactsHashFragment() {
            final String configuredRedirectUri = "https://example.com/";
            final String requestedRedirectUri = "https://example.com/#IAmAHash";

            ClientDetails client = createClient("front-end-app", configuredRedirectUri);

            resolver.resolveRedirect(requestedRedirectUri, client);

            assertThat(logEvents, hasItem(
                warning(expectedWarning(client.getClientId(), configuredRedirectUri, "https://example.com/#REDACTED")))
            );
        }

        @Test
        void warnsOnImplicitAuthorizationExpansion() {
            final String configuredRedirectUri = "https://example.com/";
            final String requestedRedirectUri = "https://user:pass@example.com/";

            ClientDetails client = createClient("myAppIsCool", configuredRedirectUri);

            resolver.resolveRedirect(requestedRedirectUri, client);

            assertThat(logEvents, hasItem(
                warning(expectedWarning(client.getClientId(), configuredRedirectUri, "https://REDACTED:REDACTED@example.com/")))
            );
        }

        @Test
        void doesNotWarnForExactMatch() {
            final String configuredRedirectUri = "https://example.com/";
            final String requestedRedirectUri = "https://example.com/";

            ClientDetails client = createClient("foo", configuredRedirectUri);

            resolver.resolveRedirect(requestedRedirectUri, client);

            assertThat(logEvents, empty());
        }

        @Test
        void doesNotWarnForPortExpansion() {
            final String configuredRedirectUri = "https://example.com/";
            final String requestedRedirectUri = "https://example.com:65000/";

            ClientDetails client = createClient("foo", configuredRedirectUri);

            assertThrows(RedirectMismatchException.class,
                    () -> resolver.resolveRedirect(requestedRedirectUri, client));

            assertThat(logEvents, empty());
        }
    }

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

        private final String requestedRedirectHttp = "http://subdomain.domain.com/path1/path2?query1=value1&query2=value2";
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
        void redirectSubdomain() {
            String clientRedirectUri = "http*://*.domain.com/path1/path2**";

            assertTrue(resolver.redirectMatches(requestedRedirectHttps, clientRedirectUri));
            assertTrue(resolver.redirectMatches(requestedRedirectHttp, clientRedirectUri));

            clientRedirectUri = "http*://*.domain.com/path1/<invalid>**";

            assertFalse(resolver.redirectMatches(requestedRedirectHttps, clientRedirectUri));
            assertFalse(resolver.redirectMatches(requestedRedirectHttp, clientRedirectUri));
        }

        @Test
        void redirectSupportsMultipleSubdomainWildcards() {
            String clientRedirectUri = "http://*.*.domain.com/";
            assertTrue(resolver.redirectMatches("http://sub1.sub2.domain.com/", clientRedirectUri));
        }

        @Test
        void subdomainMatchingRejectsDomainRedirectOnWildcardSubdomain() {
            String clientRedirectUri = "http://*.domain.com/";
            assertFalse(resolver.redirectMatches("http://other-domain.com?stuff.domain.com/", clientRedirectUri));
        }

        @Test
        void subdomainMatchingRejectsDomainRedirectOnMultilevelWildcardSubdomain() {
            String clientRedirectUri = "http://**.domain.com/";
            assertFalse(resolver.redirectMatches("http://other-domain.com?stuff.domain.com/", clientRedirectUri));
        }

        @Test
        void subdomainMatchingRejectsDomainRedirectOnWildcardSuffixedSubdomain() {
            String clientRedirectUri = "http://sub*.example.com";
            assertFalse(resolver.redirectMatches("http://sub.other-domain.com?stuff.example.com", clientRedirectUri));
        }

        @Test
        void subdomainMatchingDoesNotBlowUpWhenRequestedRedirectIsShorterThanConfiguredRedirect() {
            String clientRedirectUri = "http://sub*.domain.com/";
            assertFalse(resolver.redirectMatches("http://domain.com/", clientRedirectUri));
        }

        @Test
        void subdomainMatchingOnWildcardSubdomainWithBasicAuth() {
            String clientRedirectUri = "http://u:p@*.domain.com/";
            assertTrue(resolver.redirectMatches("http://u:p@sub.domain.com/", clientRedirectUri));
        }

        @Test
        void matchesHostsWithPort() {
            String clientRedirectUri = "http://*.domain.com:8080/";
            assertTrue(resolver.redirectMatches("http://any.domain.com:8080/", clientRedirectUri));
        }

        @Test
        void subdomainMatchingRejectsDomainRedirectOnAntPathVariableSubdomain() {
            String clientRedirectUri = "http://{foo:.*}.domain.com/";
            assertFalse(resolver.redirectMatches("http://other-domain.com?stuff.domain.com/", clientRedirectUri));
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
        void clientMissingRedirectUri() {
            when(mockClientDetails.getRegisteredRedirectUri()).thenReturn(new HashSet<>());

            RedirectMismatchException exception = assertThrows(RedirectMismatchException.class,
                    () -> resolver.resolveRedirect("http://somewhere.com", mockClientDetails));

            assertThat(exception.getMessage(), containsString("Client registration is missing redirect_uri"));
        }

        @Test
        void clientWithInvalidRedirectUri() {
            final String invalidRedirectUri = "*, */*";
            mockRegisteredRedirectUri(invalidRedirectUri);

            RedirectMismatchException exception = assertThrows(RedirectMismatchException.class,
                    () -> resolver.resolveRedirect("http://somewhere.com", mockClientDetails));

            assertThat(exception.getMessage(), containsString("Client registration contains invalid redirect_uri"));
            assertThat(exception.getMessage(), containsString(invalidRedirectUri));
        }

        @Test
        void testResolveClientWithUrlWhichHasNoWildcardsAndDoesNotEndInSlash() {
            mockRegisteredRedirectUri("http://uaa.com");

            assertResolveRedirectReturnsSameUrl("http://uaa.com");
            assertResolveRedirectReturnsSameUrl("http://user:pass@uaa.com");
            assertResolveRedirectReturnsSameUrl("http://uaa.com/xyz");
            assertResolveRedirectReturnsSameUrl("http://uaa.com/xyz/abc/1234");
            assertResolveRedirectReturnsSameUrl("http://subdomain.uaa.com");
            assertResolveRedirectReturnsSameUrl("http://subdomain1.subdomain2.subdomain3.uaa.com");
            assertResolveRedirectReturnsSameUrl("http://uaa.com/xyz?foo=bar");
            assertResolveRedirectReturnsSameUrl("http://uaa.com?foo=bar");
            assertResolveRedirectReturnsSameUrl("http://uaa.com/xyz?foo=bar#fragment");

            assertResolveRedirectThrows________("http://uaa.com:8080");
            assertResolveRedirectThrows________("https://uaa.com");
        }

        @Test
        void testResolveClientWithUrlWhichHasPortAndHasNoWildcardsAndDoesNotEndInSlash() {
            mockRegisteredRedirectUri("http://uaa.com:8080");

            assertResolveRedirectReturnsSameUrl("http://uaa.com:8080");
            assertResolveRedirectReturnsSameUrl("http://user:pass@uaa.com:8080");
            assertResolveRedirectReturnsSameUrl("http://uaa.com:8080/xyz");
            assertResolveRedirectReturnsSameUrl("http://uaa.com:8080/xyz/abc/1234");
            assertResolveRedirectReturnsSameUrl("http://subdomain.uaa.com:8080");
            assertResolveRedirectReturnsSameUrl("http://subdomain1.subdomain2.subdomain3.uaa.com:8080");
            assertResolveRedirectReturnsSameUrl("http://uaa.com:8080/xyz?foo=bar");
            assertResolveRedirectReturnsSameUrl("http://uaa.com:8080?foo=bar");
            assertResolveRedirectReturnsSameUrl("http://uaa.com:8080/xyz?foo=bar#fragment");
            assertResolveRedirectReturnsSameUrl("http://uaa.com:8080");

            assertResolveRedirectThrows________("http://uaa.com:8081");
            assertResolveRedirectThrows________("https://uaa.com:8080");
        }

        @Test
        void testResolveClientWithUrlWhichHasNoWildcardsAndDoesEndInSlash() {
            mockRegisteredRedirectUri("http://uaa.com/");

            assertResolveRedirectReturnsSameUrl("http://uaa.com/");
            assertResolveRedirectReturnsSameUrl("http://user:pass@uaa.com/");
            assertResolveRedirectReturnsSameUrl("http://uaa.com/xyz");
            assertResolveRedirectReturnsSameUrl("http://uaa.com/xyz/abc/1234");
            assertResolveRedirectReturnsSameUrl("http://subdomain.uaa.com/");
            assertResolveRedirectReturnsSameUrl("http://subdomain1.subdomain2.subdomain3.uaa.com/");
            assertResolveRedirectReturnsSameUrl("http://uaa.com/xyz?foo=bar");
            assertResolveRedirectReturnsSameUrl("http://uaa.com/?foo=bar");
            assertResolveRedirectReturnsSameUrl("http://uaa.com/xyz?foo=bar#fragment");

            assertResolveRedirectThrows________("http://uaa.com:8080");
            assertResolveRedirectThrows________("http://uaa.com");
            assertResolveRedirectThrows________("http://uaa.com?foo=bar");
            assertResolveRedirectThrows________("http://uaa.com#foo");
            assertResolveRedirectThrows________("http://subdomain.uaa.com");
            assertResolveRedirectThrows________("http://subdomain1.subdomain2.uaa.com");
            assertResolveRedirectThrows________("https://uaa.com");
        }

        @Test
        void testResolveClientWithUrlWhichHasWildcardsOrDoubleWildcardsInTheSubdomainAndDoesNotEndInSlash() {
            for (String uriPattern : newArrayList("http://*.uaa.com", "http://**.uaa.com")) {
                mockRegisteredRedirectUri(uriPattern);

                assertResolveRedirectReturnsSameUrl("http://subdomain.uaa.com");
                assertResolveRedirectReturnsSameUrl("http://subdomain1.subdomain2.uaa.com");
                assertResolveRedirectReturnsSameUrl("http://subdomain1.subdomain2.subdomain3.uaa.com");
                assertResolveRedirectReturnsSameUrl("http://user:pass@subdomain.uaa.com");

                assertResolveRedirectThrows________("http://subdomain.evil.com/domain.uaa.com");
                assertResolveRedirectThrows________("http://evil.com/domain.uaa.com");
                assertResolveRedirectThrows________("http://evil.com/uaa.com");

                assertResolveRedirectThrows________("http://subdomain.uaa.com/xyz");
                assertResolveRedirectThrows________("http://subdomain.uaa.com/xyz/abc/1234");
                assertResolveRedirectThrows________("http://subdomain.uaa.com/xyz?foo=bar");
                assertResolveRedirectThrows________("http://subdomain.uaa.com/?foo=bar");
                assertResolveRedirectThrows________("http://subdomain.uaa.com?foo=bar");
                assertResolveRedirectThrows________("http://subdomain.uaa.com/xyz?foo=bar#fragment");

                assertResolveRedirectThrows________("http://subdomain.uaa.com:8080");
                assertResolveRedirectThrows________("http://uaa.com");
                assertResolveRedirectThrows________("http://subdomain.uaa.com#foo");
                assertResolveRedirectThrows________("http://subdomain.uaa.com/");
                assertResolveRedirectThrows________("https://subdomain.uaa.com");
            }

            for (String uriPattern : newArrayList("http://sub*.uaa.com", "http://sub**.uaa.com")) {
                mockRegisteredRedirectUri(uriPattern);

                assertResolveRedirectReturnsSameUrl("http://subdomain.uaa.com");
                assertResolveRedirectReturnsSameUrl("http://subdomain1.subdomain2.uaa.com");
                assertResolveRedirectReturnsSameUrl("http://subdomain1.subdomain2.subdomain3.uaa.com");
                assertResolveRedirectThrows________("http://user:pass@subdomain.uaa.com");
            }
        }

        @Test
        void testResolveClientWithUrlWhichHasWildcardAsThePath() {
            mockRegisteredRedirectUri("http://uaa.com/*");

            assertResolveRedirectReturnsSameUrl("http://uaa.com/");
            assertResolveRedirectReturnsSameUrl("http://uaa.com/xyz");
            assertResolveRedirectReturnsSameUrl("http://uaa.com/xyz?foo=bar");
            assertResolveRedirectReturnsSameUrl("http://uaa.com/?foo=bar");
            assertResolveRedirectReturnsSameUrl("http://uaa.com/xyz?foo=bar#fragment");
            assertResolveRedirectReturnsSameUrl("http://uaa.com/#fragment");

            assertResolveRedirectThrows________("http://uaa.com");
            assertResolveRedirectThrows________("http://user:pass@uaa.com");
            assertResolveRedirectThrows________("http://uaa.com/xyz/abc/1234");
            assertResolveRedirectThrows________("http://subdomain.uaa.com/");
            assertResolveRedirectThrows________("http://subdomain1.subdomain2.subdomain3.uaa.com/");
            assertResolveRedirectThrows________("http://uaa.com:8080");
            assertResolveRedirectThrows________("http://uaa.com?foo=bar");
            assertResolveRedirectThrows________("http://uaa.com#foo");
            assertResolveRedirectThrows________("http://subdomain.uaa.com");
            assertResolveRedirectThrows________("http://subdomain1.subdomain2.uaa.com");
            assertResolveRedirectThrows________("https://uaa.com");
            assertResolveRedirectThrows________("https://uaa.com/");
        }

        @Test
        void testResolveClientWithUrlWhichHasWildcardInThePath() {
            mockRegisteredRedirectUri("http://uaa.com/a/*/b");

            assertResolveRedirectReturnsSameUrl("http://uaa.com/a/zzz/b");
            assertResolveRedirectThrows________("http://uaa.com/a/zzz/b?foo=bar");
            assertResolveRedirectThrows________("http://uaa.com/a/zzz/b#fragment");
            assertResolveRedirectThrows________("http://uaa.com/a/b");
            assertResolveRedirectThrows________("http://uaa.com/a/b/c");
            assertResolveRedirectThrows________("http://uaa.com/xyz");
            assertResolveRedirectThrows________("http://uaa.com");
            assertResolveRedirectThrows________("http://user:pass@uaa.com/a/zzz/b");
            assertResolveRedirectThrows________("http://subdomain.uaa.com/a/zzz/b");
            assertResolveRedirectThrows________("http://subdomain1.subdomain2.subdomain3.uaa.com/a/zzz/b");
            assertResolveRedirectThrows________("http://uaa.com:8080/a/zzz/b");
            assertResolveRedirectThrows________("https://uaa.com/a/zzz/b");

            mockRegisteredRedirectUri("http://uaa.com/a/z*z/b");

            assertResolveRedirectReturnsSameUrl("http://uaa.com/a/zz/b");
            assertResolveRedirectReturnsSameUrl("http://uaa.com/a/zxz/b");
            assertResolveRedirectReturnsSameUrl("http://uaa.com/a/zxxxxz/b");
            assertResolveRedirectReturnsSameUrl("http://uaa.com/a/z?foo=baz/b");
            assertResolveRedirectThrows________("http://uaa.com/a/z/z/b");
            assertResolveRedirectThrows________("http://uaa.com/a/zxz/b?foo=bar");
            assertResolveRedirectThrows________("http://uaa.com/a/zxz/b#foo");

            mockRegisteredRedirectUri("http://uaa.com/a/z*z/b*c");

            assertResolveRedirectReturnsSameUrl("http://uaa.com/a/zz/bc");
            assertResolveRedirectReturnsSameUrl("http://uaa.com/a/zxz/bxc");
            assertResolveRedirectThrows________("http://uaa.com/a/zz/b/c");
            assertResolveRedirectThrows________("http://uaa.com/a/zxz/bxc?foo=bar");

            mockRegisteredRedirectUri("http://uaa.com/a/b*");

            assertResolveRedirectReturnsSameUrl("http://uaa.com/a/b");
            assertResolveRedirectReturnsSameUrl("http://uaa.com/a/bzzz");
            assertResolveRedirectReturnsSameUrl("http://uaa.com/a/b?foo=bar");
            assertResolveRedirectReturnsSameUrl("http://uaa.com/a/b#foo");
            assertResolveRedirectThrows________("http://uaa.com/a/b/c");
            assertResolveRedirectThrows________("http://uaa.com/a/b/c?foo=bar");
        }

        @Test
        void testResolveClientWithUrlWhichHasDoubleWildcardAsThePath() {
            mockRegisteredRedirectUri("http://uaa.com/**");

            assertResolveRedirectReturnsSameUrl("http://uaa.com");
            assertResolveRedirectReturnsSameUrl("http://uaa.com/");
            assertResolveRedirectReturnsSameUrl("http://uaa.com/xyz");
            assertResolveRedirectReturnsSameUrl("http://uaa.com/xyz?foo=bar");
            assertResolveRedirectReturnsSameUrl("http://uaa.com/?foo=bar");
            assertResolveRedirectReturnsSameUrl("http://uaa.com/xyz?foo=bar#fragment");
            assertResolveRedirectReturnsSameUrl("http://uaa.com/#fragment");
            assertResolveRedirectReturnsSameUrl("http://uaa.com/xyz/abc/1234");
            assertResolveRedirectReturnsSameUrl("http://uaa.com/xyz/abc/1234?foo=bar");
            assertResolveRedirectReturnsSameUrl("http://uaa.com/xyz/abc/1234?foo=bar#fragment");
            assertResolveRedirectReturnsSameUrl("http://uaa.com/xyz/abc/1234#fragment");

            assertResolveRedirectThrows________("http://user:pass@uaa.com");
            assertResolveRedirectThrows________("http://user:pass@uaa.com/");
            assertResolveRedirectThrows________("http://subdomain.uaa.com");
            assertResolveRedirectThrows________("http://subdomain.uaa.com/");
            assertResolveRedirectThrows________("http://subdomain1.subdomain2.subdomain3.uaa.com/");
            assertResolveRedirectThrows________("http://uaa.com:8080");
            assertResolveRedirectThrows________("http://uaa.com:8080/");
            assertResolveRedirectThrows________("http://uaa.com?foo=bar");
            assertResolveRedirectThrows________("http://uaa.com#foo");
            assertResolveRedirectThrows________("https://uaa.com");
            assertResolveRedirectThrows________("https://uaa.com/");
        }

        @Test
        void testResolveClientWithUrlWhichHasDoubleWildcardInThePath() {
            // note that this case works as you might expect, but the other cases below work as if you had used a single '*'
            mockRegisteredRedirectUri("http://uaa.com/a/**/b");

            assertResolveRedirectReturnsSameUrl("http://uaa.com/a/b");
            assertResolveRedirectReturnsSameUrl("http://uaa.com/a/zzz/b");
            assertResolveRedirectReturnsSameUrl("http://uaa.com/a/c/d/e/f/b");
            assertResolveRedirectThrows________("http://uaa.com/a/zzz/b?foo=bar");
            assertResolveRedirectThrows________("http://uaa.com/a/zzz/b#fragment");
            assertResolveRedirectThrows________("http://uaa.com/a/b/c");
            assertResolveRedirectThrows________("http://uaa.com/xyz");
            assertResolveRedirectThrows________("http://uaa.com");
            assertResolveRedirectThrows________("http://user:pass@uaa.com/a/zzz/b");
            assertResolveRedirectThrows________("http://subdomain.uaa.com/a/zzz/b");
            assertResolveRedirectThrows________("http://subdomain1.subdomain2.subdomain3.uaa.com/a/zzz/b");
            assertResolveRedirectThrows________("http://uaa.com:8080/a/zzz/b");
            assertResolveRedirectThrows________("https://uaa.com/a/zzz/b");

            mockRegisteredRedirectUri("http://uaa.com/a/z**z/b");

            assertResolveRedirectReturnsSameUrl("http://uaa.com/a/zz/b");
            assertResolveRedirectReturnsSameUrl("http://uaa.com/a/zxz/b");
            assertResolveRedirectReturnsSameUrl("http://uaa.com/a/zxxxxz/b");
            assertResolveRedirectReturnsSameUrl("http://uaa.com/a/z?foo=baz/b");
            assertResolveRedirectThrows________("http://uaa.com/a/z/x/z/b");
            assertResolveRedirectThrows________("http://uaa.com/a/zxx/xx/xxz/b");
            assertResolveRedirectThrows________("http://uaa.com/a/z/z/b");
            assertResolveRedirectThrows________("http://uaa.com/a/zxz/b?foo=bar");
            assertResolveRedirectThrows________("http://uaa.com/a/zxz/b#foo");

            mockRegisteredRedirectUri("http://uaa.com/a/z**z/b**c");

            assertResolveRedirectReturnsSameUrl("http://uaa.com/a/zz/bc");
            assertResolveRedirectReturnsSameUrl("http://uaa.com/a/zxz/bxc");
            assertResolveRedirectThrows________("http://uaa.com/a/z/x/z/b/x/c");
            assertResolveRedirectThrows________("http://uaa.com/a/zz/b/c");
            assertResolveRedirectThrows________("http://uaa.com/a/zxz/bxc?foo=bar");

            mockRegisteredRedirectUri("http://uaa.com/a/b**");

            assertResolveRedirectReturnsSameUrl("http://uaa.com/a/b");
            assertResolveRedirectReturnsSameUrl("http://uaa.com/a/bzzz");
            assertResolveRedirectReturnsSameUrl("http://uaa.com/a/b?foo=bar");
            assertResolveRedirectReturnsSameUrl("http://uaa.com/a/b#foo");
            assertResolveRedirectThrows________("http://uaa.com/a/b/c");
            assertResolveRedirectThrows________("http://uaa.com/a/b/c?foo=bar");
        }

        private void mockRegisteredRedirectUri(String allowedRedirectUri) {
            when(mockClientDetails.getRegisteredRedirectUri()).thenReturn(Collections.singleton(allowedRedirectUri));
        }

        private void assertResolveRedirectReturnsSameUrl(String requestedRedirect) {
            assertThat(resolver.resolveRedirect(requestedRedirect, mockClientDetails), equalTo(requestedRedirect));
        }

        private void assertResolveRedirectThrows________(String requestedRedirect) {
            assertThrows(RedirectMismatchException.class, () -> resolver.resolveRedirect(requestedRedirect, mockClientDetails));
        }

    }
}
