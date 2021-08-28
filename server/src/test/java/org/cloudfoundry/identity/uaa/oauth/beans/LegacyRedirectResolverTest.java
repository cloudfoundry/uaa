package org.cloudfoundry.identity.uaa.oauth.beans;

import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.core.LogEvent;
import org.apache.logging.log4j.core.LoggerContext;
import org.apache.logging.log4j.core.appender.AbstractAppender;
import org.hamcrest.Description;
import org.hamcrest.Matcher;
import org.hamcrest.TypeSafeMatcher;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.security.oauth2.common.exceptions.RedirectMismatchException;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;

import static org.apache.logging.log4j.Level.WARN;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_AUTHORIZATION_CODE;
import static org.cloudfoundry.identity.uaa.util.AssertThrowsWithMessage.assertThrowsWithMessageThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.hasItem;
import static org.hamcrest.Matchers.is;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * For additional tests, see also org.cloudfoundry.identity.uaa.oauth.beans.RedirectResolverTest
 *
 * @see RedirectResolverTest
 */
class LegacyRedirectResolverTest {

    private final LegacyRedirectResolver resolver = new LegacyRedirectResolver();

    private static ClientDetails createClient(String id, String... redirectUris) {
        BaseClientDetails clientDetails = new BaseClientDetails();
        clientDetails.setClientId(id);
        clientDetails.setAuthorizedGrantTypes(Collections.singleton(GRANT_TYPE_AUTHORIZATION_CODE));
        clientDetails.setRegisteredRedirectUri(new HashSet<>(Arrays.asList(redirectUris)));

        return clientDetails;
    }

    private static String expectedWarning(String clientId, String requested, String configured) {
        return String.format(LegacyRedirectResolver.MSG_TEMPLATE, clientId, requested, configured);
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
            final String configuredRedirectUri = "https://example.com";
            final String requestedRedirectUri = "https://subdomain.example.com";
            ClientDetails client = createClient("foo", configuredRedirectUri);

            resolver.resolveRedirect(requestedRedirectUri, client);
            assertThat(logEvents, hasItem(
                    warning(expectedWarning(client.getClientId(), requestedRedirectUri, configuredRedirectUri)))
            );
        }

        @Test
        void doesNotWarnOnEmptyRedirectUri() {
            ClientDetails client = createClient("foo", "http://localhost");

            resolver.resolveRedirect(null, client);
            assertThat(logEvents, empty());
        }

        @Test
        void warnsOnImplicitMultipleDomainExpansion() {
            final String configuredRedirectUri = "https://example.com";
            final String requestedRedirectUri = "https://another.subdomain.example.com";
            ClientDetails client = createClient("foo", configuredRedirectUri);

            resolver.resolveRedirect(requestedRedirectUri, client);
            assertThat(logEvents, hasItem(
                    warning(expectedWarning(client.getClientId(), requestedRedirectUri, configuredRedirectUri)))
            );
        }

        @Test
        void warnsOnExplicitDomainExpansion() {
            final String configuredRedirectUri = "https://*.example.com";
            final String requestedRedirectUri = "https://subdomain.example.com";
            ClientDetails client = createClient("foo", configuredRedirectUri);

            resolver.resolveRedirect(requestedRedirectUri, client);
            assertThat(logEvents, hasItem(
                    warning(expectedWarning(client.getClientId(), requestedRedirectUri, configuredRedirectUri)))
            );
        }

        @Test
        void warnsOnImplicitPathExpansion() {
            final String configuredRedirectUri = "https://example.com/";
            final String requestedRedirectUri = "https://example.com/path";
            ClientDetails client = createClient("foo", configuredRedirectUri);

            resolver.resolveRedirect(requestedRedirectUri, client);
            assertThat(logEvents, hasItem(warning(expectedWarning(client.getClientId(), requestedRedirectUri, configuredRedirectUri))));
        }

        @Test
        void warnsOnImplicitMultiplePathExpansion() {
            final String configuredRedirectUri = "https://example.com/";
            final String requestedRedirectUri = "https://example.com/some/path";
            ClientDetails client = createClient("foo", configuredRedirectUri);

            resolver.resolveRedirect(requestedRedirectUri, client);
            assertThat(logEvents, hasItem(warning(expectedWarning(client.getClientId(), requestedRedirectUri, configuredRedirectUri))));
        }

        @Test
        void warnsOnExplicitPathExpansion() {
            final String configuredRedirectUri = "https://example.com/*";
            final String requestedRedirectUri = "https://example.com/path";
            ClientDetails client = createClient("foo", configuredRedirectUri);

            resolver.resolveRedirect(requestedRedirectUri, client);
            assertThat(logEvents, hasItem(
                    warning(expectedWarning(client.getClientId(), requestedRedirectUri, configuredRedirectUri)))
            );
        }

        @Test
        void warnsOnAllConfiguredUrisWhichLegacyMatchButDoNotStrictlyMatch() {
            final String configuredExplicitRedirectUri = "https://*.example.com/";
            final String configuredImplicitRedirectUri = "https://example.com/";
            final String requestedRedirectUri = "https://an.example.com/";

            // the explicit redirect uri will match first, but we should still log
            ClientDetails client = createClient("foo", configuredExplicitRedirectUri, configuredImplicitRedirectUri);

            resolver.resolveRedirect(requestedRedirectUri, client);
            assertThat(logEvents, hasItem(warning(expectedWarning(client.getClientId(), requestedRedirectUri, configuredImplicitRedirectUri))));
            assertThat(logEvents, hasItem(warning(expectedWarning(client.getClientId(), requestedRedirectUri, configuredExplicitRedirectUri))));
        }

        @Test
        void warnsOnlyAboutMatchingConfiguredUrisMWhenThereIsAMatch() {
            final String configuredImplicitRedirectUri = "https://example.com";
            final String configuredOtherRedirectUri = "https://other.com/";
            final String requestedRedirectUri = "https://an.example.com/";

            // the explicit redirect uri will match first, but we should still log
            ClientDetails client = createClient("foo", configuredOtherRedirectUri, requestedRedirectUri, configuredImplicitRedirectUri);

            resolver.resolveRedirect(requestedRedirectUri, client);
            assertThat(logEvents, hasItem(warning(expectedWarning(client.getClientId(), requestedRedirectUri, configuredImplicitRedirectUri))));
            // configured uri which matches both old and new resolvers is not logged
            // and non-matching configured uri is also not logged
            assertThat(logEvents.size(), is(1));
        }

        @Test
        void redactsQueryParameterValues() {
            final String configuredRedirectUri = "https://example.com/";
            final String requestedRedirectUri = "https://example.com/path?foo=bar&foo=1234&baz=qux";

            ClientDetails client = createClient("foo", configuredRedirectUri);

            resolver.resolveRedirect(requestedRedirectUri, client);

            assertThat(logEvents, hasItem(
                    warning(expectedWarning(client.getClientId(), "https://example.com/path?foo=REDACTED&foo=REDACTED&baz=REDACTED", configuredRedirectUri)))
            );
        }

        @Test
        void redactsHashFragment() {
            final String configuredRedirectUri = "https://example.com";
            final String requestedRedirectUri = "https://example.com/a/b#IAmAHash";

            ClientDetails client = createClient("front-end-app", configuredRedirectUri);

            resolver.resolveRedirect(requestedRedirectUri, client);

            assertThat(logEvents, hasItem(
                    warning(expectedWarning(client.getClientId(), "https://example.com/a/b#REDACTED", configuredRedirectUri)))
            );
        }

        @Test
        void warnsOnImplicitAuthorizationExpansion() {
            final String configuredRedirectUri = "https://example.com/";
            final String requestedRedirectUri = "https://user:pass@example.com/";

            ClientDetails client = createClient("myAppIsCool", configuredRedirectUri);

            resolver.resolveRedirect(requestedRedirectUri, client);

            assertThat(logEvents, hasItem(
                    warning(expectedWarning(client.getClientId(), "https://REDACTED:REDACTED@example.com/", configuredRedirectUri)))
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

        @Test
        void doesNotWarnWhenThereIsNoMatch() {
            final String configuredRedirectUri = "https://example.com";
            final String requestedRedirectUri = "https://other.com";

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
        void matchesSchemeCustom() {
            assertTrue(resolver.redirectMatches("myapp://callback", "myapp://callback"));
            assertTrue(resolver.redirectMatches("myapp://callback#token=xyz123", "myapp://callback*"));
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

        @Test
        void matchesPortWithWildcardPort() {
            final String clientRedirectUri = "https://example.com:*/";
            assertTrue(resolver.redirectMatches("https://example.com:65000/", clientRedirectUri));
        }

        @Test
        void matchesPortWithWildcardPortAndPath() {
            final String clientRedirectUri = "https://example.com:*/**";
            assertTrue(resolver.redirectMatches("https://example.com:65000/path/subpath", clientRedirectUri));
        }

        @Test
        void matchesEmptyPortWithWildcardPort() {
            final String clientRedirectUri = "https://example.com:*/";
            assertTrue(resolver.redirectMatches("https://example.com:80/", clientRedirectUri));
            assertFalse(resolver.redirectMatches("https://example.com/", clientRedirectUri));
        }

        @Test
        void matchesEmptyPortWithWildcardPortAndPath() {
            final String clientRedirectUri = "https://example.com:*/**";
            assertTrue(resolver.redirectMatches("https://example.com:80/path1/path2/path3", clientRedirectUri));
            assertFalse(resolver.redirectMatches("https://example.com/path1/path2/path3", clientRedirectUri));
        }

        @Test
        public void testIllegalUnderscoreDomain() {
            final String clientRedirectUri = "http*://*.example.com/**";
            assertFalse(resolver.redirectMatches("https://invalid_redirect.example.com/login/callback", clientRedirectUri));
        }

        @Test
        public void testLegalDomain() {
            final String clientRedirectUri = "http*://*.example.com/**";
            assertTrue(resolver.redirectMatches("https://valid-redirect.example.com/login/callback", clientRedirectUri));
        }

    }

    @Nested
    @DisplayName("with caps")
    class RedirectMatchesCaps {
        @Test
        void withClientHostCaps() {
            final String clientRedirectUri = "http://SubDomain.Domain.com";
            final String clientRedirectUriPort = "http://SubDomain.Domain.com:8080";
            final String clientRedirectUriPath = "http://SubDomain.Domain.com/bee/Bop";
            final String clientRedirectUriQuery = "http://SubDomain.Domain.com?rock=Steady";
            final String clientRedirectUriFragment = "http://SubDomain.Domain.com";

            assertTrue(resolver.redirectMatches("http://subdomain.domain.com", clientRedirectUri));
            assertTrue(resolver.redirectMatches("http://subdomain.domain.com:8080", clientRedirectUriPort));
            assertTrue(resolver.redirectMatches("http://subdomain.domain.com/bee/Bop", clientRedirectUriPath));
            assertTrue(resolver.redirectMatches("http://subdomain.domain.com?rock=Steady", clientRedirectUriQuery));
            assertTrue(resolver.redirectMatches("http://subdomain.domain.com#Shredder", clientRedirectUriFragment));
        }

        @Test
        void withRequestedHostCaps() {
            final String clientRedirectUri = "http://subdomain.domain.com";
            final String clientRedirectUriPort = "http://subdomain.domain.com:8080";
            final String clientRedirectUriPath = "http://subdomain.domain.com/bee/Bop";
            final String clientRedirectUriQuery = "http://subdomain.domain.com?rock=Steady";
            final String clientRedirectUriFragment = "http://subdomain.domain.com";

            assertTrue(resolver.redirectMatches("http://sUBdOMAIN.dOMAIN.com", clientRedirectUri));
            assertTrue(resolver.redirectMatches("http://sUBdOMAIN.dOMAIN.com:8080", clientRedirectUriPort));
            assertTrue(resolver.redirectMatches("http://sUBdOMAIN.dOMAIN.com/bee/Bop", clientRedirectUriPath));
            assertTrue(resolver.redirectMatches("http://sUBdOMAIN.dOMAIN.com?rock=Steady", clientRedirectUriQuery));
            assertTrue(resolver.redirectMatches("http://sUBdOMAIN.dOMAIN.com#Shredder", clientRedirectUriFragment));
        }

        @Test
        void withWildCardHostCaps() {
            final String clientRedirectUri = "http://SubDomain.Domain.com/**";
            final String clientRedirectUriPort = "http://SubDomain.Domain.com:8080/**";
            final String clientRedirectUriPath = "http://SubDomain.Domain.com/bee/Bop/**";

            assertTrue(resolver.redirectMatches("http://sUBdOMAIN.dOMAIN.com", clientRedirectUri));
            assertTrue(resolver.redirectMatches("http://sUBdOMAIN.dOMAIN.com:8080/", clientRedirectUriPort));
            assertTrue(resolver.redirectMatches("http://sUBdOMAIN.dOMAIN.com/bee/Bop/", clientRedirectUriPath));
        }
    }

    @Nested
    class ResolveRedirect {
        private ClientDetails mockClientDetails;

        @BeforeEach
        void setUp() {
            mockClientDetails = mock(BaseClientDetails.class);
            when(mockClientDetails.getAuthorizedGrantTypes()).thenReturn(Collections.singleton(GRANT_TYPE_AUTHORIZATION_CODE));
        }

        @Test
        void clientMissingRedirectUri() {
            when(mockClientDetails.getRegisteredRedirectUri()).thenReturn(new HashSet<>());

            assertThrowsWithMessageThat(RedirectMismatchException.class,
                    () -> resolver.resolveRedirect("http://somewhere.com", mockClientDetails),
                    containsString("Client registration is missing redirect_uri"));
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

        private void mockRegisteredRedirectUri(String allowedRedirectUri) {
            when(mockClientDetails.getRegisteredRedirectUri()).thenReturn(Collections.singleton(allowedRedirectUri));
        }
    }

    @Nested
    class PathTraversalBypass {

        private static final String BASE_URI = "http://example.com/foo";

        @ParameterizedTest(name = "\"" + BASE_URI + "{0}\" should match both \"" + BASE_URI + "\" and \"" + BASE_URI + "/**\"")
        @ValueSource(strings = {
                "/./bar",
                "/%2e/bar",         // %2e is . url encoded
                "/%252e/bar",       // %25 is % url encoded
                "/%2525252e/bar",   // path may be url decoded multiple times when passing through web servers, proxies and browser
        })
        void singleDotTraversal(String requestedSuffix) {
            assertTrue(resolver.redirectMatches(BASE_URI + requestedSuffix, BASE_URI));
            assertTrue(resolver.redirectMatches(BASE_URI + requestedSuffix, BASE_URI + "/**"));
        }

        @ParameterizedTest(name = "\"" + BASE_URI + "{0}\" should not match \"" + BASE_URI + "\" or \"" + BASE_URI + "/**\"")
        @ValueSource(strings = {
                "/../bar",
                "/%2e./bar",        // %2e is . url encoded
                "/%252e./bar",      // %25 is % url encoded
                "/%2525252e./bar",  // path may be url decoded multiple times when passing through web servers, proxies and browser
                "/%25252525252525252525252e/bar",
                "/%25252525252525252525252e./bar",
        })
        void doubleDotTraversal(String requestedSuffix) {
            assertFalse(resolver.redirectMatches(BASE_URI + requestedSuffix, BASE_URI));
            assertFalse(resolver.redirectMatches(BASE_URI + requestedSuffix, BASE_URI + "/**"));
        }
    }
}
