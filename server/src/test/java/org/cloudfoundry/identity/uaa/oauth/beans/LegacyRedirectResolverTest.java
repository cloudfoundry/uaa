package org.cloudfoundry.identity.uaa.oauth.beans;

import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.core.LogEvent;
import org.apache.logging.log4j.core.LoggerContext;
import org.apache.logging.log4j.core.appender.AbstractAppender;
import org.cloudfoundry.identity.uaa.client.UaaClientDetails;
import org.cloudfoundry.identity.uaa.oauth.common.exceptions.RedirectMismatchException;
import org.cloudfoundry.identity.uaa.oauth.provider.ClientDetails;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;

import static org.apache.logging.log4j.Level.WARN;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.AssertionsForClassTypes.assertThatExceptionOfType;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_AUTHORIZATION_CODE;
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
        UaaClientDetails clientDetails = new UaaClientDetails();
        clientDetails.setClientId(id);
        clientDetails.setAuthorizedGrantTypes(Collections.singleton(GRANT_TYPE_AUTHORIZATION_CODE));
        clientDetails.setRegisteredRedirectUri(new HashSet<>(Arrays.asList(redirectUris)));

        return clientDetails;
    }

    private static String expectedWarning(String clientId, String requested, String configured) {
        return LegacyRedirectResolver.MSG_TEMPLATE.formatted(clientId, requested, configured);
    }

    private void assertThatMessageWasLogged(
            final List<LogEvent> logEvents,
            final Level expectedLevel,
            final String expectedMessage) {

        assertThat(logEvents).filteredOn(l -> l.getLevel().equals(expectedLevel))
                .extracting(l -> l.getMessage().getFormattedMessage())
                .contains(expectedMessage);
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
            assertThatMessageWasLogged(logEvents, WARN, expectedWarning(client.getClientId(), requestedRedirectUri, configuredRedirectUri));
        }

        @Test
        void doesNotWarnOnEmptyRedirectUri() {
            ClientDetails client = createClient("foo", "http://localhost");

            resolver.resolveRedirect(null, client);
            assertThat(logEvents).isEmpty();
        }

        @Test
        void warnsOnImplicitMultipleDomainExpansion() {
            final String configuredRedirectUri = "https://example.com";
            final String requestedRedirectUri = "https://another.subdomain.example.com";
            ClientDetails client = createClient("foo", configuredRedirectUri);

            resolver.resolveRedirect(requestedRedirectUri, client);
            assertThatMessageWasLogged(logEvents, WARN, expectedWarning(client.getClientId(), requestedRedirectUri, configuredRedirectUri));
        }

        @Test
        void warnsOnExplicitDomainExpansion() {
            final String configuredRedirectUri = "https://*.example.com";
            final String requestedRedirectUri = "https://subdomain.example.com";
            ClientDetails client = createClient("foo", configuredRedirectUri);

            resolver.resolveRedirect(requestedRedirectUri, client);
            assertThatMessageWasLogged(logEvents, WARN, expectedWarning(client.getClientId(), requestedRedirectUri, configuredRedirectUri));
        }

        @Test
        void warnsOnPortWildCard() {
            final String configuredRedirectUri = "https://example.com:*/*";
            final String requestedRedirectUri = "https://example.com:443/callback";
            ClientDetails client = createClient("foo", configuredRedirectUri);

            resolver.resolveRedirect(requestedRedirectUri, client);
            assertThatMessageWasLogged(logEvents, WARN, expectedWarning(client.getClientId(), requestedRedirectUri, configuredRedirectUri));
        }

        @Test
        void warnsOnImplicitPathExpansion() {
            final String configuredRedirectUri = "https://example.com/";
            final String requestedRedirectUri = "https://example.com/path";
            ClientDetails client = createClient("foo", configuredRedirectUri);

            resolver.resolveRedirect(requestedRedirectUri, client);
            assertThatMessageWasLogged(logEvents, WARN, expectedWarning(client.getClientId(), requestedRedirectUri, configuredRedirectUri));
        }

        @Test
        void warnsOnImplicitMultiplePathExpansion() {
            final String configuredRedirectUri = "https://example.com/";
            final String requestedRedirectUri = "https://example.com/some/path";
            ClientDetails client = createClient("foo", configuredRedirectUri);

            resolver.resolveRedirect(requestedRedirectUri, client);
            assertThatMessageWasLogged(logEvents, WARN, expectedWarning(client.getClientId(), requestedRedirectUri, configuredRedirectUri));
        }

        @Test
        void warnsOnExplicitPathExpansion() {
            final String configuredRedirectUri = "https://example.com/*";
            final String requestedRedirectUri = "https://example.com/path";
            ClientDetails client = createClient("foo", configuredRedirectUri);

            resolver.resolveRedirect(requestedRedirectUri, client);
            assertThatMessageWasLogged(logEvents, WARN, expectedWarning(client.getClientId(), requestedRedirectUri, configuredRedirectUri));
        }

        @Test
        void warnsOnAllConfiguredUrisWhichLegacyMatchButDoNotStrictlyMatch() {
            final String configuredExplicitRedirectUri = "https://*.example.com/";
            final String configuredImplicitRedirectUri = "https://example.com/";
            final String requestedRedirectUri = "https://an.example.com/";

            // the explicit redirect uri will match first, but we should still log
            ClientDetails client = createClient("foo", configuredExplicitRedirectUri, configuredImplicitRedirectUri);

            resolver.resolveRedirect(requestedRedirectUri, client);
            assertThatMessageWasLogged(logEvents, WARN, expectedWarning(client.getClientId(), requestedRedirectUri, configuredImplicitRedirectUri));
            assertThatMessageWasLogged(logEvents, WARN, expectedWarning(client.getClientId(), requestedRedirectUri, configuredExplicitRedirectUri));
        }

        @Test
        void warnsOnlyAboutMatchingConfiguredUrisMWhenThereIsAMatch() {
            final String configuredImplicitRedirectUri = "https://example.com";
            final String configuredOtherRedirectUri = "https://other.com/";
            final String requestedRedirectUri = "https://an.example.com/";

            // the explicit redirect uri will match first, but we should still log
            ClientDetails client = createClient("foo", configuredOtherRedirectUri, requestedRedirectUri, configuredImplicitRedirectUri);

            resolver.resolveRedirect(requestedRedirectUri, client);
            assertThatMessageWasLogged(logEvents, WARN, expectedWarning(client.getClientId(), requestedRedirectUri, configuredImplicitRedirectUri));

            // configured uri which matches both old and new resolvers is not logged
            // and non-matching configured uri is also not logged
            assertThat(logEvents).hasSize(1);
        }

        @Test
        void redactsQueryParameterValues() {
            final String configuredRedirectUri = "https://example.com/";
            final String requestedRedirectUri = "https://example.com/path?foo=bar&foo=1234&baz=qux";

            ClientDetails client = createClient("foo", configuredRedirectUri);

            resolver.resolveRedirect(requestedRedirectUri, client);
            assertThatMessageWasLogged(logEvents, WARN, expectedWarning(client.getClientId(), "https://example.com/path?foo=REDACTED&foo=REDACTED&baz=REDACTED", configuredRedirectUri));
        }

        @Test
        void redactsHashFragment() {
            final String configuredRedirectUri = "https://example.com";
            final String requestedRedirectUri = "https://example.com/a/b#IAmAHash";

            ClientDetails client = createClient("front-end-app", configuredRedirectUri);

            resolver.resolveRedirect(requestedRedirectUri, client);
            assertThatMessageWasLogged(logEvents, WARN, expectedWarning(client.getClientId(), "https://example.com/a/b#REDACTED", configuredRedirectUri));
        }

        @Test
        void warnsOnImplicitAuthorizationExpansion() {
            final String configuredRedirectUri = "https://example.com/";
            final String requestedRedirectUri = "https://user:pass@example.com/";

            ClientDetails client = createClient("myAppIsCool", configuredRedirectUri);

            resolver.resolveRedirect(requestedRedirectUri, client);
            assertThatMessageWasLogged(logEvents, WARN, expectedWarning(client.getClientId(), "https://REDACTED:REDACTED@example.com/", configuredRedirectUri));
        }

        @Test
        void doesNotWarnForExactMatch() {
            final String configuredRedirectUri = "https://example.com/";
            final String requestedRedirectUri = "https://example.com/";

            ClientDetails client = createClient("foo", configuredRedirectUri);

            resolver.resolveRedirect(requestedRedirectUri, client);

            assertThat(logEvents).isEmpty();
        }

        @Test
        void doesNotWarnForPortExpansion() {
            final String configuredRedirectUri = "https://example.com/";
            final String requestedRedirectUri = "https://example.com:65000/";

            ClientDetails client = createClient("foo", configuredRedirectUri);

            assertThatExceptionOfType(RedirectMismatchException.class).isThrownBy(() -> resolver.resolveRedirect(requestedRedirectUri, client));

            assertThat(logEvents).isEmpty();
        }

        @Test
        void doesNotWarnWhenThereIsNoMatch() {
            final String configuredRedirectUri = "https://example.com";
            final String requestedRedirectUri = "https://other.com";

            ClientDetails client = createClient("foo", configuredRedirectUri);

            assertThatExceptionOfType(RedirectMismatchException.class).isThrownBy(() -> resolver.resolveRedirect(requestedRedirectUri, client));

            assertThat(logEvents).isEmpty();
        }
    }

    @Nested
    @DisplayName("matching http://domain.com")
    class WhenMatchingAgainstJustTLD {
        private final String clientRedirectUri = "http://domain.com";

        @Test
        void allSubdomainsShouldMatch() {
            assertThat(resolver.redirectMatches("http://subdomain.domain.com", clientRedirectUri)).isTrue();
            assertThat(resolver.redirectMatches("http://another-subdomain.domain.com", clientRedirectUri)).isTrue();
            assertThat(resolver.redirectMatches("http://one.two.domain.com", clientRedirectUri)).isTrue();
        }

        @Test
        void allPathsShouldMatch() {
            assertThat(resolver.redirectMatches("http://domain.com/one", clientRedirectUri)).isTrue();
            assertThat(resolver.redirectMatches("http://domain.com/another", clientRedirectUri)).isTrue();
            assertThat(resolver.redirectMatches("http://domain.com/one/two", clientRedirectUri)).isTrue();
        }

        @Test
        void allPathsInAnySubdomainShouldMatch() {
            assertThat(resolver.redirectMatches("http://subdomain.domain.com/one", clientRedirectUri)).isTrue();
            assertThat(resolver.redirectMatches("http://subdomain.domain.com/another", clientRedirectUri)).isTrue();
            assertThat(resolver.redirectMatches("http://subdomain.domain.com/one/two", clientRedirectUri)).isTrue();

            assertThat(resolver.redirectMatches("http://another-subdomain.domain.com/one", clientRedirectUri)).isTrue();
            assertThat(resolver.redirectMatches("http://another-subdomain.domain.com/another", clientRedirectUri)).isTrue();
            assertThat(resolver.redirectMatches("http://another-subdomain.domain.com/one/two", clientRedirectUri)).isTrue();

            assertThat(resolver.redirectMatches("http://one.two.domain.com/one", clientRedirectUri)).isTrue();
            assertThat(resolver.redirectMatches("http://one.two.domain.com/another", clientRedirectUri)).isTrue();
            assertThat(resolver.redirectMatches("http://one.two.domain.com/one/two", clientRedirectUri)).isTrue();
        }

        @Test
        void doesNotMatchDifferentTld() {
            assertThat(resolver.redirectMatches("http://other-domain.com", clientRedirectUri)).isFalse();
            assertThat(resolver.redirectMatches("http://domain.io", clientRedirectUri)).isFalse();
        }

        @Test
        void doesNotMatchDifferentProtocol() {
            assertThat(resolver.redirectMatches("https://domain.com", clientRedirectUri)).isFalse();
            assertThat(resolver.redirectMatches("ws://domain.com", clientRedirectUri)).isFalse();
        }
    }

    @Nested
    @DisplayName("matching http://domain.com/*")
    class WhenMatchingWithSinglePathPattern {
        private final String clientRedirectUri = "http://domain.com/*";

        @Test
        void shouldNotMatchSubdomains() {
            assertThat(resolver.redirectMatches("http://subdomain.domain.com", clientRedirectUri)).isFalse();
            assertThat(resolver.redirectMatches("http://another-subdomain.domain.com", clientRedirectUri)).isFalse();
            assertThat(resolver.redirectMatches("http://one.two.domain.com", clientRedirectUri)).isFalse();
        }

        @Test
        void allPathsShouldMatch() {
            assertThat(resolver.redirectMatches("http://domain.com/one", clientRedirectUri)).isTrue();
            assertThat(resolver.redirectMatches("http://domain.com/another", clientRedirectUri)).isTrue();
            assertThat(resolver.redirectMatches("http://domain.com/one/two", clientRedirectUri)).isFalse();
        }

        @Test
        void shouldNotMatchSubdomainsWithPaths() {
            assertThat(resolver.redirectMatches("http://subdomain.domain.com/one", clientRedirectUri)).isFalse();
            assertThat(resolver.redirectMatches("http://subdomain.domain.com/another", clientRedirectUri)).isFalse();
            assertThat(resolver.redirectMatches("http://subdomain.domain.com/one/two", clientRedirectUri)).isFalse();

            assertThat(resolver.redirectMatches("http://another-subdomain.domain.com/one", clientRedirectUri)).isFalse();
            assertThat(resolver.redirectMatches("http://another-subdomain.domain.com/another", clientRedirectUri)).isFalse();
            assertThat(resolver.redirectMatches("http://another-subdomain.domain.com/one/two", clientRedirectUri)).isFalse();

            assertThat(resolver.redirectMatches("http://one.two.domain.com/one", clientRedirectUri)).isFalse();
            assertThat(resolver.redirectMatches("http://one.two.domain.com/another", clientRedirectUri)).isFalse();
            assertThat(resolver.redirectMatches("http://one.two.domain.com/one/two", clientRedirectUri)).isFalse();
        }

        @Test
        void doesNotMatchDifferentTld() {
            assertThat(resolver.redirectMatches("http://other-domain.com", clientRedirectUri)).isFalse();
            assertThat(resolver.redirectMatches("http://domain.io", clientRedirectUri)).isFalse();
        }

        @Test
        void doesNotMatchDifferentProtocol() {
            assertThat(resolver.redirectMatches("https://domain.com", clientRedirectUri)).isFalse();
            assertThat(resolver.redirectMatches("ws://domain.com", clientRedirectUri)).isFalse();
        }
    }

    @Nested
    @DisplayName("matching http://domain.com/**")
    class WhenMatchingWithAllSubPathsPattern {
        private final String clientRedirectUri = "http://domain.com/**";

        @Test
        void shouldNotMatchSubdomains() {
            assertThat(resolver.redirectMatches("http://subdomain.domain.com", clientRedirectUri)).isFalse();
            assertThat(resolver.redirectMatches("http://another-subdomain.domain.com", clientRedirectUri)).isFalse();
            assertThat(resolver.redirectMatches("http://one.two.domain.com", clientRedirectUri)).isFalse();
        }

        @Test
        void allPathsShouldMatch() {
            assertThat(resolver.redirectMatches("http://domain.com/one", clientRedirectUri)).isTrue();
            assertThat(resolver.redirectMatches("http://domain.com/another", clientRedirectUri)).isTrue();
            assertThat(resolver.redirectMatches("http://domain.com/one/two", clientRedirectUri)).isTrue();
        }

        @Test
        void shouldNotMatchSubdomainsWithPaths() {
            assertThat(resolver.redirectMatches("http://subdomain.domain.com/one", clientRedirectUri)).isFalse();
            assertThat(resolver.redirectMatches("http://subdomain.domain.com/another", clientRedirectUri)).isFalse();
            assertThat(resolver.redirectMatches("http://subdomain.domain.com/one/two", clientRedirectUri)).isFalse();

            assertThat(resolver.redirectMatches("http://another-subdomain.domain.com/one", clientRedirectUri)).isFalse();
            assertThat(resolver.redirectMatches("http://another-subdomain.domain.com/another", clientRedirectUri)).isFalse();
            assertThat(resolver.redirectMatches("http://another-subdomain.domain.com/one/two", clientRedirectUri)).isFalse();

            assertThat(resolver.redirectMatches("http://one.two.domain.com/one", clientRedirectUri)).isFalse();
            assertThat(resolver.redirectMatches("http://one.two.domain.com/another", clientRedirectUri)).isFalse();
            assertThat(resolver.redirectMatches("http://one.two.domain.com/one/two", clientRedirectUri)).isFalse();
        }

        @Test
        void doesNotMatchDifferentTld() {
            assertThat(resolver.redirectMatches("http://other-domain.com", clientRedirectUri)).isFalse();
            assertThat(resolver.redirectMatches("http://domain.io", clientRedirectUri)).isFalse();
        }

        @Test
        void doesNotMatchDifferentProtocol() {
            assertThat(resolver.redirectMatches("https://domain.com", clientRedirectUri)).isFalse();
            assertThat(resolver.redirectMatches("ws://domain.com", clientRedirectUri)).isFalse();
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

            assertThat(resolver.redirectMatches("http://subdomain.domain.com/", clientRedirectUri)).isTrue();
            assertThat(resolver.redirectMatches("http://subdomain.domain.com/one", clientRedirectUri)).isTrue();
            assertThat(resolver.redirectMatches("http://subdomain.domain.com/one/", clientRedirectUri)).isTrue();
            assertThat(resolver.redirectMatches("http://subdomain.domain.com/one/two", clientRedirectUri)).isTrue();
            assertThat(resolver.redirectMatches("http://subdomain.domain.com/one/two/three", clientRedirectUri)).isTrue();
        }

        @Test
        void trailingPath() {
            final String clientRedirectUri = "http://subdomain.domain.com/one";

            assertThat(resolver.redirectMatches("http://subdomain.domain.com/", clientRedirectUri)).isFalse();
            assertThat(resolver.redirectMatches("http://subdomain.domain.com/one", clientRedirectUri)).isTrue();
            assertThat(resolver.redirectMatches("http://subdomain.domain.com/one/", clientRedirectUri)).isTrue();
            assertThat(resolver.redirectMatches("http://subdomain.domain.com/one/two", clientRedirectUri)).isTrue();
            assertThat(resolver.redirectMatches("http://subdomain.domain.com/one/two/three", clientRedirectUri)).isTrue();
        }

        @Test
        void singleTrailingAsterisk() {
            final String clientRedirectUri = "http://subdomain.domain.com/*";

            assertThat(resolver.redirectMatches("http://subdomain.domain.com/", clientRedirectUri)).isTrue();
            assertThat(resolver.redirectMatches("http://subdomain.domain.com/one", clientRedirectUri)).isTrue();
            assertThat(resolver.redirectMatches("http://subdomain.domain.com/one/", clientRedirectUri)).isFalse();
            assertThat(resolver.redirectMatches("http://subdomain.domain.com/one/two", clientRedirectUri)).isFalse();
            assertThat(resolver.redirectMatches("http://subdomain.domain.com/one/two/three", clientRedirectUri)).isFalse();
        }

        @Test
        void singleTrailingAsterisk_withPath() {
            final String clientRedirectUri = "http://subdomain.domain.com/one*";

            assertThat(resolver.redirectMatches("http://subdomain.domain.com/", clientRedirectUri)).isFalse();
            assertThat(resolver.redirectMatches("http://subdomain.domain.com/one", clientRedirectUri)).isTrue();
            assertThat(resolver.redirectMatches("http://subdomain.domain.com/one-foo-bar", clientRedirectUri)).isTrue();
            assertThat(resolver.redirectMatches("http://subdomain.domain.com/one/", clientRedirectUri)).isFalse();
            assertThat(resolver.redirectMatches("http://subdomain.domain.com/one/two", clientRedirectUri)).isFalse();
            assertThat(resolver.redirectMatches("http://subdomain.domain.com/one/two/three", clientRedirectUri)).isFalse();
        }

        @Test
        void singleAsterisk_insidePath() {
            String clientRedirectUri = "http://subdomain.domain.com/one/*/four";

            assertThat(resolver.redirectMatches("http://subdomain.domain.com/one/four", clientRedirectUri)).isFalse();
            assertThat(resolver.redirectMatches("http://subdomain.domain.com/one/middle/four", clientRedirectUri)).isTrue();
            assertThat(resolver.redirectMatches("http://subdomain.domain.com/one/two/three/four", clientRedirectUri)).isFalse();
        }

        @Test
        void matchesSchemeWildcard() {
            String clientRedirectUri = "http*://subdomain.domain.com/**";

            assertThat(resolver.redirectMatches(requestedRedirectHttp, clientRedirectUri)).isTrue();
            assertThat(resolver.redirectMatches(requestedRedirectHttps, clientRedirectUri)).isTrue();
        }

        @Test
        void matchesSchemeHttp() {
            String clientRedirectUri = "http://subdomain.domain.com/**";

            assertThat(resolver.redirectMatches(requestedRedirectHttp, clientRedirectUri)).isTrue();
            assertThat(resolver.redirectMatches(requestedRedirectHttps, clientRedirectUri)).isFalse();
        }

        @Test
        void matchesSchemeHttps() {
            String clientRedirectUri = "https://subdomain.domain.com/**";

            assertThat(resolver.redirectMatches(requestedRedirectHttp, clientRedirectUri)).isFalse();
            assertThat(resolver.redirectMatches(requestedRedirectHttps, clientRedirectUri)).isTrue();
        }

        @Test
        void matchesSchemeCustom() {
            assertThat(resolver.redirectMatches("myapp://callback", "myapp://callback")).isTrue();
            assertThat(resolver.redirectMatches("myapp://callback#token=xyz123", "myapp://callback*")).isTrue();
        }

        @Test
        void matchesPathContainingAntPathMatcher() {
            String clientRedirectUri = "http*://subdomain.domain.com/path1/path2**";

            assertThat(resolver.redirectMatches(requestedRedirectHttp, clientRedirectUri)).isTrue();
            assertThat(resolver.redirectMatches(requestedRedirectHttps, clientRedirectUri)).isTrue();

            clientRedirectUri = "http*://subdomain.domain.com/path1/<invalid>**";

            assertThat(resolver.redirectMatches(requestedRedirectHttp, clientRedirectUri)).isFalse();
            assertThat(resolver.redirectMatches(requestedRedirectHttps, clientRedirectUri)).isFalse();
        }

        @Test
        void matchesHashFragments() {
            assertThat(resolver.redirectMatches("http://uaa.com/#fragment", "http://uaa.com")).isTrue();
        }

        @Test
        void redirectSubdomain() {
            String clientRedirectUri = "http*://*.domain.com/path1/path2**";

            assertThat(resolver.redirectMatches(requestedRedirectHttps, clientRedirectUri)).isTrue();
            assertThat(resolver.redirectMatches(requestedRedirectHttp, clientRedirectUri)).isTrue();

            clientRedirectUri = "http*://*.domain.com/path1/<invalid>**";

            assertThat(resolver.redirectMatches(requestedRedirectHttps, clientRedirectUri)).isFalse();
            assertThat(resolver.redirectMatches(requestedRedirectHttp, clientRedirectUri)).isFalse();
        }

        @Test
        void redirectSupportsMultipleSubdomainWildcards() {
            String clientRedirectUri = "http://*.*.domain.com/";
            assertThat(resolver.redirectMatches("http://sub1.sub2.domain.com/", clientRedirectUri)).isTrue();
        }

        @Test
        void subdomainMatchingRejectsDomainRedirectOnWildcardSubdomain() {
            String clientRedirectUri = "http://*.domain.com/";
            assertThat(resolver.redirectMatches("http://other-domain.com?stuff.domain.com/", clientRedirectUri)).isFalse();
        }

        @Test
        void subdomainMatchingRejectsDomainRedirectOnMultilevelWildcardSubdomain() {
            String clientRedirectUri = "http://**.domain.com/";
            assertThat(resolver.redirectMatches("http://other-domain.com?stuff.domain.com/", clientRedirectUri)).isFalse();
        }

        @Test
        void subdomainMatchingRejectsDomainRedirectOnWildcardSuffixedSubdomain() {
            String clientRedirectUri = "http://sub*.example.com";
            assertThat(resolver.redirectMatches("http://sub.other-domain.com?stuff.example.com", clientRedirectUri)).isFalse();
        }

        @Test
        void subdomainMatchingDoesNotBlowUpWhenRequestedRedirectIsShorterThanConfiguredRedirect() {
            String clientRedirectUri = "http://sub*.domain.com/";
            assertThat(resolver.redirectMatches("http://domain.com/", clientRedirectUri)).isFalse();
        }

        @Test
        void subdomainMatchingOnWildcardSubdomainWithBasicAuth() {
            String clientRedirectUri = "http://u:p@*.domain.com/";
            assertThat(resolver.redirectMatches("http://u:p@sub.domain.com/", clientRedirectUri)).isTrue();
        }

        @Test
        void matchesHostsWithPort() {
            String clientRedirectUri = "http://*.domain.com:8080/";
            assertThat(resolver.redirectMatches("http://any.domain.com:8080/", clientRedirectUri)).isTrue();
        }

        @Test
        void subdomainMatchingRejectsDomainRedirectOnAntPathVariableSubdomain() {
            String clientRedirectUri = "http://foo.*.domain.com/";
            assertThat(resolver.redirectMatches("http://other-domain.com?stuff.domain.com/", clientRedirectUri)).isFalse();
        }

        @Test
        void matchesPortWithWildcardPort() {
            final String clientRedirectUri = "https://example.com:*/";
            assertThat(resolver.redirectMatches("https://example.com:65000/", clientRedirectUri)).isTrue();
        }

        @Test
        void matchesPortWithWildcardPortAndPath() {
            final String clientRedirectUri = "https://example.com:*/**";
            assertThat(resolver.redirectMatches("https://example.com:65000/path/subpath", clientRedirectUri)).isTrue();
        }

        @Test
        void matchesEmptyPortWithWildcardPort() {
            final String clientRedirectUri = "https://example.com:*/";
            assertThat(resolver.redirectMatches("https://example.com:80/", clientRedirectUri)).isTrue();
            assertThat(resolver.redirectMatches("https://example.com/", clientRedirectUri)).isFalse();
        }

        @Test
        void matchesEmptyPortWithWildcardPortAndPath() {
            final String clientRedirectUri = "https://example.com:*/**";
            assertThat(resolver.redirectMatches("https://example.com:80/path1/path2/path3", clientRedirectUri)).isTrue();
            assertThat(resolver.redirectMatches("https://example.com/path1/path2/path3", clientRedirectUri)).isFalse();
        }

        @Test
        void illegalUnderscoreDomain() {
            final String clientRedirectUri = "http*://*.example.com/**";
            assertThat(resolver.redirectMatches("https://invalid_redirect.example.com/login/callback", clientRedirectUri)).isFalse();
        }

        @Test
        void legalDomain() {
            final String clientRedirectUri = "http*://*.example.com/**";
            assertThat(resolver.redirectMatches("https://valid-redirect.example.com/login/callback", clientRedirectUri)).isTrue();
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

            assertThat(resolver.redirectMatches("http://subdomain.domain.com", clientRedirectUri)).isTrue();
            assertThat(resolver.redirectMatches("http://subdomain.domain.com:8080", clientRedirectUriPort)).isTrue();
            assertThat(resolver.redirectMatches("http://subdomain.domain.com/bee/Bop", clientRedirectUriPath)).isTrue();
            assertThat(resolver.redirectMatches("http://subdomain.domain.com?rock=Steady", clientRedirectUriQuery)).isTrue();
            assertThat(resolver.redirectMatches("http://subdomain.domain.com#Shredder", clientRedirectUriFragment)).isTrue();
        }

        @Test
        void withRequestedHostCaps() {
            final String clientRedirectUri = "http://subdomain.domain.com";
            final String clientRedirectUriPort = "http://subdomain.domain.com:8080";
            final String clientRedirectUriPath = "http://subdomain.domain.com/bee/Bop";
            final String clientRedirectUriQuery = "http://subdomain.domain.com?rock=Steady";
            final String clientRedirectUriFragment = "http://subdomain.domain.com";

            assertThat(resolver.redirectMatches("http://sUBdOMAIN.dOMAIN.com", clientRedirectUri)).isTrue();
            assertThat(resolver.redirectMatches("http://sUBdOMAIN.dOMAIN.com:8080", clientRedirectUriPort)).isTrue();
            assertThat(resolver.redirectMatches("http://sUBdOMAIN.dOMAIN.com/bee/Bop", clientRedirectUriPath)).isTrue();
            assertThat(resolver.redirectMatches("http://sUBdOMAIN.dOMAIN.com?rock=Steady", clientRedirectUriQuery)).isTrue();
            assertThat(resolver.redirectMatches("http://sUBdOMAIN.dOMAIN.com#Shredder", clientRedirectUriFragment)).isTrue();
        }

        @Test
        void withWildCardHostCaps() {
            final String clientRedirectUri = "http://SubDomain.Domain.com/**";
            final String clientRedirectUriPort = "http://SubDomain.Domain.com:8080/**";
            final String clientRedirectUriPath = "http://SubDomain.Domain.com/bee/Bop/**";

            assertThat(resolver.redirectMatches("http://sUBdOMAIN.dOMAIN.com", clientRedirectUri)).isTrue();
            assertThat(resolver.redirectMatches("http://sUBdOMAIN.dOMAIN.com:8080/", clientRedirectUriPort)).isTrue();
            assertThat(resolver.redirectMatches("http://sUBdOMAIN.dOMAIN.com/bee/Bop/", clientRedirectUriPath)).isTrue();
        }
    }

    @Nested
    class ResolveRedirect {
        private ClientDetails mockClientDetails;

        @BeforeEach
        void setUp() {
            mockClientDetails = mock(UaaClientDetails.class);
            when(mockClientDetails.getAuthorizedGrantTypes()).thenReturn(Collections.singleton(GRANT_TYPE_AUTHORIZATION_CODE));
        }

        @Test
        void clientMissingRedirectUri() {
            when(mockClientDetails.getRegisteredRedirectUri()).thenReturn(new HashSet<>());

            assertThatThrownBy(() -> resolver.resolveRedirect("http://somewhere.com", mockClientDetails))
                    .isInstanceOf(RedirectMismatchException.class)
                    .hasMessageContaining("Client registration is missing redirect_uri");
        }

        @Test
        void clientWithInvalidRedirectUri() {
            final String invalidRedirectUri = "*, */*";
            mockRegisteredRedirectUri(invalidRedirectUri);

            assertThatThrownBy(() -> resolver.resolveRedirect("http://somewhere.com", mockClientDetails))
                    .isInstanceOf(RedirectMismatchException.class)
                    .hasMessageContaining("Client registration contains invalid redirect_uri")
                    .hasMessageContaining(invalidRedirectUri);
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
            assertThat(resolver.redirectMatches(BASE_URI + requestedSuffix, BASE_URI)).isTrue();
            assertThat(resolver.redirectMatches(BASE_URI + requestedSuffix, BASE_URI + "/**")).isTrue();
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
            assertThat(resolver.redirectMatches(BASE_URI + requestedSuffix, BASE_URI)).isFalse();
            assertThat(resolver.redirectMatches(BASE_URI + requestedSuffix, BASE_URI + "/**")).isFalse();
        }
    }
}
