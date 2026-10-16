package org.cloudfoundry.identity.uaa.provider.oauth;

import org.assertj.core.api.InstanceOfAssertFactories;
import com.nimbusds.jose.jwk.JWKSet;
import org.cloudfoundry.identity.uaa.cache.UrlContentCache;
import org.cloudfoundry.identity.uaa.client.ClientJwtConfiguration;
import org.cloudfoundry.identity.uaa.impl.config.RestTemplateConfig;
import org.cloudfoundry.identity.uaa.oauth.jwk.JsonWebKey;
import org.cloudfoundry.identity.uaa.oauth.jwk.JsonWebKeySet;
import org.cloudfoundry.identity.uaa.provider.OIDCIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.security.IdpOutboundTrustCache;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.util.StubClientHttpRequestFactory;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.mockito.Answers;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.web.client.HttpServerErrorException;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.DefaultUriBuilderFactory;

import java.net.MalformedURLException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.atomic.AtomicLong;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.awaitility.Awaitility.await;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

class OidcMetadataFetcherTest {
    private static final int MAX_DISCOVERY_RESPONSE_SIZE = 1024 * 1024;
    private static final byte[] JWKS = "{\"keys\":[{\"alg\":\"RS256\",\"e\":\"e\",\"kid\":\"id\",\"kty\":\"RSA\",\"n\":\"n\"}]}".getBytes(StandardCharsets.UTF_8);

    private OidcMetadataFetcher metadataDiscoverer;
    private UrlContentCache urlContentCache;
    private RestTemplate restTemplate;
    private StubClientHttpRequestFactory remote;

    private OIDCIdentityProviderDefinition definition;

    @BeforeEach
    void setUp() {
        urlContentCache = mock(UrlContentCache.class, Answers.CALLS_REAL_METHODS);
        restTemplate = mock(RestTemplate.class, Answers.RETURNS_DEEP_STUBS);
        remote = new StubClientHttpRequestFactory();
        when(restTemplate.getRequestFactory()).thenReturn(remote);
        when(restTemplate.getUriTemplateHandler()).thenReturn(new DefaultUriBuilderFactory());

        metadataDiscoverer = new OidcMetadataFetcher(urlContentCache, restTemplate, restTemplate);
        definition = new OIDCIdentityProviderDefinition();
    }

    @Test
    void destroy_shutsDownDedicatedJwksRefreshExecutor() {
        assertThat(metadataDiscoverer.jwksRefreshExecutor().isShutdown()).isFalse();

        metadataDiscoverer.destroy();

        assertThat(metadataDiscoverer.jwksRefreshExecutor().isShutdown()).isTrue();
    }

    @Nested
    class WithDiscoveryUrl {

        private OidcMetadata oidcMetadata;

        @BeforeEach
        void setup() throws MalformedURLException {
            definition.setDiscoveryUrl(URI.create("http://discovery.url").toURL());
            oidcMetadata = new OidcMetadata();

            oidcMetadata.setAuthorizationEndpoint(URI.create("http://authz.endpoint").toURL());
            oidcMetadata.setTokenEndpoint(URI.create("http://token.endpoint").toURL());
            oidcMetadata.setUserinfoEndpoint(URI.create("http://userinfo.endpoint").toURL());
            oidcMetadata.setJsonWebKeysUri(URI.create("http://jwks.uri").toURL());
            oidcMetadata.setIssuer("metadataissuer");
        }

        @Test
        void shouldFavorUsingConfiguredIdentityProviderProperties() throws Exception {
            definition.setAuthUrl(URI.create("http://authz.should.not.have.been.updated").toURL());
            definition.setTokenUrl(URI.create("http://token.should.not.have.been.updated").toURL());
            definition.setUserInfoUrl(URI.create("http://userinfo.should.not.have.been.updated").toURL());
            definition.setTokenKeyUrl(URI.create("http://jwks.should.not.have.been.updated").toURL());
            definition.setIssuer("should-not-have-been-updated");
            when(urlContentCache.getUrlContent(anyString(), any(RestTemplate.class), eq(MAX_DISCOVERY_RESPONSE_SIZE)))
                    .thenReturn(JsonUtils.writeValueAsBytes(oidcMetadata));

            metadataDiscoverer.fetchMetadataAndUpdateDefinition(definition);

            assertThat(definition).isNotNull();
            assertThat(definition.getAuthUrl()).hasToString("http://authz.should.not.have.been.updated");
            assertThat(definition.getTokenUrl()).hasToString("http://token.should.not.have.been.updated");
            assertThat(definition.getUserInfoUrl()).hasToString("http://userinfo.should.not.have.been.updated");
            assertThat(definition.getTokenKeyUrl()).hasToString("http://jwks.should.not.have.been.updated");
            assertThat(definition.getIssuer()).isEqualTo("should-not-have-been-updated");
        }

        @Test
        void givenConfiguredIdentityProviderPropertiesAreNotSet_shouldUseOidcMetadata() throws Exception {
            when(urlContentCache.getUrlContent(anyString(), any(RestTemplate.class), eq(MAX_DISCOVERY_RESPONSE_SIZE)))
                    .thenReturn(JsonUtils.writeValueAsBytes(oidcMetadata));

            metadataDiscoverer.fetchMetadataAndUpdateDefinition(definition);

            assertThat(definition).isNotNull();
            assertThat(definition.getAuthUrl()).hasToString("http://authz.endpoint");
            assertThat(definition.getTokenUrl()).hasToString("http://token.endpoint");
            assertThat(definition.getUserInfoUrl()).hasToString("http://userinfo.endpoint");
            assertThat(definition.getTokenKeyUrl()).hasToString("http://jwks.uri");
            assertThat(definition.getIssuer()).isEqualTo("metadataissuer");
        }

        @Test
        void shouldPerformDiscoveryUsingCache() throws Exception {
            definition.setAuthUrl(URI.create("http://should.be.updated").toURL());
            definition.setTokenUrl(URI.create("http://should.be.updated").toURL());
            definition.setSkipSslValidation(false);

            when(urlContentCache.getUrlContent(anyString(), any(RestTemplate.class), eq(MAX_DISCOVERY_RESPONSE_SIZE)))
                    .thenReturn(JsonUtils.writeValueAsBytes(oidcMetadata));

            metadataDiscoverer.fetchMetadataAndUpdateDefinition(definition);
            metadataDiscoverer.fetchMetadataAndUpdateDefinition(definition);

            verify(urlContentCache, times(2))
                    .getUrlContent(
                            eq(definition.getDiscoveryUrl().toString()), eq(restTemplate), eq(MAX_DISCOVERY_RESPONSE_SIZE)
                    );
        }

        @Test
        void shouldPerformTokenKeyUrlUsingCache() throws Exception {
            definition.setTokenKeyUrl(URI.create("http://should.be.updated").toURL());
            definition.setSkipSslValidation(false);

            remote.respond(HttpStatus.OK, JWKS);

            metadataDiscoverer.fetchWebKeySet(definition);
            metadataDiscoverer.fetchWebKeySet(definition);

            // It should only execute once because of the internal Caffeine cache
            assertThat(remote.requests()).hasSize(1);
        }

        @Test
        void shouldPerformTokenKeyUrlNoCacheUsed() throws Exception {
            definition.setTokenKeyUrl(URI.create("http://should.be.updated").toURL());
            definition.setSkipSslValidation(false);
            definition.setCacheJwks(false);

            remote.respond(HttpStatus.OK, JWKS);

            metadataDiscoverer.fetchWebKeySet(definition);
            definition.setSkipSslValidation(true);
            metadataDiscoverer.fetchWebKeySet(definition);

            // Should execute twice because cache is disabled
            assertThat(remote.requests()).hasSize(2);
        }

        @Test
        void shouldPerformTokenKeyUrlNoCacheUsedError() throws Exception {
            definition.setTokenKeyUrl(URI.create("http://should.be.updated").toURL());
            definition.setSkipSslValidation(false);
            definition.setCacheJwks(false);

            remote.respond(HttpStatus.NO_CONTENT, new byte[0]);

            assertThatThrownBy(() -> metadataDiscoverer.fetchWebKeySet(definition))
                    .asInstanceOf(InstanceOfAssertFactories.throwable(IllegalArgumentException.class));

            assertThat(remote.requests()).hasSize(1);
        }

    }

    @Nested
    class WithResponseSizeLimit {
        private static final int MAX_JWKS_RESPONSE_SIZE = 1024 * 1024;
        private static final String VALID_JWKS = "{\"keys\":[{\"alg\":\"RS256\",\"e\":\"e\",\"kid\":\"id\",\"kty\":\"RSA\",\"n\":\"n\"}]}";

        @BeforeEach
        void setup() throws MalformedURLException {
            definition.setTokenKeyUrl(URI.create("http://token_keys").toURL());
            definition.setCacheJwks(false);
        }

        @Test
        void fetchWebKeySet_readsBodyAndSendsJsonAcceptHeader() throws Exception {
            remote.respond(HttpStatus.OK, VALID_JWKS.getBytes(StandardCharsets.UTF_8));

            JsonWebKeySet<JsonWebKey> keys = metadataDiscoverer.fetchWebKeySet(definition);

            assertThat(keys.getKeys()).singleElement()
                    .extracting(JsonWebKey::getKid).isEqualTo("id");
            assertThat(remote.requests()).singleElement().satisfies(request -> {
                assertThat(request.getURI()).isEqualTo(URI.create("http://token_keys"));
                assertThat(request.getMethod()).isEqualTo(HttpMethod.GET);
                assertThat(request.getHeaders().getFirst(HttpHeaders.ACCEPT)).isEqualTo("application/json,application/jwk-set+json");
            });
        }

        @Test
        void fetchWebKeySet_whenContentLengthExceedsLimit_rejectsWithoutReadingBody() {
            HttpHeaders headers = new HttpHeaders();
            headers.setContentLength(MAX_JWKS_RESPONSE_SIZE + 1L);
            // a valid body that would parse if it were read
            remote.respond(HttpStatus.OK, headers, VALID_JWKS.getBytes(StandardCharsets.UTF_8));

            assertThatThrownBy(() -> metadataDiscoverer.fetchWebKeySet(definition))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessage("Response exceeds maximum allowed size");
        }

        @Test
        void fetchWebKeySet_whenErrorBodyIsHuge_readsOnlyABoundedPrefix() {
            remote.respond(HttpStatus.INTERNAL_SERVER_ERROR, new byte[MAX_JWKS_RESPONSE_SIZE * 10]);

            assertThatThrownBy(() -> metadataDiscoverer.fetchWebKeySet(definition))
                    .isInstanceOfSatisfying(HttpServerErrorException.class,
                            e -> assertThat(e.getResponseBodyAsByteArray()).hasSize(4 * 1024));
        }

        @Test
        void fetchWebKeySet_whenStreamedBodyExceedsLimit_rejects() throws Exception {
            remote.respond(HttpStatus.OK, new byte[MAX_JWKS_RESPONSE_SIZE + 1]);

            assertThatThrownBy(() -> metadataDiscoverer.fetchWebKeySet(definition))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessage("Response exceeds maximum allowed size");
        }

        @Test
        void fetchWebKeySet_whenStreamedBodyIsExactlyAtLimit_isRead() throws Exception {
            byte[] body = new byte[MAX_JWKS_RESPONSE_SIZE];
            Arrays.fill(body, (byte) ' ');
            byte[] jwks = VALID_JWKS.getBytes(StandardCharsets.UTF_8);
            System.arraycopy(jwks, 0, body, 0, jwks.length);
            remote.respond(HttpStatus.OK, body);

            assertThat(metadataDiscoverer.fetchWebKeySet(definition).getKeys()).hasSize(1);
        }

        @Test
        void fetchWebKeySet_whenIdpKeySetHasTooManyKeys_rejectsBeforeParsingKeys() {
            remote.respond(HttpStatus.OK, jwksWithKeys(101));

            assertThatThrownBy(() -> metadataDiscoverer.fetchWebKeySet(definition))
                    .isInstanceOf(OidcMetadataFetchingException.class)
                    .hasMessage("JWK set has 101 keys, maximum is 100");
        }

        @Test
        void fetchWebKeySet_whenOversizedKeysArrayHidesBehindEmptyDuplicate_rejects() {
            String oversized = new String(jwksWithKeys(101), StandardCharsets.UTF_8);
            remote.respond(HttpStatus.OK, ("{\"keys\":[]," + oversized.substring(1)).getBytes(StandardCharsets.UTF_8));

            assertThatThrownBy(() -> metadataDiscoverer.fetchWebKeySet(definition))
                    .isInstanceOf(OidcMetadataFetchingException.class)
                    .hasRootCauseMessage("Duplicate \"keys\" member in JWK set");
        }

        @Test
        void fetchClientWebKeySet_whenOversizedKeysArrayHidesBehindEmptyDuplicate_rejects() {
            String oversized = new String(jwksWithKeys(ClientJwtConfiguration.MAX_KEY_SIZE + 1), StandardCharsets.UTF_8);
            remote.respond(HttpStatus.OK, ("{\"keys\":[]," + oversized.substring(1)).getBytes(StandardCharsets.UTF_8));

            assertThatThrownBy(() -> metadataDiscoverer.fetchWebKeySet(new ClientJwtConfiguration("http://localhost/token_keys", null)))
                    .isInstanceOf(OidcMetadataFetchingException.class)
                    .hasRootCauseMessage("Duplicate \"keys\" member in JWK set");
        }

        @Test
        void fetchClientWebKeySet_whenEscapedKeysNameHidesTooManyKeys_rejectsBeforeParsingKeys() {
            String json = new String(jwksWithKeys(ClientJwtConfiguration.MAX_KEY_SIZE + 1), StandardCharsets.UTF_8)
                    .replaceFirst("\"keys\"", "\"\\\\u006beys\"");
            assertThat(json).startsWith("{\"\\u006beys\":[");
            remote.respond(HttpStatus.OK, json.getBytes(StandardCharsets.UTF_8));

            assertThatThrownBy(() -> metadataDiscoverer.fetchWebKeySet(new ClientJwtConfiguration("http://localhost/token_keys", null)))
                    .isInstanceOf(OidcMetadataFetchingException.class)
                    .hasMessage("JWK set has 11 keys, maximum is 10");
        }

        @Test
        void fetchWebKeySet_whenIdpKeySetIsAtKeyLimit_isAccepted() throws Exception {
            remote.respond(HttpStatus.OK, jwksWithKeys(100));

            assertThat(metadataDiscoverer.fetchWebKeySet(definition).getKeys()).hasSize(100);
        }

        @Test
        void fetchClientWebKeySet_whenKeySetHasMoreThanClientKeyLimit_rejectsBeforeParsingKeys() {
            remote.respond(HttpStatus.OK, jwksWithKeys(ClientJwtConfiguration.MAX_KEY_SIZE + 1));

            assertThatThrownBy(() -> metadataDiscoverer.fetchWebKeySet(new ClientJwtConfiguration("http://localhost/token_keys", null)))
                    .isInstanceOf(OidcMetadataFetchingException.class)
                    .hasMessage("JWK set has 11 keys, maximum is 10");
        }

        private static byte[] jwksWithKeys(int count) {
            StringBuilder json = new StringBuilder("{\"keys\":[");
            for (int i = 0; i < count; i++) {
                json.append(i == 0 ? "" : ",")
                        .append("{\"alg\":\"RS256\",\"e\":\"e\",\"kid\":\"k").append(i).append("\",\"kty\":\"RSA\",\"n\":\"n\"}");
            }
            return json.append("]}").toString().getBytes(StandardCharsets.UTF_8);
        }

        @Test
        void fetchClientWebKeySet_whenStreamedBodyExceedsLimit_rejects() {
            remote.respond(HttpStatus.OK, new byte[MAX_JWKS_RESPONSE_SIZE + 1]);

            assertThatThrownBy(() -> metadataDiscoverer.fetchWebKeySet(new ClientJwtConfiguration("http://localhost/token_keys", null)))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessage("Response exceeds maximum allowed size");
        }
    }

    @Nested
    class WithoutDiscoveryUrl {
        @BeforeEach
        void setup() {
            definition.setDiscoveryUrl(null);
        }

        @Test
        @DisplayName("when the idp is configured without a discovery URL then it should retain the configured OAuth/OIDC endpoints")
        void shouldNotPerformDiscovery() throws Exception {
            definition.setAuthUrl(URI.create("http://authz.not.updated").toURL());
            definition.setTokenUrl(URI.create("http://token.not.updated").toURL());
            definition.setTokenKeyUrl(URI.create("http://jwk.not.updated").toURL());
            definition.setUserInfoUrl(URI.create("http://userinfo.not.updated").toURL());
            definition.setIssuer("issuer-not-changed");

            metadataDiscoverer.fetchMetadataAndUpdateDefinition(definition);

            assertThat(definition).isNotNull();
            assertThat(definition.getDiscoveryUrl()).isNull();
            assertThat(definition.getAuthUrl()).hasToString("http://authz.not.updated");
            assertThat(definition.getTokenUrl()).hasToString("http://token.not.updated");
            assertThat(definition.getTokenKeyUrl()).hasToString("http://jwk.not.updated");
            assertThat(definition.getUserInfoUrl()).hasToString("http://userinfo.not.updated");
            assertThat(definition.getIssuer()).isEqualTo("issuer-not-changed");

            verifyNoInteractions(urlContentCache);
        }

    }

    @Nested
    class WithErrorSituations {
        @BeforeEach
        void setup() throws MalformedURLException {
            definition.setTokenKeyUrl(URI.create("http://token_keys").toURL());
            definition.setSkipSslValidation(true);
            definition.setRelyingPartyId("id");
            definition.setRelyingPartySecret("x");
        }

        @Test
        void failWithEmptyContent() throws Exception {

            remote.respond(HttpStatus.OK, new byte[0]);

            assertThatThrownBy(() -> metadataDiscoverer.fetchWebKeySet(definition)).asInstanceOf(InstanceOfAssertFactories.throwable(OidcMetadataFetchingException.class));
        }

        @Test
        void failWithTruncatedContent_whenUncached() {
            definition.setCacheJwks(false);
            remote.respond(HttpStatus.OK, "{\"keys\":[".getBytes(StandardCharsets.UTF_8));

            assertThatThrownBy(() -> metadataDiscoverer.fetchWebKeySet(definition))
                    .isInstanceOf(OidcMetadataFetchingException.class);
        }

        @Test
        void failWithTruncatedContent_forClientJwksUri() {
            remote.respond(HttpStatus.OK, "{\"keys\":[{\"kty\":\"RSA\"".getBytes(StandardCharsets.UTF_8));

            assertThatThrownBy(() -> metadataDiscoverer.fetchWebKeySet(new ClientJwtConfiguration("http://localhost/token_keys", null)))
                    .isInstanceOf(OidcMetadataFetchingException.class);
        }

        @Test
        void failWithInvalidContent() throws Exception {

            remote.respond(HttpStatus.OK, "{x}".getBytes(StandardCharsets.UTF_8));

            assertThatThrownBy(() -> metadataDiscoverer.fetchWebKeySet(definition)).asInstanceOf(InstanceOfAssertFactories.throwable(OidcMetadataFetchingException.class));
        }
    }

    @Nested
    class WithJwtClientKey {
        @BeforeEach
        void setup() throws MalformedURLException {
            definition.setTokenKeyUrl(URI.create("http://token_keys").toURL());
            definition.setSkipSslValidation(true);
            definition.setRelyingPartyId("id");
            definition.setRelyingPartySecret(null);
            remote.respond(HttpStatus.OK, JWKS);
        }

        @Test
        void getConfigFromJwksUri() throws Exception {

            JsonWebKeySet<JsonWebKey> keys = metadataDiscoverer.fetchWebKeySet(new ClientJwtConfiguration("http://token_keys", null));
            assertThat(keys).isNotNull();
            assertThat(keys.getKeys()).hasSize(1);
            assertThat(keys.getKeys().getFirst().getKid()).isEqualTo("id");
        }

        @Test
        void getConfigFromJwks() throws Exception {

            JsonWebKeySet<JsonWebKey> keys = metadataDiscoverer.fetchWebKeySet(ClientJwtConfiguration.parse("{\"keys\":[{\"alg\":\"RS256\",\"e\":\"e\",\"kid\":\"a\",\"kty\":\"RSA\",\"n\":\"n\"}]}"));
            assertThat(keys).isNotNull();
            assertThat(keys.getKeys()).hasSize(1);
            assertThat(keys.getKeys().getFirst().getKid()).isEqualTo("a");
        }

        @Test
        void failWithInvalidConfig() throws Exception {

            assertThatThrownBy(() -> metadataDiscoverer.fetchWebKeySet(new ClientJwtConfiguration(null, null))).asInstanceOf(InstanceOfAssertFactories.throwable(OidcMetadataFetchingException.class));
        }

        @Test
        void fetchJwkSet_forJwksUri_parsesOnceAndReusesInstance() throws Exception {
            ClientJwtConfiguration clientJwtConfiguration = new ClientJwtConfiguration("http://token_keys", null);

            JWKSet first = metadataDiscoverer.fetchJwkSet(clientJwtConfiguration);
            JWKSet second = metadataDiscoverer.fetchJwkSet(clientJwtConfiguration);

            assertThat(second).isSameAs(first);
            assertThat(first.getKeyByKeyId("id")).isNotNull();
            assertThat(remote.requests()).hasSize(1);
        }

        @Test
        void fetchJwkSet_forInlineJwks_returnsParsedKeys() throws Exception {
            JWKSet keys = metadataDiscoverer.fetchJwkSet(ClientJwtConfiguration.parse("{\"keys\":[{\"alg\":\"RS256\",\"e\":\"e\",\"kid\":\"a\",\"kty\":\"RSA\",\"n\":\"n\"}]}"));

            assertThat(keys.getKeyByKeyId("a")).isNotNull();
            assertThat(remote.requests()).isEmpty();
        }

        @Test
        void fetchJwkSet_forIdpDefinition_parsesOnceAndReusesInstance() throws Exception {
            JWKSet first = metadataDiscoverer.fetchJwkSet(definition);
            JWKSet second = metadataDiscoverer.fetchJwkSet(definition);

            assertThat(second).isSameAs(first);
            assertThat(first.getKeyByKeyId("id")).isNotNull();
            assertThat(metadataDiscoverer.fetchWebKeySet(definition).getKeys()).singleElement()
                    .extracting(JsonWebKey::getKid).isEqualTo("id");
            assertThat(remote.requests()).hasSize(1);
        }

        @Test
        void fetchJwkSet_withoutTokenKeyUrl_returnsEmptySet() throws Exception {
            definition.setTokenKeyUrl(null);

            assertThat(metadataDiscoverer.fetchJwkSet(definition).isEmpty()).isTrue();
            assertThat(remote.requests()).isEmpty();
        }
    }

    @Nested
    class WithJwksCacheRefresh {
        private static final byte[] ROTATED_JWKS = "{\"keys\":[{\"alg\":\"RS256\",\"e\":\"e\",\"kid\":\"rotated\",\"kty\":\"RSA\",\"n\":\"n\"}]}".getBytes(StandardCharsets.UTF_8);
        // Accepted by JsonWebKeyHelper, rejected by Nimbus: key_ops must be an array
        private static final byte[] NIMBUS_REJECTED_JWKS = "{\"keys\":[{\"alg\":\"RS256\",\"e\":\"e\",\"kid\":\"bad\",\"kty\":\"RSA\",\"n\":\"n\",\"key_ops\":\"verify\"}]}".getBytes(StandardCharsets.UTF_8);

        private final AtomicLong nanos = new AtomicLong();
        private final ClientJwtConfiguration clientJwtConfiguration = new ClientJwtConfiguration("http://token_keys", null);

        @BeforeEach
        void setup() throws MalformedURLException {
            metadataDiscoverer = new OidcMetadataFetcher(urlContentCache, restTemplate, restTemplate, restTemplate,
                    new IdpOutboundTrustCache(), RestTemplateConfig.createDefaults(), nanos::get);
            definition.setTokenKeyUrl(URI.create("http://token_keys").toURL());
        }

        @Test
        void idpKeys_whenRefreshFails_keepServingLastGoodKeySetUntilARefreshSucceeds() throws Exception {
            remote.respond(HttpStatus.OK, JWKS)
                    .respond(HttpStatus.INTERNAL_SERVER_ERROR, new byte[0])
                    .respond(HttpStatus.OK, ROTATED_JWKS);
            assertThat(idpKid()).isEqualTo("id");

            advancePastRefresh();

            assertThat(idpKid()).isEqualTo("id");
            await().atMost(Duration.ofSeconds(5)).untilAsserted(() -> assertThat(remote.requests()).hasSize(2));
            await().atMost(Duration.ofSeconds(5)).untilAsserted(() -> assertThat(idpKid()).isEqualTo("rotated"));
            assertThat(metadataDiscoverer.fetchJwkSet(definition).getKeyByKeyId("rotated")).isNotNull();
        }

        @Test
        void clientKeys_whenRefreshFails_keepServingLastGoodKeySetUntilARefreshSucceeds() throws Exception {
            remote.respond(HttpStatus.OK, JWKS)
                    .respond(HttpStatus.INTERNAL_SERVER_ERROR, new byte[0])
                    .respond(HttpStatus.OK, ROTATED_JWKS);
            assertThat(clientKid()).isEqualTo("id");

            advancePastRefresh();

            assertThat(clientKid()).isEqualTo("id");
            await().atMost(Duration.ofSeconds(5)).untilAsserted(() -> assertThat(remote.requests()).hasSize(2));
            await().atMost(Duration.ofSeconds(5)).untilAsserted(() -> assertThat(clientKid()).isEqualTo("rotated"));
            assertThat(metadataDiscoverer.fetchJwkSet(clientJwtConfiguration).getKeyByKeyId("rotated")).isNotNull();
        }

        @Test
        void idpJwkSet_whenCachedKeySetCannotBeParsed_retriesOnNextRequest() throws Exception {
            remote.respond(HttpStatus.OK, NIMBUS_REJECTED_JWKS)
                    .respond(HttpStatus.OK, JWKS);

            assertThatThrownBy(() -> metadataDiscoverer.fetchJwkSet(definition))
                    .isInstanceOf(OidcMetadataFetchingException.class)
                    .hasMessage("Unable to parse verification keys");

            ThreadPoolExecutor refreshExecutor = (ThreadPoolExecutor) metadataDiscoverer.jwksRefreshExecutor();
            await().atMost(Duration.ofSeconds(5)).untilAsserted(() -> assertThat(remote.requests()).hasSize(2));
            await().atMost(Duration.ofSeconds(5))
                    .until(() -> refreshExecutor.getActiveCount() == 0 && refreshExecutor.getQueue().isEmpty());

            assertThat(metadataDiscoverer.fetchJwkSet(definition).getKeyByKeyId("id")).isNotNull();
            assertThat(remote.requests()).hasSize(2);
        }

        @Test
        void idpWebKeySet_whenCachedKeySetCannotBeParsedByNimbus_isServedWithoutRefetching() throws Exception {
            remote.respond(HttpStatus.OK, NIMBUS_REJECTED_JWKS)
                    .respond(HttpStatus.OK, JWKS);

            assertThat(idpKid()).isEqualTo("bad");
            assertThat(idpKid()).isEqualTo("bad");

            assertThat(remote.requests()).hasSize(1);
        }

        private void advancePastRefresh() {
            nanos.addAndGet(Duration.ofMinutes(11).toNanos());
        }

        private String idpKid() throws OidcMetadataFetchingException {
            return metadataDiscoverer.fetchWebKeySet(definition).getKeys().getFirst().getKid();
        }

        private String clientKid() throws OidcMetadataFetchingException {
            return metadataDiscoverer.fetchWebKeySet(clientJwtConfiguration).getKeys().getFirst().getKid();
        }
    }

    @Nested
    class WithCaCertificates {
        private IdpOutboundTrustCache trustCache;

        @BeforeEach
        void setup() throws MalformedURLException {
            trustCache = mock(IdpOutboundTrustCache.class);
            when(trustCache.resolveRestTemplate(any(), any(), anyBoolean(), anyInt(), anyInt(), any(), any(), any()))
                    .thenReturn(restTemplate);
            metadataDiscoverer = new OidcMetadataFetcher(urlContentCache, restTemplate, restTemplate, restTemplate, trustCache, RestTemplateConfig.createDefaults());
            definition.setDiscoveryUrl(URI.create("http://discovery.url").toURL());
            definition.setCaCertificates(List.of("-----BEGIN CERTIFICATE-----\nfake\n-----END CERTIFICATE-----"));
        }

        @Test
        void discoveryFetch_bypassesSharedUrlCache_whenCaCertificatesSet() throws Exception {
            remote.respond(HttpStatus.OK, JsonUtils.writeValueAsBytes(new OidcMetadata()));

            metadataDiscoverer.fetchMetadataAndUpdateDefinition(definition);

            assertThat(remote.requests()).singleElement().satisfies(request -> {
                assertThat(request.getURI()).isEqualTo(definition.getDiscoveryUrl().toURI());
                assertThat(request.getMethod()).isEqualTo(HttpMethod.GET);
            });
            verifyNoInteractions(urlContentCache);
        }

        @Test
        void discoveryFetch_whenCaCertificatesSet_rejectsOversizedDocument() {
            remote.respond(HttpStatus.OK, new byte[MAX_DISCOVERY_RESPONSE_SIZE + 1]);

            assertThatThrownBy(() -> metadataDiscoverer.fetchMetadataAndUpdateDefinition(definition))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessage("Response exceeds maximum allowed size");
        }

        @Test
        void discoveryFetch_passesCaCertificatesAndIdentityKeyToTrustCache() throws Exception {
            remote.respond(HttpStatus.OK, JsonUtils.writeValueAsBytes(new OidcMetadata()));

            metadataDiscoverer.fetchMetadataAndUpdateDefinition(definition);

            verify(trustCache).resolveRestTemplate(
                    eq(definition.getDiscoveryUrl().toString()),
                    eq(definition.getCaCertificates()),
                    eq(false),
                    anyInt(), anyInt(), any(), eq(restTemplate), eq(restTemplate));
        }

        @Test
        void tokenKeyFetch_bypassesSharedUrlCache_whenCaCertificatesSet() throws Exception {
            definition.setTokenKeyUrl(URI.create("http://token_keys").toURL());
            definition.setRelyingPartyId("id");
            definition.setRelyingPartySecret("secret");
            remote.respond(HttpStatus.OK, JWKS);

            metadataDiscoverer.fetchWebKeySet(definition);

            assertThat(remote.requests()).singleElement().satisfies(request ->
                    assertThat(request.getHeaders().getFirst(HttpHeaders.AUTHORIZATION)).startsWith("Basic "));
            verifyNoInteractions(urlContentCache);
        }

        @Test
        void tokenKeyFetch_withCaCertificates_isCachedWhenCacheJwksEnabled() throws Exception {
            definition.setTokenKeyUrl(URI.create("http://token_keys").toURL());
            definition.setCacheJwks(true);
            remote.respond(HttpStatus.OK, JWKS);

            metadataDiscoverer.fetchWebKeySet(definition);
            metadataDiscoverer.fetchWebKeySet(definition);

            assertThat(remote.requests()).hasSize(1);
        }

        @Test
        void tokenKeyFetch_withCaCertificates_isNotCachedWhenCacheJwksDisabled() throws Exception {
            definition.setTokenKeyUrl(URI.create("http://token_keys").toURL());
            definition.setCacheJwks(false);
            remote.respond(HttpStatus.OK, JWKS);

            metadataDiscoverer.fetchWebKeySet(definition);
            metadataDiscoverer.fetchWebKeySet(definition);

            assertThat(remote.requests()).hasSize(2);
        }

        @Test
        void tokenKeyFetch_withDifferentTrustConfiguration_doesNotShareCacheEntry() throws Exception {
            definition.setTokenKeyUrl(URI.create("http://token_keys").toURL());
            RestTemplate otherTrust = mock(RestTemplate.class, Answers.RETURNS_DEEP_STUBS);
            StubClientHttpRequestFactory otherRemote = new StubClientHttpRequestFactory().respond(HttpStatus.OK, JWKS);
            when(otherTrust.getRequestFactory()).thenReturn(otherRemote);
            when(otherTrust.getUriTemplateHandler()).thenReturn(new DefaultUriBuilderFactory());
            remote.respond(HttpStatus.OK, JWKS);

            metadataDiscoverer.fetchWebKeySet(definition);
            when(trustCache.resolveRestTemplate(any(), any(), anyBoolean(), anyInt(), anyInt(), any(), any(), any()))
                    .thenReturn(otherTrust);
            metadataDiscoverer.fetchWebKeySet(definition);

            assertThat(remote.requests()).hasSize(1);
            assertThat(otherRemote.requests()).hasSize(1);
        }

        @Test
        void skipSslValidationTrue_doesNotBypassSharedUrlCache_evenWithCaCertificatesSet() throws Exception {
            definition.setSkipSslValidation(true);
            when(urlContentCache.getUrlContent(anyString(), any(RestTemplate.class), eq(MAX_DISCOVERY_RESPONSE_SIZE)))
                    .thenReturn(JsonUtils.writeValueAsBytes(new OidcMetadata()));

            metadataDiscoverer.fetchMetadataAndUpdateDefinition(definition);

            verify(urlContentCache).getUrlContent(eq(definition.getDiscoveryUrl().toString()), eq(restTemplate), eq(MAX_DISCOVERY_RESPONSE_SIZE));
            assertThat(remote.requests()).isEmpty();
        }
    }
}
