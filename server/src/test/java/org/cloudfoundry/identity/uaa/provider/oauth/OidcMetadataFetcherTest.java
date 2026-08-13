package org.cloudfoundry.identity.uaa.provider.oauth;

import org.assertj.core.api.InstanceOfAssertFactories;
import org.cloudfoundry.identity.uaa.cache.UrlContentCache;
import org.cloudfoundry.identity.uaa.client.ClientJwtConfiguration;
import org.cloudfoundry.identity.uaa.impl.config.RestTemplateConfig;
import org.cloudfoundry.identity.uaa.oauth.jwk.JsonWebKey;
import org.cloudfoundry.identity.uaa.oauth.jwk.JsonWebKeySet;
import org.cloudfoundry.identity.uaa.provider.OIDCIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.security.IdpOutboundTrustCache;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.mockito.Answers;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.client.RestTemplate;

import java.net.MalformedURLException;
import java.net.URI;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

class OidcMetadataFetcherTest {
    private OidcMetadataFetcher metadataDiscoverer;
    private UrlContentCache urlContentCache;
    private RestTemplate restTemplate;

    private OIDCIdentityProviderDefinition definition;

    @BeforeEach
    void setUp() {
        urlContentCache = mock(UrlContentCache.class, Answers.CALLS_REAL_METHODS);
        restTemplate = mock(RestTemplate.class, Answers.RETURNS_DEEP_STUBS);

        metadataDiscoverer = new OidcMetadataFetcher(urlContentCache, restTemplate, restTemplate);
        definition = new OIDCIdentityProviderDefinition();
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
            when(urlContentCache.getUrlContent(anyString(), any(RestTemplate.class)))
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
            when(urlContentCache.getUrlContent(anyString(), any(RestTemplate.class)))
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

            when(urlContentCache.getUrlContent(anyString(), any(RestTemplate.class)))
                    .thenReturn(JsonUtils.writeValueAsBytes(oidcMetadata));

            metadataDiscoverer.fetchMetadataAndUpdateDefinition(definition);
            metadataDiscoverer.fetchMetadataAndUpdateDefinition(definition);

            verify(urlContentCache, times(2))
                    .getUrlContent(
                            eq(definition.getDiscoveryUrl().toString()), eq(restTemplate)
                    );
        }

        @Test
        void shouldPerformTokenKeyUrlUsingCache() throws Exception {
            definition.setTokenKeyUrl(URI.create("http://should.be.updated").toURL());
            definition.setSkipSslValidation(false);

            when(urlContentCache.getUrlContent(anyString(), any(RestTemplate.class), any(HttpMethod.class), any(HttpEntity.class)))
                    .thenReturn("{\"keys\":[{\"alg\":\"RS256\",\"e\":\"e\",\"kid\":\"id\",\"kty\":\"RSA\",\"n\":\"n\"}]}".getBytes());

            metadataDiscoverer.fetchWebKeySet(definition);
            metadataDiscoverer.fetchWebKeySet(definition);

            verify(urlContentCache, times(2))
                    .getUrlContent(
                            any(), any(), any(), any()
                    );
        }

        @Test
        void shouldPerformTokenKeyUrlNoCacheUsed() throws Exception {
            definition.setTokenKeyUrl(URI.create("http://should.be.updated").toURL());
            definition.setSkipSslValidation(false);
            definition.setCacheJwks(false);

            ResponseEntity<byte[]> responseEntity = mock(ResponseEntity.class);
            when(restTemplate.exchange(anyString(), any(HttpMethod.class), any(HttpEntity.class), any(Class.class)))
                    .thenReturn(responseEntity);
            when(responseEntity.getStatusCode()).thenReturn(HttpStatus.OK);
            when(responseEntity.getBody()).thenReturn("{\"keys\":[{\"alg\":\"RS256\",\"e\":\"e\",\"kid\":\"id\",\"kty\":\"RSA\",\"n\":\"n\"}]}".getBytes());

            metadataDiscoverer.fetchWebKeySet(definition);
            definition.setSkipSslValidation(true);
            metadataDiscoverer.fetchWebKeySet(definition);

            verify(urlContentCache, times(0))
                    .getUrlContent(
                            any(), any(), any(), any()
                    );
            verify(restTemplate, times(2)).exchange(anyString(), any(HttpMethod.class), any(HttpEntity.class), any(Class.class));
        }

        @Test
        void shouldPerformTokenKeyUrlNoCacheUsedError() throws Exception {
            definition.setTokenKeyUrl(URI.create("http://should.be.updated").toURL());
            definition.setSkipSslValidation(false);
            definition.setCacheJwks(false);

            ResponseEntity<byte[]> responseEntity = mock(ResponseEntity.class);
            when(restTemplate.exchange(anyString(), any(HttpMethod.class), any(HttpEntity.class), any(Class.class)))
                    .thenReturn(responseEntity);
            when(responseEntity.getStatusCode()).thenReturn(HttpStatus.FORBIDDEN);

            assertThatThrownBy(() -> metadataDiscoverer.fetchWebKeySet(definition)).asInstanceOf(InstanceOfAssertFactories.throwable(IllegalArgumentException.class));

            verify(urlContentCache, times(0))
                    .getUrlContent(
                            any(), any(), any(), any()
                    );
            verify(restTemplate, times(1)).exchange(anyString(), any(HttpMethod.class), any(HttpEntity.class), any(Class.class));
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

            when(urlContentCache.getUrlContent(anyString(), any(RestTemplate.class), any(HttpMethod.class), any(HttpEntity.class)))
                    .thenReturn("".getBytes());

            assertThatThrownBy(() -> metadataDiscoverer.fetchWebKeySet(definition)).asInstanceOf(InstanceOfAssertFactories.throwable(OidcMetadataFetchingException.class));
        }

        @Test
        void failWithInvalidContent() throws Exception {

            when(urlContentCache.getUrlContent(anyString(), any(RestTemplate.class), any(HttpMethod.class), any(HttpEntity.class)))
                    .thenReturn("{x}".getBytes());

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
            when(urlContentCache.getUrlContent(anyString(), any(RestTemplate.class), any(HttpMethod.class), any(HttpEntity.class)))
                    .thenReturn("{\"keys\":[{\"alg\":\"RS256\",\"e\":\"e\",\"kid\":\"id\",\"kty\":\"RSA\",\"n\":\"n\"}]}".getBytes());
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
            when(restTemplate.getForObject(anyString(), eq(byte[].class)))
                    .thenReturn(JsonUtils.writeValueAsBytes(new OidcMetadata()));

            metadataDiscoverer.fetchMetadataAndUpdateDefinition(definition);

            verify(restTemplate).getForObject(eq(definition.getDiscoveryUrl().toString()), eq(byte[].class));
            verifyNoInteractions(urlContentCache);
        }

        @Test
        void discoveryFetch_passesCaCertificatesAndIdentityKeyToTrustCache() throws Exception {
            when(restTemplate.getForObject(anyString(), eq(byte[].class)))
                    .thenReturn(JsonUtils.writeValueAsBytes(new OidcMetadata()));

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
            ResponseEntity<byte[]> responseEntity = mock(ResponseEntity.class);
            when(responseEntity.getStatusCode()).thenReturn(HttpStatus.OK);
            when(responseEntity.getBody()).thenReturn("{\"keys\":[{\"alg\":\"RS256\",\"e\":\"e\",\"kid\":\"id\",\"kty\":\"RSA\",\"n\":\"n\"}]}".getBytes());
            when(restTemplate.exchange(anyString(), any(HttpMethod.class), any(HttpEntity.class), any(Class.class)))
                    .thenReturn(responseEntity);

            metadataDiscoverer.fetchWebKeySet(definition);

            verify(restTemplate).exchange(anyString(), any(HttpMethod.class), any(HttpEntity.class), any(Class.class));
            verifyNoInteractions(urlContentCache);
        }

        @Test
        void skipSslValidationTrue_doesNotBypassSharedUrlCache_evenWithCaCertificatesSet() throws Exception {
            definition.setSkipSslValidation(true);
            when(urlContentCache.getUrlContent(anyString(), any(RestTemplate.class)))
                    .thenReturn(JsonUtils.writeValueAsBytes(new OidcMetadata()));

            metadataDiscoverer.fetchMetadataAndUpdateDefinition(definition);

            verify(urlContentCache).getUrlContent(eq(definition.getDiscoveryUrl().toString()), eq(restTemplate));
            verify(restTemplate, never()).getForObject(anyString(), eq(byte[].class));
        }
    }
}
