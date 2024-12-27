package org.cloudfoundry.identity.uaa.provider.oauth;

import org.cloudfoundry.identity.uaa.cache.UrlContentCache;
import org.cloudfoundry.identity.uaa.client.ClientJwtConfiguration;
import org.cloudfoundry.identity.uaa.oauth.jwk.JsonWebKey;
import org.cloudfoundry.identity.uaa.oauth.jwk.JsonWebKeySet;
import org.cloudfoundry.identity.uaa.provider.OIDCIdentityProviderDefinition;
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
import java.net.URL;

import static org.hamcrest.CoreMatchers.*;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

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
            definition.setDiscoveryUrl(new URL("http://discovery.url"));
            oidcMetadata = new OidcMetadata();

            oidcMetadata.setAuthorizationEndpoint(new URL("http://authz.endpoint"));
            oidcMetadata.setTokenEndpoint(new URL("http://token.endpoint"));
            oidcMetadata.setUserinfoEndpoint(new URL("http://userinfo.endpoint"));
            oidcMetadata.setJsonWebKeysUri(new URL("http://jwks.uri"));
            oidcMetadata.setIssuer("metadataissuer");
        }

        @Test
        void shouldFavorUsingConfiguredIdentityProviderProperties() throws OidcMetadataFetchingException, MalformedURLException {
            definition.setAuthUrl(new URL("http://authz.should.not.have.been.updated"));
            definition.setTokenUrl(new URL("http://token.should.not.have.been.updated"));
            definition.setUserInfoUrl(new URL("http://userinfo.should.not.have.been.updated"));
            definition.setTokenKeyUrl(new URL("http://jwks.should.not.have.been.updated"));
            definition.setIssuer("should-not-have-been-updated");
            when(urlContentCache.getUrlContent(anyString(), any(RestTemplate.class)))
                    .thenReturn(JsonUtils.writeValueAsBytes(oidcMetadata));

            metadataDiscoverer.fetchMetadataAndUpdateDefinition(definition);

            assertThat(definition, is(notNullValue()));
            assertThat(definition.getAuthUrl().toString(), is("http://authz.should.not.have.been.updated"));
            assertThat(definition.getTokenUrl().toString(), is("http://token.should.not.have.been.updated"));
            assertThat(definition.getUserInfoUrl().toString(), is("http://userinfo.should.not.have.been.updated"));
            assertThat(definition.getTokenKeyUrl().toString(), is("http://jwks.should.not.have.been.updated"));
            assertThat(definition.getIssuer(), is("should-not-have-been-updated"));
        }

        @Test
        void givenConfiguredIdentityProviderPropertiesAreNotSet_shouldUseOidcMetadata() throws OidcMetadataFetchingException {
            when(urlContentCache.getUrlContent(anyString(), any(RestTemplate.class)))
                    .thenReturn(JsonUtils.writeValueAsBytes(oidcMetadata));

            metadataDiscoverer.fetchMetadataAndUpdateDefinition(definition);

            assertThat(definition, is(notNullValue()));
            assertThat(definition.getAuthUrl().toString(), is("http://authz.endpoint"));
            assertThat(definition.getTokenUrl().toString(), is("http://token.endpoint"));
            assertThat(definition.getUserInfoUrl().toString(), is("http://userinfo.endpoint"));
            assertThat(definition.getTokenKeyUrl().toString(), is("http://jwks.uri"));
            assertThat(definition.getIssuer(), is("metadataissuer"));
        }

        @Test
        void shouldPerformDiscoveryUsingCache() throws OidcMetadataFetchingException, MalformedURLException {
            definition.setAuthUrl(new URL("http://should.be.updated"));
            definition.setTokenUrl(new URL("http://should.be.updated"));
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
        void shouldPerformTokenKeyUrlUsingCache() throws OidcMetadataFetchingException, MalformedURLException {
            definition.setTokenKeyUrl(new URL("http://should.be.updated"));
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
        void shouldPerformTokenKeyUrlNoCacheUsed() throws OidcMetadataFetchingException, MalformedURLException {
            definition.setTokenKeyUrl(new URL("http://should.be.updated"));
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
        void shouldPerformTokenKeyUrlNoCacheUsedError() throws MalformedURLException {
            definition.setTokenKeyUrl(new URL("http://should.be.updated"));
            definition.setSkipSslValidation(false);
            definition.setCacheJwks(false);

            ResponseEntity<byte[]> responseEntity = mock(ResponseEntity.class);
            when(restTemplate.exchange(anyString(), any(HttpMethod.class), any(HttpEntity.class), any(Class.class)))
                    .thenReturn(responseEntity);
            when(responseEntity.getStatusCode()).thenReturn(HttpStatus.FORBIDDEN);

            assertThrows(IllegalArgumentException.class, () -> metadataDiscoverer.fetchWebKeySet(definition));

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
        void shouldNotPerformDiscovery() throws OidcMetadataFetchingException, MalformedURLException {
            definition.setAuthUrl(new URL("http://authz.not.updated"));
            definition.setTokenUrl(new URL("http://token.not.updated"));
            definition.setTokenKeyUrl(new URL("http://jwk.not.updated"));
            definition.setUserInfoUrl(new URL("http://userinfo.not.updated"));
            definition.setIssuer("issuer-not-changed");

            metadataDiscoverer.fetchMetadataAndUpdateDefinition(definition);

            assertThat(definition, is(notNullValue()));
            assertThat(definition.getDiscoveryUrl(), nullValue());
            assertThat(definition.getAuthUrl().toString(), is("http://authz.not.updated"));
            assertThat(definition.getTokenUrl().toString(), is("http://token.not.updated"));
            assertThat(definition.getTokenKeyUrl().toString(), is("http://jwk.not.updated"));
            assertThat(definition.getUserInfoUrl().toString(), is("http://userinfo.not.updated"));
            assertThat(definition.getIssuer(), is("issuer-not-changed"));

            verifyNoInteractions(urlContentCache);
        }

    }

    @Nested
    class WithErrorSituations {
        @BeforeEach
        void setup() throws MalformedURLException {
            definition.setTokenKeyUrl(new URL("http://token_keys"));
            definition.setSkipSslValidation(true);
            definition.setRelyingPartyId("id");
            definition.setRelyingPartySecret("x");
        }

        @Test
        void failWithEmptyContent() throws OidcMetadataFetchingException, MalformedURLException {

            when(urlContentCache.getUrlContent(anyString(), any(RestTemplate.class), any(HttpMethod.class), any(HttpEntity.class)))
                    .thenReturn("".getBytes());

            assertThrows(OidcMetadataFetchingException.class, () -> metadataDiscoverer.fetchWebKeySet(definition));
        }

        @Test
        void failWithInvalidContent() throws OidcMetadataFetchingException, MalformedURLException {

            when(urlContentCache.getUrlContent(anyString(), any(RestTemplate.class), any(HttpMethod.class), any(HttpEntity.class)))
                    .thenReturn("{x}".getBytes());

            assertThrows(OidcMetadataFetchingException.class, () -> metadataDiscoverer.fetchWebKeySet(definition));
        }
    }

    @Nested
    class WithJwtClientKey {
        @BeforeEach
        void setup() throws MalformedURLException {
            definition.setTokenKeyUrl(new URL("http://token_keys"));
            definition.setSkipSslValidation(true);
            definition.setRelyingPartyId("id");
            definition.setRelyingPartySecret(null);
            when(urlContentCache.getUrlContent(anyString(), any(RestTemplate.class), any(HttpMethod.class), any(HttpEntity.class)))
                    .thenReturn("{\"keys\":[{\"alg\":\"RS256\",\"e\":\"e\",\"kid\":\"id\",\"kty\":\"RSA\",\"n\":\"n\"}]}".getBytes());
        }

        @Test
        void getConfigFromJwksUri() throws OidcMetadataFetchingException, MalformedURLException {

            JsonWebKeySet<JsonWebKey> keys = metadataDiscoverer.fetchWebKeySet(new ClientJwtConfiguration("http://token_keys", null));
            assertNotNull(keys);
            assertEquals(1, keys.getKeys().size());
            assertEquals("id", keys.getKeys().get(0).getKid());
        }

        @Test
        void getConfigFromJwks() throws OidcMetadataFetchingException, MalformedURLException {

            JsonWebKeySet<JsonWebKey> keys = metadataDiscoverer.fetchWebKeySet(ClientJwtConfiguration.parse("{\"keys\":[{\"alg\":\"RS256\",\"e\":\"e\",\"kid\":\"a\",\"kty\":\"RSA\",\"n\":\"n\"}]}"));
            assertNotNull(keys);
            assertEquals(1, keys.getKeys().size());
            assertEquals("a", keys.getKeys().get(0).getKid());
        }

        @Test
        void failWithInvalidConfig() throws OidcMetadataFetchingException, MalformedURLException {

            assertThrows(OidcMetadataFetchingException.class, () -> metadataDiscoverer.fetchWebKeySet(new ClientJwtConfiguration(null, null)));
        }
    }

}
