package org.cloudfoundry.identity.uaa.provider.oauth;

import org.cloudfoundry.identity.uaa.cache.UrlContentCache;
import org.cloudfoundry.identity.uaa.provider.OIDCIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.mockito.Answers;
import org.springframework.web.client.RestTemplate;

import java.net.MalformedURLException;
import java.net.URL;

import static org.hamcrest.CoreMatchers.*;
import static org.junit.Assert.assertThat;
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
        public void setup() throws MalformedURLException {
            definition.setDiscoveryUrl(new URL("http://discovery.url"));
            oidcMetadata = new OidcMetadata();

            oidcMetadata.setAuthorizationEndpoint(new URL("http://authz.endpoint"));
            oidcMetadata.setTokenEndpoint(new URL("http://token.endpoint"));
            oidcMetadata.setUserinfoEndpoint(new URL("http://userinfo.endpoint"));
            oidcMetadata.setJsonWebKeysUri(new URL("http://jwks.uri"));
            oidcMetadata.setIssuer("metadataissuer");
        }

        @Test
        public void shouldFavorUsingConfiguredIdentityProviderProperties() throws OidcMetadataFetchingException, MalformedURLException {
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
        public void givenConfiguredIdentityProviderPropertiesAreNotSet_shouldUseOidcMetadata() throws OidcMetadataFetchingException {
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
        public void shouldPerformDiscoveryUsingCache() throws OidcMetadataFetchingException, MalformedURLException {
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
    }

    @Nested
    class WithoutDiscoveryUrl {
        @BeforeEach
        public void setup() {
            definition.setDiscoveryUrl(null);
        }

        @Test
        @DisplayName("when the idp is configured without a discovery URL then it should retain the configured OAuth/OIDC endpoints")
        public void shouldNotPerformDiscovery() throws OidcMetadataFetchingException, MalformedURLException {
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
}
