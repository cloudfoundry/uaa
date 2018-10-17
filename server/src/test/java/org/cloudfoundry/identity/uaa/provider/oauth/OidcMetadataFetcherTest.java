package org.cloudfoundry.identity.uaa.provider.oauth;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.cloudfoundry.identity.uaa.cache.ExpiringUrlCache;
import org.cloudfoundry.identity.uaa.cache.UrlContentCache;
import org.cloudfoundry.identity.uaa.provider.OIDCIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.util.TimeServiceImpl;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Answers;
import org.springframework.web.client.RestTemplate;

import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URL;
import java.time.Duration;

import static org.hamcrest.CoreMatchers.*;
import static org.junit.Assert.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class OidcMetadataFetcherTest {
    private OidcMetadataFetcher metadataDiscoverer;
    private UrlContentCache urlContentCache;
    private RestTemplate restTemplate;

    private OIDCIdentityProviderDefinition definition;

    private ObjectMapper objectMapper = new ObjectMapper();

    @BeforeEach
    void setUp() {
        urlContentCache = new ExpiringUrlCache(Duration.ofMinutes(2), new TimeServiceImpl(), 2);
        restTemplate = mock(RestTemplate.class, Answers.RETURNS_DEEP_STUBS);

        metadataDiscoverer = new OidcMetadataFetcher(urlContentCache, restTemplate, restTemplate);
    }

    @Test
    public void withoutDiscoveryUrl_shouldNotPerformDiscovery() throws OidcMetadataFetchingException, MalformedURLException {
        definition = new OIDCIdentityProviderDefinition();
        definition.setAuthUrl(new URL("http://not.updated"));
        definition.setTokenUrl(new URL("http://not.updated"));

        metadataDiscoverer.fetchMetadataAndUpdateDefinition(definition);

        assertThat(definition, is(notNullValue()));
        assertThat(definition.getDiscoveryUrl(), nullValue());
        assertThat(definition.getAuthUrl().toString(), is("http://not.updated"));
        assertThat(definition.getTokenUrl().toString(), is("http://not.updated"));
    }

    @Test
    public void withDiscoveryUrl_shouldPerformDiscovery() throws OidcMetadataFetchingException, MalformedURLException, JsonProcessingException {
        definition = new OIDCIdentityProviderDefinition();
        definition.setAuthUrl(new URL("http://should.be.updated"));
        definition.setTokenUrl(new URL("http://should.be.updated"));
        definition.setDiscoveryUrl(new URL("http://discovery.com"));
        when(restTemplate.getForObject(any(URI.class), eq(byte[].class)))
                .thenReturn(objectMapper.writeValueAsBytes(buildOidcMetadata()));

        metadataDiscoverer.fetchMetadataAndUpdateDefinition(definition);

        assertThat(definition, is(notNullValue()));
        assertThat(definition.getAuthUrl().toString(), is("http://authz.endpoint"));
        assertThat(definition.getTokenUrl().toString(), is("http://token.endpoint"));
        assertThat(definition.getUserInfoUrl().toString(), is("http://userinfo.endpoint"));
        assertThat(definition.getTokenKeyUrl().toString(), is("http://jwks.uri"));
        assertThat(definition.getIssuer(), is("metadataissuer"));
    }

    @Test
    public void withDiscoveryUrl_usesCache() throws OidcMetadataFetchingException, MalformedURLException, JsonProcessingException {
        definition = new OIDCIdentityProviderDefinition();
        definition.setAuthUrl(new URL("http://should.be.updated"));
        definition.setTokenUrl(new URL("http://should.be.updated"));
        definition.setDiscoveryUrl(new URL("http://discovery.com"));
        definition.setSkipSslValidation(false);

        when(restTemplate.getForObject(any(URI.class), eq(byte[].class)))
                .thenReturn(objectMapper.writeValueAsBytes(buildOidcMetadata()))
                .thenThrow(new RuntimeException("shouldn't have been called more than once"));

        metadataDiscoverer.fetchMetadataAndUpdateDefinition(definition);
        metadataDiscoverer.fetchMetadataAndUpdateDefinition(definition);
    }

    private OidcMetadata buildOidcMetadata() {
        try {
            OidcMetadata metadata = new OidcMetadata();

            metadata.setAuthorizationEndpoint(new URL("http://authz.endpoint"));
            metadata.setTokenEndpoint(new URL("http://token.endpoint"));
            metadata.setUserinfoEndpoint(new URL("http://userinfo.endpoint"));
            metadata.setJsonWebKeysUri(new URL("http://jwks.uri"));
            metadata.setIssuer("metadataissuer");

            return metadata;
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
