package org.cloudfoundry.identity.uaa.provider.saml;

import org.cloudfoundry.identity.uaa.cache.UrlContentCache;
import org.cloudfoundry.identity.uaa.impl.config.RestTemplateConfig;
import org.cloudfoundry.identity.uaa.security.IdpOutboundTrustCache;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.web.client.RestTemplate;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

class FixedHttpMetaDataProviderTest {

    private RestTemplate trustingRestTemplate;
    private RestTemplate nonTrustingRestTemplate;
    private UrlContentCache urlContentCache;
    private IdpOutboundTrustCache trustCache;
    private FixedHttpMetaDataProvider provider;

    @BeforeEach
    void setup() {
        trustingRestTemplate = mock(RestTemplate.class);
        nonTrustingRestTemplate = mock(RestTemplate.class);
        urlContentCache = mock(UrlContentCache.class);
        trustCache = mock(IdpOutboundTrustCache.class);
        provider = new FixedHttpMetaDataProvider(trustingRestTemplate, nonTrustingRestTemplate, urlContentCache,
                trustCache, RestTemplateConfig.createDefaults(), 10_000, 10_000);
    }

    @Test
    void noCaCertificates_routesThroughSharedUrlCache() throws Exception {
        when(trustCache.resolveRestTemplate(any(), any(), anyBoolean(), anyInt(), anyInt(), any(), any(), any()))
                .thenReturn(nonTrustingRestTemplate);
        when(urlContentCache.getUrlContent(eq("https://idp.example.com/metadata"), eq(nonTrustingRestTemplate)))
                .thenReturn("metadata".getBytes());

        byte[] result = provider.fetchMetadata("https://idp.example.com/metadata", false, null, "identity-key");

        assertThat(result).isEqualTo("metadata".getBytes());
        verify(nonTrustingRestTemplate, never()).getForObject(any(String.class), eq(byte[].class));
    }

    @Test
    void withCaCertificates_bypassesSharedUrlCache() throws Exception {
        RestTemplate perIdpRestTemplate = mock(RestTemplate.class);
        when(trustCache.resolveRestTemplate(eq("identity-key"), eq(List.of("cert-pem")), eq(false), anyInt(), anyInt(), any(), any(), any()))
                .thenReturn(perIdpRestTemplate);
        when(perIdpRestTemplate.getForObject("https://idp.example.com/metadata", byte[].class))
                .thenReturn("metadata".getBytes());

        byte[] result = provider.fetchMetadata("https://idp.example.com/metadata", false, List.of("cert-pem"), "identity-key");

        assertThat(result).isEqualTo("metadata".getBytes());
        verifyNoInteractions(urlContentCache);
    }

    @Test
    void skipSslValidationTrue_doesNotBypassSharedUrlCache_evenWithCaCertificatesSet() throws Exception {
        when(trustCache.resolveRestTemplate(any(), any(), eq(true), anyInt(), anyInt(), any(), any(), any()))
                .thenReturn(trustingRestTemplate);
        when(urlContentCache.getUrlContent(eq("https://idp.example.com/metadata"), eq(trustingRestTemplate)))
                .thenReturn("metadata".getBytes());

        byte[] result = provider.fetchMetadata("https://idp.example.com/metadata", true, List.of("cert-pem"), "identity-key");

        assertThat(result).isEqualTo("metadata".getBytes());
        verify(trustingRestTemplate, never()).getForObject(any(String.class), eq(byte[].class));
    }

    @Nested
    class LegacyConstructor {

        @Test
        void defaultConstructor_stillWorks() throws Exception {
            UrlContentCache cache = mock(UrlContentCache.class);
            when(cache.getUrlContent(eq("https://idp.example.com/metadata"), any(RestTemplate.class)))
                    .thenReturn("metadata".getBytes());
            FixedHttpMetaDataProvider legacyProvider = new FixedHttpMetaDataProvider(trustingRestTemplate, nonTrustingRestTemplate, cache);

            byte[] result = legacyProvider.fetchMetadata("https://idp.example.com/metadata", false, null, "identity-key");

            assertThat(result).isEqualTo("metadata".getBytes());
        }
    }
}
