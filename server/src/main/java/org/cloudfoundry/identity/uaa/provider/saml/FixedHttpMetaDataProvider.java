package org.cloudfoundry.identity.uaa.provider.saml;

import org.cloudfoundry.identity.uaa.cache.UrlContentCache;
import org.cloudfoundry.identity.uaa.impl.config.RestTemplateConfig;
import org.cloudfoundry.identity.uaa.security.IdpOutboundTrustCache;
import org.springframework.web.client.RestTemplate;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.List;

public class FixedHttpMetaDataProvider {

    private final RestTemplate trustingRestTemplate;
    private final RestTemplate nonTrustingRestTemplate;
    private final UrlContentCache cache;
    private final IdpOutboundTrustCache trustCache;
    private final RestTemplateConfig restTemplateConfig;
    private final int connectTimeout;
    private final int readTimeout;

    public FixedHttpMetaDataProvider(
            final RestTemplate trustingRestTemplate,
            final RestTemplate nonTrustingRestTemplate,
            final UrlContentCache cache) {
        this(trustingRestTemplate, nonTrustingRestTemplate, cache, new IdpOutboundTrustCache(), RestTemplateConfig.createDefaults(), 10_000, 10_000);
    }

    public FixedHttpMetaDataProvider(
            final RestTemplate trustingRestTemplate,
            final RestTemplate nonTrustingRestTemplate,
            final UrlContentCache cache,
            final IdpOutboundTrustCache trustCache,
            final RestTemplateConfig restTemplateConfig,
            final int connectTimeout,
            final int readTimeout) {
        this.trustingRestTemplate = trustingRestTemplate;
        this.nonTrustingRestTemplate = nonTrustingRestTemplate;
        this.cache = cache;
        this.trustCache = trustCache;
        this.restTemplateConfig = restTemplateConfig;
        this.connectTimeout = connectTimeout;
        this.readTimeout = readTimeout;
    }

    /**
     * Fetches SAML metadata from a URL. This is on a hot path -- called not just at IdP create/update
     * validation time but on essentially every SAML login/registration-resolution flow for URL-type
     * IdPs (mitigated only by {@code cache}'s TTL) -- so the per-IdP trust lookup below must stay
     * cheap; {@link IdpOutboundTrustCache} caches the built SSLContext/RestTemplate rather than
     * rebuilding it per call.
     *
     * @param identityKey a stable per-IdP cache key, e.g. {@code SamlIdentityProviderDefinition.getUniqueAlias()}
     */
    public byte[] fetchMetadata(String metadataURL, boolean isSkipSSLValidation, List<String> caCertificates, String identityKey)
            throws MetadataProviderNotFoundException {
        validateMetadataURL(metadataURL);
        RestTemplate restTemplate = trustCache.resolveRestTemplate(identityKey, caCertificates, isSkipSSLValidation,
                connectTimeout, readTimeout, restTemplateConfig, trustingRestTemplate, nonTrustingRestTemplate);
        boolean hasCustomTrust = !isSkipSSLValidation && caCertificates != null && !caCertificates.isEmpty();
        if (hasCustomTrust) {
            // A per-IdP merged-trust RestTemplate can't safely share cache's entries with other
            // IdPs/zones that happen to point at the same metadata URL but a different trust config --
            // cache keys purely on the URL, not on which RestTemplate fetched it -- so bypass it
            // entirely whenever caCertificates is in play (same fix applied to OIDC discovery).
            return restTemplate.getForObject(metadataURL, byte[].class);
        }
        return cache.getUrlContent(metadataURL, restTemplate);
    }

    private void validateMetadataURL(String metadataURL) throws MetadataProviderNotFoundException {
        try {
            new URI(metadataURL);
        } catch (URISyntaxException e) {
            throw new MetadataProviderNotFoundException("Illegal URL syntax", e);
        }
    }
}
