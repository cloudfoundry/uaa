package org.cloudfoundry.identity.uaa.provider.saml;

import org.cloudfoundry.identity.uaa.cache.UrlContentCache;
import org.springframework.web.client.RestTemplate;

import java.net.URI;
import java.net.URISyntaxException;

public class FixedHttpMetaDataProvider {

    private final RestTemplate trustingRestTemplate;
    private final RestTemplate nonTrustingRestTemplate;
    private final UrlContentCache cache;

    public FixedHttpMetaDataProvider(
            final RestTemplate trustingRestTemplate,
            final RestTemplate nonTrustingRestTemplate,
            final UrlContentCache cache) {
        this.trustingRestTemplate = trustingRestTemplate;
        this.nonTrustingRestTemplate = nonTrustingRestTemplate;
        this.cache = cache;
    }

    public byte[] fetchMetadata(String metadataURL, boolean isSkipSSLValidation) throws MetadataProviderNotFoundException {
        validateMetadataURL(metadataURL);
        if (isSkipSSLValidation) {
            return cache.getUrlContent(metadataURL, trustingRestTemplate);
        }
        return cache.getUrlContent(metadataURL, nonTrustingRestTemplate);
    }

    private void validateMetadataURL(String metadataURL) throws MetadataProviderNotFoundException {
        try {
            new URI(metadataURL);
        } catch (URISyntaxException e) {
            throw new MetadataProviderNotFoundException("Illegal URL syntax", e);
        }
    }
}
