package org.cloudfoundry.identity.uaa.provider.saml;

import org.cloudfoundry.identity.uaa.cache.UrlContentCache;
import org.cloudfoundry.identity.uaa.impl.config.RestTemplateConfig;

import java.net.URI;
import java.net.URISyntaxException;

public class FixedHttpMetaDataProvider {

    private final RestTemplateConfig restTemplateConfig;
    private final UrlContentCache cache;

    public FixedHttpMetaDataProvider(
            final RestTemplateConfig restTemplateConfig,
            final UrlContentCache cache) {
        this.restTemplateConfig = restTemplateConfig;
        this.cache = cache;
    }

    public byte[] fetchMetadata(String metadataURL, boolean isSkipSSLValidation) throws MetadataProviderNotFoundException {
        validateMetadataURL(metadataURL);
        return cache.getUrlContent(metadataURL, restTemplateConfig.createRestTemplate(isSkipSSLValidation));
    }

    private void validateMetadataURL(String metadataURL) throws MetadataProviderNotFoundException {
        try {
            new URI(metadataURL);
        } catch (URISyntaxException e) {
            throw new MetadataProviderNotFoundException("Illegal URL syntax", e);
        }
    }
}
