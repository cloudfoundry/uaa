package org.cloudfoundry.identity.uaa.provider.saml;

import org.cloudfoundry.identity.uaa.cache.UrlContentCache;
import org.opensaml.saml2.metadata.provider.MetadataProviderException;
import org.springframework.web.client.RestTemplate;

import java.net.URI;
import java.net.URISyntaxException;

public class FixedHttpMetaDataProvider {

    private RestTemplate trustingRestTemplate;
    private RestTemplate nonTrustingRestTemplate;
    private UrlContentCache cache;

    public byte[] fetchMetadata(String metadataURL, boolean isSkipSSLValidation) throws MetadataProviderException {
        validateMetadataURL(metadataURL);

        if (isSkipSSLValidation) {
            return cache.getUrlContent(metadataURL, trustingRestTemplate);
        }
        return cache.getUrlContent(metadataURL, nonTrustingRestTemplate);
    }

    private void validateMetadataURL(String metadataURL) throws MetadataProviderException {
        try {
            new URI(metadataURL);
        } catch (URISyntaxException e) {
            throw new MetadataProviderException("Illegal URL syntax", e);
        }
    }

    public void setTrustingRestTemplate(RestTemplate trustingRestTemplate) {
        this.trustingRestTemplate = trustingRestTemplate;
    }

    public void setNonTrustingRestTemplate(RestTemplate nonTrustingRestTemplate) {
        this.nonTrustingRestTemplate = nonTrustingRestTemplate;
    }

    public void setCache(UrlContentCache cache) {
        this.cache = cache;
    }
}
