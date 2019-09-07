/*******************************************************************************
 *     Cloud Foundry
 *     Copyright (c) [2009-2016] Pivotal Software, Inc. All Rights Reserved.
 *
 *     This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *     You may not use this product except in compliance with the License.
 *
 *     This product includes a number of subcomponents with
 *     separate copyright notices and license terms. Your use of these
 *     subcomponents is subject to the terms and conditions of the
 *     subcomponent's license, as noted in the LICENSE file.
 *******************************************************************************/

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


    public byte[] fetchMetadata(String metadataURL, boolean isSkipSSLValidation) throws MetadataProviderException, URISyntaxException {
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
