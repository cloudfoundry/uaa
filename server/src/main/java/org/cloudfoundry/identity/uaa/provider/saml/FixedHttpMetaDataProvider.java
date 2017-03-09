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

import org.apache.commons.httpclient.HttpClient;
import org.apache.commons.httpclient.SimpleHttpConnectionManager;
import org.apache.commons.httpclient.params.HttpClientParams;
import org.apache.commons.httpclient.protocol.ProtocolSocketFactory;
import org.cloudfoundry.identity.uaa.cache.UrlContentCache;
import org.opensaml.saml2.metadata.provider.HTTPMetadataProvider;
import org.opensaml.saml2.metadata.provider.MetadataProviderException;
import org.springframework.web.client.RestTemplate;

import java.util.Timer;

/**
 * This class works around the problem described in <a href="http://issues.apache.org/jira/browse/HTTPCLIENT-646">http://issues.apache.org/jira/browse/HTTPCLIENT-646</a> when a socket factory is set
 * on the OpenSAML
 * {@link HTTPMetadataProvider#setSocketFactory(ProtocolSocketFactory)} all
 * subsequent GET Methods should be executed using a relative URL, otherwise the
 * HttpClient
 * resets the underlying socket factory.
 *
 *
 */
public class  FixedHttpMetaDataProvider extends HTTPMetadataProvider {

    private RestTemplate template;
    private UrlContentCache cache;

    public static FixedHttpMetaDataProvider buildProvider(Timer backgroundTaskTimer,
                                                          HttpClientParams params,
                                                          String metadataURL,
                                                          RestTemplate template,
                                                          UrlContentCache cache) throws MetadataProviderException {
        SimpleHttpConnectionManager connectionManager = new SimpleHttpConnectionManager(true);
        connectionManager.getParams().setDefaults(params);
        HttpClient client = new HttpClient(connectionManager);
        return new FixedHttpMetaDataProvider(backgroundTaskTimer, client, metadataURL, template, cache);
    }

    private FixedHttpMetaDataProvider(Timer backgroundTaskTimer,
                                      HttpClient client,
                                      String metadataURL,
                                      RestTemplate template,
                                      UrlContentCache cache) throws MetadataProviderException {
        super(backgroundTaskTimer, client, metadataURL);
        this.template = template;
        this.cache = cache;
    }

    @Override
    public byte[] fetchMetadata() throws MetadataProviderException {
        return cache.getUrlContent(getMetadataURI(), template);
    }


}
