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
import org.apache.commons.httpclient.protocol.ProtocolSocketFactory;
import org.opensaml.saml2.metadata.provider.HTTPMetadataProvider;
import org.opensaml.saml2.metadata.provider.MetadataProviderException;

import java.net.URISyntaxException;
import java.util.Timer;

/**
 * This class works around the problem described in <a href="http://issues.apache.org/jira/browse/HTTPCLIENT-646">http://issues.apache.org/jira/browse/HTTPCLIENT-646</a> when a socket factory is set
 * on the OpenSAML
 * {@link HTTPMetadataProvider#setSocketFactory(ProtocolSocketFactory)} all
 * subsequent GET Methods should be executed using a relative URL, otherwise the
 * HttpClient
 * resets the underlying socket factory.
 *
 * @author Filip Hanik
 *
 */
public class FixedHttpMetaDataProvider extends HTTPMetadataProvider {

    /**
     * Track if we have a custom socket factory
     */
    private boolean socketFactorySet = false;
    private byte[] metadata;


    public FixedHttpMetaDataProvider(Timer backgroundTaskTimer, HttpClient client, String metadataURL) throws MetadataProviderException {
        super(backgroundTaskTimer, client, metadataURL);
    }


    @Override
    public byte[] fetchMetadata() throws MetadataProviderException {
        if (metadata==null) {
            metadata = super.fetchMetadata();
        }
        return metadata;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void setSocketFactory(ProtocolSocketFactory newSocketFactory) {
        // TODO Auto-generated method stub
        super.setSocketFactory(newSocketFactory);
        if (newSocketFactory != null) {
            socketFactorySet = true;
        } else {
            socketFactorySet = false;
        }
    }

    /**
     * If a custom socket factory has been set, only
     * return a relative URL so that the custom factory is retained.
     * This works around
     * https://issues.apache.org/jira/browse/HTTPCLIENT-646 {@inheritDoc}
     */
    @Override
    public String getMetadataURI() {
        if (isSocketFactorySet()) {
            java.net.URI uri;
            try {
                uri = new java.net.URI(super.getMetadataURI());
                String result = uri.getPath();
                if (uri.getQuery() != null && uri.getQuery().trim().length() > 0) {
                    result = result + "?" + uri.getQuery();
                }
                return result;
            } catch (URISyntaxException e) {
                // this can never happen, satisfy compiler
                throw new IllegalArgumentException(e);
            }
        } else {
            return super.getMetadataURI();
        }
    }

    public boolean isSocketFactorySet() {
        return socketFactorySet;
    }
}
