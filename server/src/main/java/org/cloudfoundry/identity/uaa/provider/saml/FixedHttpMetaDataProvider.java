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

import com.google.common.base.Ticker;
import com.google.common.cache.Cache;
import com.google.common.cache.CacheBuilder;
import org.apache.commons.httpclient.HostConfiguration;
import org.apache.commons.httpclient.HttpClient;
import org.apache.commons.httpclient.SimpleHttpConnectionManager;
import org.apache.commons.httpclient.params.HttpClientParams;
import org.apache.commons.httpclient.protocol.ProtocolSocketFactory;
import org.opensaml.saml2.metadata.provider.HTTPMetadataProvider;
import org.opensaml.saml2.metadata.provider.MetadataProviderException;

import java.net.URISyntaxException;
import java.util.Timer;
import java.util.concurrent.TimeUnit;

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
    private long lastFetchTime = 0;
    private static long expirationTimeMillis = 10*60*1000; //10 minutes refresh on the URL fetch
    private static Ticker ticker = new Ticker() {
        @Override
        public long read() {
            return System.nanoTime();
        }
    };

    protected static Cache<String, byte[]> metadataCache = buildCache();

    protected static Cache<String, byte[]> buildCache() {
        return CacheBuilder
            .newBuilder()
            .expireAfterWrite(expirationTimeMillis, TimeUnit.MILLISECONDS)
            .maximumSize(20000)
            .ticker(ticker)
            .build();
    }

    public static FixedHttpMetaDataProvider buildProvider(Timer backgroundTaskTimer, HttpClientParams params, String metadataURL) throws MetadataProviderException {
        SimpleHttpConnectionManager connectionManager = new SimpleHttpConnectionManager(true);
        connectionManager.getParams().setDefaults(params);
        HttpClient client = new HttpClient(connectionManager);
        configureProxyIfNeeded(client, metadataURL);
        return new FixedHttpMetaDataProvider(backgroundTaskTimer, client, metadataURL);
    }

    private FixedHttpMetaDataProvider(Timer backgroundTaskTimer, HttpClient client, String metadataURL) throws MetadataProviderException {
        super(backgroundTaskTimer, client, metadataURL);
    }

    public static void configureProxyIfNeeded(HttpClient client, String metadataURL) {
        if (System.getProperty("http.proxyHost")!=null && System.getProperty("http.proxyPort")!=null && metadataURL.toLowerCase().startsWith("http://")) {
            setProxy(client, "http");
        } else if (System.getProperty("https.proxyHost")!=null && System.getProperty("https.proxyPort")!=null && metadataURL.toLowerCase().startsWith("https://")) {
            setProxy(client, "https");
        }
    }

    protected static void setProxy(HttpClient client, String prefix) {
        try {
            String host = System.getProperty(prefix + ".proxyHost");
            int port = Integer.parseInt(System.getProperty(prefix + ".proxyPort"));
            HostConfiguration configuration = client.getHostConfiguration();
            configuration.setProxy(host, port);
        } catch (NumberFormatException e) {
            throw new IllegalStateException("Invalid proxy port configured:"+System.getProperty(prefix + ".proxyPort"));
        }
    }


    @Override
    public byte[] fetchMetadata() throws MetadataProviderException {
        byte[] metadata = metadataCache.getIfPresent(getMetadataURI());
        if (metadata==null || (System.currentTimeMillis()-lastFetchTime)>getExpirationTimeMillis()) {
            metadata = super.fetchMetadata();
            lastFetchTime = System.currentTimeMillis();
            metadataCache.put(getMetadataURI(), metadata);
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

    public long getExpirationTimeMillis() {
        return expirationTimeMillis;
    }

    public void setExpirationTimeMillis(long expirationTimeMillis) {
        this.expirationTimeMillis = expirationTimeMillis;
        metadataCache = buildCache();
    }

    public Ticker getTicker() {
        return ticker;
    }

    public void setTicker(Ticker ticker) {
        FixedHttpMetaDataProvider.ticker = ticker;
        metadataCache = buildCache();
    }
}
