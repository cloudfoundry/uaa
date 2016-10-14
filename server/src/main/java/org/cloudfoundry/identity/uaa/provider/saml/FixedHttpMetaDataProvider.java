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
import org.apache.commons.httpclient.HttpClient;
import org.apache.commons.httpclient.SimpleHttpConnectionManager;
import org.apache.commons.httpclient.params.HttpClientParams;
import org.apache.commons.httpclient.protocol.ProtocolSocketFactory;
import org.opensaml.saml2.metadata.provider.HTTPMetadataProvider;
import org.opensaml.saml2.metadata.provider.MetadataProviderException;
import org.springframework.web.client.RestTemplate;

import java.util.Timer;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;

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

    private static final byte[] CLASS_DEF = new byte[0];
    private static AtomicLong expirationTimeMillis = new AtomicLong(10*60*1000); //10 minutes refresh on the URL fetch

    private static Ticker ticker = new Ticker() {
        @Override
        public long read() {
            return System.nanoTime();
        }
    };
    private RestTemplate template;

    protected static volatile Cache<String, CacheEntry> metadataCache = buildCache();

    protected static Cache<String, CacheEntry> buildCache() {
        return CacheBuilder
            .newBuilder()
            .expireAfterWrite(expirationTimeMillis.get(), TimeUnit.MILLISECONDS)
            .maximumSize(20000)
            .ticker(ticker)
            .build();
    }

    public static FixedHttpMetaDataProvider buildProvider(Timer backgroundTaskTimer,
                                                          HttpClientParams params,
                                                          String metadataURL,
                                                          RestTemplate template) throws MetadataProviderException {
        SimpleHttpConnectionManager connectionManager = new SimpleHttpConnectionManager(true);
        connectionManager.getParams().setDefaults(params);
        HttpClient client = new HttpClient(connectionManager);
        return new FixedHttpMetaDataProvider(backgroundTaskTimer, client, metadataURL, template);
    }

    private FixedHttpMetaDataProvider(Timer backgroundTaskTimer,
                                      HttpClient client,
                                      String metadataURL,
                                      RestTemplate template) throws MetadataProviderException {
        super(backgroundTaskTimer, client, metadataURL);
        this.template = template;
    }

    @Override
    public byte[] fetchMetadata() throws MetadataProviderException {
        CacheEntry entry = metadataCache.getIfPresent(getMetadataURI());
        byte[] metadata = entry != null ? entry.getData() : null;
        if (metadata==null || (System.currentTimeMillis()-entry.getTimeEntered())>getExpirationTimeMillis()) {
            metadata = template.getForObject(getMetadataURI(), CLASS_DEF.getClass());
            metadataCache.put(getMetadataURI(), new CacheEntry(System.currentTimeMillis(), metadata));
        }
        return metadata;
    }


    public static long getExpirationTimeMillis() {
        return expirationTimeMillis.get();
    }

    public static void setExpirationTimeMillis(long expirationTimeMillis) {
        if (FixedHttpMetaDataProvider.expirationTimeMillis.getAndSet(expirationTimeMillis) != expirationTimeMillis) {
            metadataCache = buildCache();
        }
    }

    public static void setTicker(Ticker ticker) {
        if (ticker != FixedHttpMetaDataProvider.ticker) {
            FixedHttpMetaDataProvider.ticker = ticker;
            metadataCache = buildCache();
        }
    }

    static class CacheEntry {
        private final long timeEntered;
        private final byte[] data;

        public CacheEntry(long timeEntered, byte[] data) {
            this.timeEntered = timeEntered;
            this.data = data;
        }

        public long getTimeEntered() {
            return timeEntered;
        }

        public byte[] getData() {
            return data;
        }

    }
}
