/*
 * *****************************************************************************
 *      Cloud Foundry
 *      Copyright (c) [2009-2016] Pivotal Software, Inc. All Rights Reserved.
 *
 *      This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *      You may not use this product except in compliance with the License.
 *
 *      This product includes a number of subcomponents with
 *      separate copyright notices and license terms. Your use of these
 *      subcomponents is subject to the terms and conditions of the
 *      subcomponent's license, as noted in the LICENSE file.
 * *****************************************************************************
 */

package org.cloudfoundry.identity.uaa.provider.saml;

import com.google.common.base.Ticker;
import org.apache.commons.httpclient.params.HttpClientParams;
import org.cloudfoundry.identity.uaa.util.UaaHttpRequestUtils;
import org.junit.Test;
import org.springframework.web.client.RestTemplate;

import javax.net.ssl.SSLHandshakeException;
import java.util.Date;
import java.util.Timer;
import java.util.TimerTask;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.fail;

public class FixedHttpMetaDataProviderTest {


    HttpClientParams params;
    private Timer dummyTimer = new Timer() {
        @Override public void cancel() { super.cancel(); }
        @Override public int purge() {return 0; }
        @Override public void schedule(TimerTask task, long delay) {}
        @Override public void schedule(TimerTask task, long delay, long period) {}
        @Override public void schedule(TimerTask task, Date firstTime, long period) {}
        @Override public void schedule(TimerTask task, Date time) {}
        @Override public void scheduleAtFixedRate(TimerTask task, long delay, long period) {}
        @Override public void scheduleAtFixedRate(TimerTask task, Date firstTime, long period) {}
    };
    private FixedHttpMetaDataProvider fixedHttpMetaDataProvider;
    private Ticker ticker = new Ticker() {
        @Override
        public long read() {
            return getNanoValue();
        }
    };

    private volatile long nanoValue = System.nanoTime();

    public long getNanoValue() {
        return nanoValue;
    }


    public void setUp(String url, RestTemplate template) throws Exception {
        params = new HttpClientParams();
        params.setSoTimeout(1000);
        params.setConnectionManagerTimeout(1000);
        fixedHttpMetaDataProvider =  FixedHttpMetaDataProvider.buildProvider(dummyTimer,
                                                                             params,
                                                                             url,
                                                                             template);
        fixedHttpMetaDataProvider.setExpirationTimeMillis(100);
        fixedHttpMetaDataProvider.setTicker(ticker);
    }

    @Test
    public void self_signed_fetch_fails_by_default() throws Exception {
        RestTemplate template = new RestTemplate(UaaHttpRequestUtils.createRequestFactory(false));
        setUp("https://login.identity.cf-app.com/saml/metadata", template);
        Object originalCache = FixedHttpMetaDataProvider.metadataCache;
        try {
            fixedHttpMetaDataProvider.fetchMetadata();
            fail("Expecting a SSL handshake exception");
        }catch (Exception x) {
            assertEquals(SSLHandshakeException.class, x.getCause().getClass());
        }
        template = new RestTemplate(UaaHttpRequestUtils.createRequestFactory(true));
        setUp("https://login.identity.cf-app.com/saml/metadata", template);
        assertNotNull(fixedHttpMetaDataProvider.fetchMetadata());
        assertSame(originalCache, FixedHttpMetaDataProvider.metadataCache);
    }

    @Test
    public void testFetchMetadata_check_cache() throws Exception {
        RestTemplate template = new RestTemplate(UaaHttpRequestUtils.createRequestFactory(true));
        setUp("https://login.identity.cf-app.com:443/saml/metadata", template);
        assertEquals(0, FixedHttpMetaDataProvider.metadataCache.size());
        fixedHttpMetaDataProvider.fetchMetadata();
        assertEquals(1, FixedHttpMetaDataProvider.metadataCache.size());
        nanoValue = nanoValue + (1000 * 1000 * 1000); //1 second
        assertNull(FixedHttpMetaDataProvider.metadataCache.getIfPresent(fixedHttpMetaDataProvider.getMetadataURI()));
        assertEquals(0, FixedHttpMetaDataProvider.metadataCache.size());
    }
}
