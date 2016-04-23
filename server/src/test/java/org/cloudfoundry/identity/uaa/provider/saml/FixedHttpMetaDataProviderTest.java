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
import org.apache.commons.httpclient.contrib.ssl.EasySSLProtocolSocketFactory;
import org.apache.commons.httpclient.params.HttpClientParams;
import org.apache.commons.httpclient.params.HttpConnectionParams;
import org.apache.commons.httpclient.protocol.Protocol;
import org.apache.commons.httpclient.protocol.ProtocolSocketFactory;
import org.cloudfoundry.identity.uaa.provider.SamlIdentityProviderDefinition;
import org.junit.Test;

import java.io.IOException;
import java.net.InetAddress;
import java.net.Socket;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Timer;
import java.util.TimerTask;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;

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
    private Ticker ticker;
    private volatile long nanoValue = System.nanoTime();

    public long getNanoValue() {
        return nanoValue;
    }


    public void setUp(String url) throws Exception {
        params = new HttpClientParams();
        params.setSoTimeout(1000);
        params.setConnectionManagerTimeout(1000);

        ProtocolSocketFactory socketFactory = (ProtocolSocketFactory) Class.forName(SamlIdentityProviderDefinition.DEFAULT_HTTPS_SOCKET_FACTORY).newInstance();
        fixedHttpMetaDataProvider =  FixedHttpMetaDataProvider.buildProvider(dummyTimer,
                                                                             params,
                                                                             url);
        fixedHttpMetaDataProvider.setExpirationTimeMillis(100);
        fixedHttpMetaDataProvider.setSocketFactory(socketFactory);
        ticker = new Ticker() {
            @Override
            public long read() {
                return getNanoValue();
            }
        };
        fixedHttpMetaDataProvider.setTicker(ticker);
    }

    @Test
    public void testFetchMetadata() throws Exception {
        setUp("https://login.identity.cf-app.com:443/saml/metadata");
        assertEquals(0, FixedHttpMetaDataProvider.metadataCache.size());
        fixedHttpMetaDataProvider.fetchMetadata();
        assertEquals(1, FixedHttpMetaDataProvider.metadataCache.size());
        nanoValue = nanoValue + (1000 * 1000 * 1000); //1 second
        assertNull(FixedHttpMetaDataProvider.metadataCache.getIfPresent(fixedHttpMetaDataProvider.getMetadataURI()));
        assertEquals(0, FixedHttpMetaDataProvider.metadataCache.size());
    }

    public void testProxy(int expectedPort, String expectedHost, String url) throws Exception {
        Protocol originalProtocol = Protocol.getProtocol("http");
        try {
            setUp(url);
            List<Object> arguments = new ArrayList();
            EasySSLProtocolSocketFactory socketFactory = new EasySSLProtocolSocketFactory() {
                @Override
                public Socket createSocket(final String host,
                                           final int port,
                                           final InetAddress localAddress,
                                           final int localPort,
                                           final HttpConnectionParams params) throws IOException {
                    arguments.add(host);
                    arguments.add(port);
                    return super.createSocket(host, port, localAddress, localPort, params);
                }

                @Override
                public Socket createSocket(String host, int port, InetAddress localHost, int localPort, int timeout) throws IOException {
                    arguments.add(host);
                    arguments.add(port);
                    return super.createSocket(host, port, localHost, localPort, timeout);
                }
            };

            Protocol ourProtocol = new Protocol("http", socketFactory, 8080);
            Protocol.registerProtocol("http", ourProtocol);
            fixedHttpMetaDataProvider.setSocketFactory(socketFactory);
            try {
                fixedHttpMetaDataProvider.fetchMetadata();
            } catch (Exception x) {
                //expected - we don't actually have a proxy
            }
            assertEquals(Integer.valueOf(expectedPort), arguments.get(1));
            assertEquals(expectedHost, arguments.get(0));
        } finally {
            Protocol.registerProtocol("http", originalProtocol);
        }
    }

    @Test
    public void test_No_Proxy_https() throws Exception {
        testProxy(443,"login.identity.cf-app.com", "https://login.identity.cf-app.com:443/saml/metadata");
    }

    @Test
    public void test_No_Proxy_http() throws Exception {
        testProxy(80,"login.identity.cf-app.com", "http://login.identity.cf-app.com:80/saml/metadata");
    }


    @Test
    public void test_Https_Proxy_As_System_Properties() throws Exception  {
        try {
            System.setProperty("https.proxyHost", "localhost");
            System.setProperty("https.proxyPort", "8080");
            testProxy(8080, "localhost", "https://login.identity.cf-app.com:443/saml/metadata");
        } finally {
            System.clearProperty("https.proxyHost");
            System.clearProperty("https.proxyPort");
        }
    }

    @Test
    public void test_Http_Proxy_As_System_Properties() throws Exception  {
        try {
            System.setProperty("http.proxyHost", "localhost");
            System.setProperty("http.proxyPort", "8081");
            testProxy(8081, "localhost", "http://login.identity.cf-app.com:80/saml/metadata");
        } finally {
            System.clearProperty("http.proxyHost");
            System.clearProperty("http.proxyPort");
        }
    }



}