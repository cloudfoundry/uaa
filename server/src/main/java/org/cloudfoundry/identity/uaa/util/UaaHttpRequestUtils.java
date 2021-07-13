/*******************************************************************************
 * Cloud Foundry
 * Copyright (c) [2009-2016] Pivotal Software, Inc. All Rights Reserved.
 * <p>
 * This product is licensed to you under the Apache License, Version 2.0 (the "License").
 * You may not use this product except in compliance with the License.
 * <p>
 * This product includes a number of subcomponents with
 * separate copyright notices and license terms. Your use of these
 * subcomponents is subject to the terms and conditions of the
 * subcomponent's license, as noted in the LICENSE file.
 *******************************************************************************/
package org.cloudfoundry.identity.uaa.util;

import org.apache.http.HeaderElement;
import org.apache.http.HeaderElementIterator;
import org.apache.http.HttpResponse;
import org.apache.http.config.Registry;
import org.apache.http.config.RegistryBuilder;
import org.apache.http.conn.ConnectionKeepAliveStrategy;
import org.apache.http.conn.socket.ConnectionSocketFactory;
import org.apache.http.conn.socket.PlainConnectionSocketFactory;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.impl.conn.PoolingHttpClientConnectionManager;
import org.apache.http.message.BasicHeaderElementIterator;
import org.apache.http.protocol.HTTP;
import org.apache.http.protocol.HttpContext;
import org.apache.http.util.TextUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.apache.http.conn.ssl.NoopHostnameVerifier;
import org.apache.http.conn.ssl.SSLContextBuilder;
import org.apache.http.conn.ssl.TrustSelfSignedStrategy;
import org.apache.http.impl.NoConnectionReuseStrategy;
import org.apache.http.impl.client.DefaultRedirectStrategy;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.impl.client.HttpClients;
import org.springframework.http.client.ClientHttpRequestFactory;
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;
import org.springframework.web.context.request.RequestAttributes;
import org.springframework.web.context.request.RequestContextHolder;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLContext;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;

import static java.util.Arrays.stream;

public abstract class UaaHttpRequestUtils {

    private static Logger logger = LoggerFactory.getLogger(UaaHttpRequestUtils.class);

    public static ClientHttpRequestFactory createRequestFactory(boolean skipSslValidation, int timeout) {
        return createRequestFactory(getClientBuilder(skipSslValidation, 10, 5, 0), timeout);
    }

    public static ClientHttpRequestFactory createRequestFactory(boolean skipSslValidation, int timeout, int poolSize, int defaultMaxPerRoute, int maxKeepAlive) {
        return createRequestFactory(getClientBuilder(skipSslValidation, poolSize, defaultMaxPerRoute, maxKeepAlive), timeout);
    }

    protected static ClientHttpRequestFactory createRequestFactory(HttpClientBuilder builder, int timeoutInMs) {
        HttpComponentsClientHttpRequestFactory httpComponentsClientHttpRequestFactory = new HttpComponentsClientHttpRequestFactory(builder.build());

        httpComponentsClientHttpRequestFactory.setReadTimeout(timeoutInMs);
        httpComponentsClientHttpRequestFactory.setConnectionRequestTimeout(timeoutInMs);
        httpComponentsClientHttpRequestFactory.setConnectTimeout(timeoutInMs);
        return httpComponentsClientHttpRequestFactory;
    }

    protected static HttpClientBuilder getClientBuilder(boolean skipSslValidation, int poolSize, int defaultMaxPerRoute, int maxKeepAlive) {
        HttpClientBuilder builder = HttpClients.custom()
            .useSystemProperties()
            .setRedirectStrategy(new DefaultRedirectStrategy());
        PoolingHttpClientConnectionManager cm;
        if (skipSslValidation) {
            SSLContext sslContext = getNonValidatingSslContext();
            final String[] supportedProtocols = split(System.getProperty("https.protocols"));
            final String[] supportedCipherSuites = split(System.getProperty("https.cipherSuites"));
            HostnameVerifier hostnameVerifierCopy = new NoopHostnameVerifier();
            SSLConnectionSocketFactory sslSocketFactory = new SSLConnectionSocketFactory(sslContext, supportedProtocols, supportedCipherSuites, hostnameVerifierCopy);
            Registry<ConnectionSocketFactory> socketFactoryRegistry = RegistryBuilder.<ConnectionSocketFactory> create()
                    .register("https", sslSocketFactory)
                    .register("http", PlainConnectionSocketFactory.getSocketFactory())
                    .build();
            cm = new PoolingHttpClientConnectionManager(socketFactoryRegistry);
        } else {
            cm = new PoolingHttpClientConnectionManager();
        }
        cm.setMaxTotal(poolSize);
        cm.setDefaultMaxPerRoute(defaultMaxPerRoute);
        builder.setConnectionManager(cm);

        if (maxKeepAlive <= 0) {
            builder.setConnectionReuseStrategy(NoConnectionReuseStrategy.INSTANCE);
        } else {
            builder.setKeepAliveStrategy(new UaaConnectionKeepAliveStrategy(maxKeepAlive));
        }

        return builder;
    }

    private static SSLContext getNonValidatingSslContext() {
        try {
            return new SSLContextBuilder().loadTrustMaterial(null, new TrustSelfSignedStrategy()).build();
        } catch (KeyManagementException | KeyStoreException | NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    public static String paramsToQueryString(Map<String, String[]> parameterMap) {
        return parameterMap.entrySet().stream()
          .flatMap(param -> stream(param.getValue()).map(value -> param.getKey() + "=" + encodeParameter(value)))
          .collect(Collectors.joining("&"));
    }

    private static String encodeParameter(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8);
    }

    public static boolean isAcceptedInvitationAuthentication() {
        try {
            RequestAttributes attr = RequestContextHolder.currentRequestAttributes();
            if (attr!=null) {
                Boolean result = (Boolean) attr.getAttribute("IS_INVITE_ACCEPTANCE", RequestAttributes.SCOPE_SESSION);
                if (result!=null) {
                    return result;
                }
            }
        } catch (IllegalStateException x) {
            //nothing bound on thread.
            logger.debug("Unable to retrieve request attributes looking for invitation.");

        }
        return false;
    }

    private static class UaaConnectionKeepAliveStrategy implements ConnectionKeepAliveStrategy {

        private static final String TIMEOUT = "timeout";

        private final long connectionKeepAliveMax;

        public UaaConnectionKeepAliveStrategy(long connectionKeepAliveMax) {
            this.connectionKeepAliveMax = connectionKeepAliveMax;
        }

        @Override public long getKeepAliveDuration(HttpResponse httpResponse, HttpContext httpContext) {
            HeaderElementIterator elementIterator = new BasicHeaderElementIterator(httpResponse.headerIterator(HTTP.CONN_KEEP_ALIVE));
            long result = connectionKeepAliveMax;

            while (elementIterator.hasNext()) {
                HeaderElement element = elementIterator.nextElement();
                String elementName = element.getName();
                String elementValue = element.getValue();
                if (elementValue != null && elementName != null && elementName.equalsIgnoreCase(TIMEOUT)) {
                    try {
                        result = Math.min(TimeUnit.SECONDS.toMillis(Long.parseLong(elementValue)), connectionKeepAliveMax);
                    } catch (NumberFormatException e) {
                        //Ignore Exception and keep current elementValue of result
                    }
                    break;
                }
            }
            return result;
        }
    }

    private static String[] split(final String s) {
        if (TextUtils.isBlank(s)) {
            return null;
        }
        return s.split(" *, *");
    }
}
