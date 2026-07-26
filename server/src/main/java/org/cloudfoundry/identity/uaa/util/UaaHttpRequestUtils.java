/*
 * *****************************************************************************
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

import tools.jackson.core.type.TypeReference;
import jakarta.servlet.http.HttpServletRequest;
import org.apache.hc.client5.http.ConnectionKeepAliveStrategy;
import org.apache.hc.client5.http.HttpRequestRetryStrategy;
import org.apache.hc.client5.http.config.ConnectionConfig;
import org.apache.hc.client5.http.impl.DefaultRedirectStrategy;
import org.apache.hc.client5.http.impl.NoopUserTokenHandler;
import org.apache.hc.client5.http.impl.classic.HttpClientBuilder;
import org.apache.hc.client5.http.impl.classic.HttpClients;
import org.apache.hc.client5.http.impl.io.PoolingHttpClientConnectionManager;
import org.apache.hc.client5.http.impl.io.PoolingHttpClientConnectionManagerBuilder;
import org.apache.hc.client5.http.socket.ConnectionSocketFactory;
import org.apache.hc.client5.http.socket.PlainConnectionSocketFactory;
import org.apache.hc.client5.http.ssl.NoopHostnameVerifier;
import org.apache.hc.client5.http.ssl.SSLConnectionSocketFactory;
import org.apache.hc.client5.http.ssl.TrustSelfSignedStrategy;
import org.apache.hc.core5.http.HeaderElement;
import org.apache.hc.core5.http.HttpHeaders;
import org.apache.hc.core5.http.HttpRequest;
import org.apache.hc.core5.http.HttpResponse;
import org.apache.hc.core5.http.config.Registry;
import org.apache.hc.core5.http.config.RegistryBuilder;
import org.apache.hc.core5.http.io.SocketConfig;
import org.apache.hc.core5.http.message.BasicHeaderElementIterator;
import org.apache.hc.core5.http.protocol.HttpContext;
import org.apache.hc.core5.ssl.SSLContextBuilder;
import org.apache.hc.core5.util.TextUtils;
import org.apache.hc.core5.util.TimeValue;
import org.apache.hc.core5.util.Timeout;
import org.cloudfoundry.identity.uaa.impl.config.RestTemplateConfig;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.client.ClientHttpRequestFactory;
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;
import org.springframework.web.context.request.RequestAttributes;
import org.springframework.web.context.request.RequestContextHolder;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLContext;
import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;

import static java.util.Arrays.stream;

public abstract class UaaHttpRequestUtils {

    private static final Logger logger = LoggerFactory.getLogger(UaaHttpRequestUtils.class);

    record HttpClientConfig(
            int poolSize,
            int defaultMaxPerRoute,
            int maxKeepAlive,
            int validateAfterInactivity,
            int retryCount,
            int connectTimeoutInMs,
            int readTimeoutInMs,
            int connectionRequestTimeoutInMs
    ) {
        public static HttpClientConfig defaults(int connectTimeoutInMs, int readTimeoutInMs) {
            return new HttpClientConfig(10, 5, 0, 2000, 0, connectTimeoutInMs, readTimeoutInMs, connectTimeoutInMs);
        }
    }

    public static ClientHttpRequestFactory createRequestFactory(boolean skipSslValidation, int timeout) {
        HttpClientConfig config = HttpClientConfig.defaults(timeout, timeout);
        return createRequestFactory(getClientBuilder(skipSslValidation, config), config.connectionRequestTimeoutInMs());
    }

    /**
     * Creates a request factory whose DNS resolver blocks private/loopback/link-local
     * addresses at connection time. Redirects are disabled to prevent SSRF via a
     * redirect to a private IP literal that would bypass DNS-based blocking.
     * Use this for outbound fetches to operator-supplied URLs (e.g. jwks_uri).
     */
    public static ClientHttpRequestFactory createSafeRequestFactory(RestTemplateConfig restTemplateConfig) {
        HttpClientConfig config = new HttpClientConfig(restTemplateConfig.maxTotal, restTemplateConfig.maxPerRoute,
                restTemplateConfig.maxKeepAlive, restTemplateConfig.validateAfterInactivity,
                restTemplateConfig.retryCount, restTemplateConfig.timeout, restTemplateConfig.timeout,
                restTemplateConfig.timeout);
        HttpClientBuilder builder = HttpClients.custom()
                .useSystemProperties()
                .setUserTokenHandler(NoopUserTokenHandler.INSTANCE)
                .disableRedirectHandling();
        PoolingHttpClientConnectionManager cm = PoolingHttpClientConnectionManagerBuilder.create()
                .setDnsResolver(PrivateNetworkBlockingDnsResolver.INSTANCE)
                .build();
        cm.setMaxTotal(config.poolSize());
        cm.setDefaultMaxPerRoute(config.defaultMaxPerRoute());
        cm.setValidateAfterInactivity(TimeValue.of(config.validateAfterInactivity(), TimeUnit.MILLISECONDS));
        cm.setDefaultConnectionConfig(ConnectionConfig.custom()
                .setConnectTimeout(toTimeout(config.connectTimeoutInMs()))
                .build());
        cm.setDefaultSocketConfig(SocketConfig.custom()
                .setSoTimeout(toTimeout(config.readTimeoutInMs()))
                .build());
        builder.setConnectionManager(cm);
        if (config.maxKeepAlive() <= 0) {
            builder.setConnectionReuseStrategy((_, _, _) -> false);
        } else {
            builder.setKeepAliveStrategy(new UaaConnectionKeepAliveStrategy(config.maxKeepAlive()));
        }
        if (config.retryCount() > 0) {
            builder.setRetryStrategy(new UaaHttpRequestRetryHandler(config.retryCount()));
        }
        return createRequestFactory(builder, config.connectionRequestTimeoutInMs());
    }

    public static ClientHttpRequestFactory createRequestFactory(boolean skipSslValidation, int connectTimeout, int readTimeout, RestTemplateConfig restTemplateConfig) {
        HttpClientConfig config = new HttpClientConfig(restTemplateConfig.maxTotal, restTemplateConfig.maxPerRoute, restTemplateConfig.maxKeepAlive, restTemplateConfig.validateAfterInactivity, restTemplateConfig.retryCount, connectTimeout, readTimeout, connectTimeout);
        return createRequestFactory(getClientBuilder(skipSslValidation, config), config.connectionRequestTimeoutInMs());
    }

    protected static ClientHttpRequestFactory createRequestFactory(HttpClientBuilder builder, int connectionRequestTimeoutInMs) {
        HttpComponentsClientHttpRequestFactory factory = new HttpComponentsClientHttpRequestFactory(builder.build());
        factory.setConnectionRequestTimeout(connectionRequestTimeoutInMs);
        return factory;
    }

    static HttpClientBuilder getClientBuilder(boolean skipSslValidation, HttpClientConfig config) {
        HttpClientBuilder builder = HttpClients.custom()
                .useSystemProperties()
                .setUserTokenHandler(NoopUserTokenHandler.INSTANCE)
                .setRedirectStrategy(new DefaultRedirectStrategy());
        PoolingHttpClientConnectionManager cm;
        if (skipSslValidation) {
            SSLContext sslContext = getNonValidatingSslContext();
            final String[] supportedProtocols = split(System.getProperty("https.protocols"));
            final String[] supportedCipherSuites = split(System.getProperty("https.cipherSuites"));
            HostnameVerifier hostnameVerifierCopy = new NoopHostnameVerifier();
            SSLConnectionSocketFactory sslSocketFactory = new SSLConnectionSocketFactory(sslContext, supportedProtocols, supportedCipherSuites, hostnameVerifierCopy);
            Registry<ConnectionSocketFactory> socketFactoryRegistry = RegistryBuilder.<ConnectionSocketFactory>create()
                    .register("https", sslSocketFactory)
                    .register("http", PlainConnectionSocketFactory.getSocketFactory())
                    .build();
            cm = new PoolingHttpClientConnectionManager(socketFactoryRegistry);
        } else {
            cm = new PoolingHttpClientConnectionManager();
        }
        cm.setMaxTotal(config.poolSize());
        cm.setDefaultMaxPerRoute(config.defaultMaxPerRoute());
        cm.setValidateAfterInactivity(TimeValue.of(config.validateAfterInactivity(), TimeUnit.MILLISECONDS));

        cm.setDefaultConnectionConfig(ConnectionConfig.custom()
                .setConnectTimeout(toTimeout(config.connectTimeoutInMs()))
                .build());
        cm.setDefaultSocketConfig(SocketConfig.custom()
                .setSoTimeout(toTimeout(config.readTimeoutInMs()))
                .build());

        builder.setConnectionManager(cm);

        if (config.maxKeepAlive() <= 0) {
            builder.setConnectionReuseStrategy((_, _, _) -> false);
        } else {
            builder.setKeepAliveStrategy(new UaaConnectionKeepAliveStrategy(config.maxKeepAlive()));
        }

        if (config.retryCount() > 0) {
            builder.setRetryStrategy(new UaaHttpRequestRetryHandler(config.retryCount()));
        }

        return builder;
    }

    private static Timeout toTimeout(int millis) {
        return millis <= 0 ? Timeout.DISABLED : Timeout.ofMilliseconds(millis);
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
            if (attr != null) {
                Boolean result = (Boolean) attr.getAttribute("IS_INVITE_ACCEPTANCE", RequestAttributes.SCOPE_SESSION);
                if (result != null) {
                    return result;
                }
            }
        } catch (IllegalStateException _) {
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

        @Override
        public TimeValue getKeepAliveDuration(HttpResponse httpResponse, HttpContext httpContext) {
            BasicHeaderElementIterator elementIterator = new BasicHeaderElementIterator(httpResponse.headerIterator(HttpHeaders.KEEP_ALIVE));
            long result = connectionKeepAliveMax;

            while (elementIterator.hasNext()) {
                HeaderElement element = elementIterator.next();
                String elementName = element.getName();
                String elementValue = element.getValue();
                if (elementValue != null && elementName != null && elementName.equalsIgnoreCase(TIMEOUT)) {
                    try {
                        result = Math.min(TimeUnit.SECONDS.toMillis(Long.parseLong(elementValue)), connectionKeepAliveMax);
                    } catch (NumberFormatException _) {
                        //Ignore Exception and keep current elementValue of result
                    }
                    break;
                }
            }
            return TimeValue.of(result, TimeUnit.MILLISECONDS);
        }
    }

    private static class UaaHttpRequestRetryHandler implements HttpRequestRetryStrategy {

        private final int executionCount;

        public UaaHttpRequestRetryHandler(int executionCount) {
            this.executionCount = executionCount;
        }

        @Override
        public boolean retryRequest(HttpRequest request, IOException exception, int execCount, HttpContext context) {
            if (execCount > this.executionCount) {
                return false;
            }
            if (exception instanceof org.apache.hc.core5.http.NoHttpResponseException) {
                return true;
            }
            return false;
        }

        @Override
        public boolean retryRequest(HttpResponse response, int execCount, HttpContext context) {
            return execCount <= this.executionCount;
        }

        @Override
        public TimeValue getRetryInterval(HttpResponse response, int execCount, HttpContext context) {
            return TimeValue.of(1, TimeUnit.SECONDS);
        }
    }

    @SuppressWarnings("java:S1168")
    private static String[] split(final String s) {
        if (TextUtils.isBlank(s)) {
            return null;
        }
        return stream(s.split(",")).map(String::trim).toList().toArray(String[]::new);
    }

    public static Map<String, String> getCredentials(HttpServletRequest request, List<String> parameterNames) {
        Map<String, String> credentials = new HashMap<>();

        for (String paramName : parameterNames) {
            String value = request.getParameter(paramName);
            if (value != null) {
                if (value.startsWith("{")) {
                    try {
                        Map<String, String> jsonCredentials = JsonUtils.readValue(value,
                                new TypeReference<>() {
                                });
                        credentials.putAll(jsonCredentials);
                    } catch (JsonUtils.JsonUtilException _) {
                        logger.warn("Unknown format of value for request param: {}. Ignoring.", paramName);
                    }
                } else {
                    credentials.put(paramName, value);
                }
            }
        }
        return credentials;
    }
}
