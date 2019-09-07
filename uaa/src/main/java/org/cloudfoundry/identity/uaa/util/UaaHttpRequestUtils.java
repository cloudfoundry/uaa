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

import javax.net.ssl.SSLContext;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.util.Map;
import java.util.stream.Collectors;

import static java.util.Arrays.stream;

public abstract class UaaHttpRequestUtils {

    private static Logger logger = LoggerFactory.getLogger(UaaHttpRequestUtils.class);

    public static ClientHttpRequestFactory createRequestFactory(boolean skipSslValidation, int timeout) {
        return createRequestFactory(getClientBuilder(skipSslValidation), timeout);
    }

    protected static ClientHttpRequestFactory createRequestFactory(HttpClientBuilder builder, int timeoutInMs) {
        HttpComponentsClientHttpRequestFactory httpComponentsClientHttpRequestFactory = new HttpComponentsClientHttpRequestFactory(builder.build());

        httpComponentsClientHttpRequestFactory.setReadTimeout(timeoutInMs);
        httpComponentsClientHttpRequestFactory.setConnectionRequestTimeout(timeoutInMs);
        httpComponentsClientHttpRequestFactory.setConnectTimeout(timeoutInMs);
        return httpComponentsClientHttpRequestFactory;
    }

    protected static HttpClientBuilder getClientBuilder(boolean skipSslValidation) {
        HttpClientBuilder builder = HttpClients.custom()
            .useSystemProperties()
            .setRedirectStrategy(new DefaultRedirectStrategy());
        if (skipSslValidation) {
            builder.setSslcontext(getNonValidatingSslContext());
            builder.setSSLHostnameVerifier(new NoopHostnameVerifier());
        }
        builder.setConnectionReuseStrategy(NoConnectionReuseStrategy.INSTANCE);
        return builder;
    }

    private static SSLContext getNonValidatingSslContext() {
        try {
            return new SSLContextBuilder().loadTrustMaterial(null, new TrustSelfSignedStrategy()).build();
        } catch (KeyManagementException e) {
            throw new RuntimeException(e);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        } catch (KeyStoreException e) {
            throw new RuntimeException(e);
        }
    }

    public static String paramsToQueryString(Map<String, String[]> parameterMap) {
        return parameterMap.entrySet().stream()
          .flatMap(param -> stream(param.getValue()).map(value -> param.getKey() + "=" + encodeParameter(value)))
          .collect(Collectors.joining("&"));
    }

    private static String encodeParameter(String value) {
        try {
            return URLEncoder.encode(value, "UTF-8");
        } catch (UnsupportedEncodingException e) {
            throw new RuntimeException(e);
        }
    }

    public static boolean isAcceptedInvitationAuthentication() {
        try {
            RequestAttributes attr = RequestContextHolder.currentRequestAttributes();
            if (attr!=null) {
                Boolean result = (Boolean) attr.getAttribute("IS_INVITE_ACCEPTANCE", RequestAttributes.SCOPE_SESSION);
                if (result!=null) {
                    return result.booleanValue();
                }
            }
        } catch (IllegalStateException x) {
            //nothing bound on thread.
            logger.debug("Unable to retrieve request attributes looking for invitation.");

        }
        return false;
    }
}
