package org.cloudfoundry.identity.uaa.util;

import org.apache.http.conn.ssl.SSLContextBuilder;
import org.apache.http.conn.ssl.TrustSelfSignedStrategy;
import org.apache.http.impl.NoConnectionReuseStrategy;
import org.apache.http.impl.client.DefaultRedirectStrategy;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.impl.client.HttpClients;
import org.springframework.http.client.ClientHttpRequestFactory;
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;

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

    public static ClientHttpRequestFactory createRequestFactory() {
        return createRequestFactory(false);
    }

    public static ClientHttpRequestFactory createRequestFactory(boolean skipSslValidation) {
        return createRequestFactory(getClientBuilder(skipSslValidation));
    }

    protected static ClientHttpRequestFactory createRequestFactory(HttpClientBuilder builder) {
        return new HttpComponentsClientHttpRequestFactory(builder.build());
    }

    protected static HttpClientBuilder getClientBuilder(boolean skipSslValidation) {
        HttpClientBuilder builder = HttpClients.custom()
            .useSystemProperties()
            .setRedirectStrategy(new DefaultRedirectStrategy());
        if (skipSslValidation) {
            builder.setSslcontext(getNonValidatingSslContext());
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
}
