package org.cloudfoundry.identity.uaa.util;

import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;

import javax.net.ssl.SSLContext;

import org.apache.http.conn.ssl.SSLContextBuilder;
import org.apache.http.conn.ssl.TrustSelfSignedStrategy;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.DefaultRedirectStrategy;
import org.apache.http.impl.client.HttpClients;
import org.springframework.http.client.ClientHttpRequestFactory;
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;

public class UaaHttpRequestUtils {

    public static ClientHttpRequestFactory createRequestFactory(boolean skipSslValidation) {
        ClientHttpRequestFactory clientHttpRequestFactory;
        if (skipSslValidation) {
            clientHttpRequestFactory = getNoValidatingClientHttpRequestFactory();
        } else {
            clientHttpRequestFactory = getClientHttpRequestFactory();
        }
        return clientHttpRequestFactory;
    }

    public static ClientHttpRequestFactory createRequestFactory() {
        return createRequestFactory(false);
    }

    public static ClientHttpRequestFactory getNoValidatingClientHttpRequestFactory() {
        SSLContext sslContext;
        try {
            sslContext = new SSLContextBuilder().loadTrustMaterial(null, new TrustSelfSignedStrategy()).build();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        } catch (KeyManagementException e) {
            throw new RuntimeException(e);
        } catch (KeyStoreException e) {
            throw new RuntimeException(e);
        }
        // Build the HTTP client from the system properties so that it uses the system proxy settings.
        CloseableHttpClient httpClient = HttpClients.custom().useSystemProperties().setSslcontext(sslContext)
                .setRedirectStrategy(new DefaultRedirectStrategy()).build();

        ClientHttpRequestFactory requestFactory = new HttpComponentsClientHttpRequestFactory(httpClient);
        return requestFactory;
    }

    public static ClientHttpRequestFactory getClientHttpRequestFactory() {
        CloseableHttpClient httpClient = HttpClients.custom().useSystemProperties()
                .setRedirectStrategy(new DefaultRedirectStrategy()).build();
        return new HttpComponentsClientHttpRequestFactory(httpClient);
    }
}
