package org.cloudfoundry.identity.uaa.util;

import org.apache.http.conn.ssl.SSLContextBuilder;
import org.apache.http.conn.ssl.TrustSelfSignedStrategy;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.DefaultRedirectStrategy;
import org.apache.http.impl.client.HttpClients;
import org.springframework.http.client.ClientHttpRequestFactory;
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;

import javax.net.ssl.SSLContext;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;

public class UaaHttpRequestUtils {

    public static ClientHttpRequestFactory getNoValidatingClientHttpRequestFactory() {
        ClientHttpRequestFactory requestFactory;
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
        //
        CloseableHttpClient httpClient =
                HttpClients.custom()
                        .setSslcontext(sslContext)
                        .setRedirectStrategy(new DefaultRedirectStrategy()).build();

        requestFactory = new HttpComponentsClientHttpRequestFactory(httpClient);
        return requestFactory;
    }
}
