package org.cloudfoundry.identity.uaa.util;

import com.sun.net.httpserver.HttpServer;
import com.sun.net.httpserver.HttpsServer;
import org.apache.hc.core5.http.HttpException;
import org.apache.hc.core5.http.HttpHost;
import org.apache.hc.core5.http.HttpRequest;
import org.apache.hc.client5.http.HttpRoute;
import org.apache.hc.client5.http.impl.classic.HttpClientBuilder;
import org.apache.hc.client5.http.routing.HttpRoutePlanner;
import org.apache.hc.core5.http.protocol.HttpContext;
import org.cloudfoundry.identity.uaa.test.network.NetworkTestUtils;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestTemplate;

import javax.net.ssl.SSLHandshakeException;
import java.io.File;
import java.util.Arrays;
import java.util.Date;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.fail;
import static org.cloudfoundry.identity.uaa.util.UaaHttpRequestUtils.createRequestFactory;
import static org.springframework.http.HttpStatus.OK;

class UaaHttpRequestUtilsTest {

    private static final String HTTP_HOST_PROPERTY = "http.proxyHost";
    private static final String HTTP_PORT_PROPERTY = "http.proxyPort";
    private static final String HTTPS_HOST_PROPERTY = "https.proxyHost";
    private static final String HTTPS_PORT_PROPERTY = "https.proxyPort";

    private static final Map<String, String> systemProxyConfig = new HashMap<>();
    private NetworkTestUtils.SimpleHttpResponseHandler httpResponseHandler;

    @BeforeAll
    static void storeSystemProxyConfig() {
        for (String s : Arrays.asList(HTTP_HOST_PROPERTY, HTTP_PORT_PROPERTY, HTTPS_HOST_PROPERTY, HTTPS_PORT_PROPERTY)) {
            systemProxyConfig.put(s, System.getProperty(s));
        }
    }

    @AfterAll
    static void restoreSystemProxyConfig() {
        for (Map.Entry<String, String> entry : systemProxyConfig.entrySet()) {
            if (entry.getValue() != null) {
                System.setProperty(entry.getKey(), entry.getValue());
            } else {
                System.clearProperty(entry.getKey());
            }
        }
    }

    public void clearSystemProxyConfig() {
        System.clearProperty(HTTPS_HOST_PROPERTY);
        System.clearProperty(HTTPS_PORT_PROPERTY);
        System.clearProperty(HTTP_HOST_PROPERTY);
        System.clearProperty(HTTP_PORT_PROPERTY);
    }

    HttpsServer httpsServer;
    HttpServer httpServer;
    private String httpsUrl;

    @BeforeEach
    void setup() throws Exception {
        clearSystemProxyConfig();
        File keystore = NetworkTestUtils.getKeystore(new Date(), 10);
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        httpResponseHandler = new NetworkTestUtils.SimpleHttpResponseHandler(headers, "OK");
        NetworkTestUtils.SimpleHttpResponseHandler httpsResponseHandler = new NetworkTestUtils.SimpleHttpResponseHandler(headers, "OK");

        httpsServer = NetworkTestUtils.startHttpsServer(keystore, NetworkTestUtils.keyPass, httpsResponseHandler);
        httpServer = NetworkTestUtils.startHttpServer(httpResponseHandler);
        httpsUrl = "https://localhost:" + httpsServer.getAddress().getPort() + "/";
    }

    @AfterEach
    void teardown() {
        httpsServer.stop(0);
        httpServer.stop(0);
    }

    @Test
    void httpProxy() {
        String host = "localhost";
        System.setProperty(HTTP_HOST_PROPERTY, host);
        System.setProperty(HTTP_PORT_PROPERTY, String.valueOf(httpServer.getAddress().getPort()));
        testHttpProxy("http://google.com:80/", httpServer.getAddress().getPort(), host, true);
    }

    @Test
    void httpsProxy() {
        String host = "localhost";
        System.setProperty("https.protocols", " TLSv1.2, TLSv1.3 ");
        System.setProperty(HTTPS_HOST_PROPERTY, host);
        System.setProperty(HTTPS_PORT_PROPERTY, String.valueOf(httpServer.getAddress().getPort()));
        testHttpProxy("https://google.com:443/", httpServer.getAddress().getPort(), host, false);
    }

    @Test
    void httpIpProxy() {
        String ip = "127.0.0.1";
        System.setProperty(HTTP_HOST_PROPERTY, ip);
        System.setProperty(HTTP_PORT_PROPERTY, String.valueOf(httpServer.getAddress().getPort()));
        testHttpProxy("http://google.com:80/", httpServer.getAddress().getPort(), ip, true);
    }

    @Test
    void httpsIpProxy() {
        String ip = "127.0.0.1";
        System.setProperty(HTTPS_HOST_PROPERTY, ip);
        System.setProperty(HTTPS_PORT_PROPERTY, String.valueOf(httpServer.getAddress().getPort()));
        testHttpProxy("https://google.com:443/", httpServer.getAddress().getPort(), ip, false);
    }

    public void testHttpProxy(String url, int expectedPort, String expectedHost, boolean wantHandlerInvoked) {
        HttpClientBuilder builder = UaaHttpRequestUtils.getClientBuilder(true, 20, 2, 5, 2000, 2);
        HttpRoutePlanner planner = (HttpRoutePlanner) ReflectionTestUtils.getField(builder.build(), "routePlanner");
        SystemProxyRoutePlanner routePlanner = new SystemProxyRoutePlanner(planner);
        builder.setRoutePlanner(routePlanner);
        RestTemplate template = new RestTemplate(UaaHttpRequestUtils.createRequestFactory(builder, Integer.MAX_VALUE, Integer.MAX_VALUE));
        try {
            template.getForObject(url, String.class);
        } catch (Exception ignored) {
            // ignored
        }
        assertThat(routePlanner.routes).hasSize(1);
        assertThat(routePlanner.routes.getFirst().getProxyHost().getHostName()).isEqualTo(expectedHost);
        assertThat(routePlanner.routes.getFirst().getProxyHost().getPort()).isEqualTo(expectedPort);
        assertThat(httpResponseHandler.wasInvoked()).isEqualTo(wantHandlerInvoked);
    }

    @Test
    void skipSslValidation() {
        RestTemplate restTemplate = new RestTemplate(createRequestFactory(true, 10_000));
        assertThat(restTemplate.getForEntity(httpsUrl, String.class).getStatusCode()).isEqualTo(OK);
    }

    @Test
    void trustedOnly() {
        RestTemplate restTemplate = new RestTemplate(UaaHttpRequestUtils.createRequestFactory(false, 10_000));
        try {
            restTemplate.getForEntity(httpsUrl, String.class);
            fail("We should not reach this step if the above URL is using a self signed certificate");
        } catch (RestClientException e) {
            assertThat(e.getCause().getClass()).isEqualTo(SSLHandshakeException.class);
        }
    }

    public static class SystemProxyRoutePlanner implements HttpRoutePlanner {
        private final HttpRoutePlanner delegate;
        public List<HttpRoute> routes = new LinkedList<>();

        public SystemProxyRoutePlanner(HttpRoutePlanner delegate) {
            this.delegate = delegate;
        }

        @Override
        public HttpRoute determineRoute(HttpHost target, HttpContext context) throws HttpException {
            HttpRoute route = delegate.determineRoute(target, context);
            routes.add(route);
            return route;
        }

        @Override
        public HttpRoute determineRoute(HttpHost target, HttpRequest request, HttpContext context) throws HttpException {
            HttpRoute route = delegate.determineRoute(target, request, context);
            routes.add(route);
            return route;
        }
    }
}
