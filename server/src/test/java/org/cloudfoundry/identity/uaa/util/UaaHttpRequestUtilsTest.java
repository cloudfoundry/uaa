package org.cloudfoundry.identity.uaa.util;

import com.sun.net.httpserver.HttpServer;
import com.sun.net.httpserver.HttpsServer;
import org.apache.http.HttpException;
import org.apache.http.HttpHost;
import org.apache.http.HttpRequest;
import org.apache.http.conn.routing.HttpRoute;
import org.apache.http.conn.routing.HttpRoutePlanner;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.protocol.HttpContext;
import org.cloudfoundry.identity.uaa.test.network.NetworkTestUtils;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
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

import static org.cloudfoundry.identity.uaa.util.UaaHttpRequestUtils.createRequestFactory;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;
import static org.springframework.http.HttpStatus.OK;

public class UaaHttpRequestUtilsTest {

    private static final String HTTP_HOST_PROPERTY = "http.proxyHost";
    private static final String HTTP_PORT_PROPERTY = "http.proxyPort";
    private static final String HTTPS_HOST_PROPERTY = "https.proxyHost";
    private static final String HTTPS_PORT_PROPERTY = "https.proxyPort";

    private static Map<String,String> systemProxyConfig = new HashMap<>();
    private NetworkTestUtils.SimpleHttpResponseHandler httpResponseHandler;
    private NetworkTestUtils.SimpleHttpResponseHandler httpsResponseHandler;

    @BeforeClass
    public static void storeSystemProxyConfig() {
        for (String s : Arrays.asList(HTTP_HOST_PROPERTY, HTTP_PORT_PROPERTY, HTTPS_HOST_PROPERTY, HTTPS_PORT_PROPERTY)) {
            systemProxyConfig.put(s, System.getProperty(s));
        }
    }
    @AfterClass
    public static void restoreSystemProxyConfig() {
        for (Map.Entry<String,String> entry : systemProxyConfig.entrySet()) {
            if (entry.getValue()!=null) {
                System.setProperty(entry.getKey(), entry.getValue());
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
    int sslPort;
    int port;
    private String httpsUrl;
    private String httpUrl;

    @Before
    public void setup() throws Exception {
        clearSystemProxyConfig();
        File keystore = NetworkTestUtils.getKeystore(new Date(), 10);
        sslPort = 23438;
        port = sslPort+1;
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        httpResponseHandler = new NetworkTestUtils.SimpleHttpResponseHandler(200, headers, "OK");
        httpsResponseHandler = new NetworkTestUtils.SimpleHttpResponseHandler(200, headers, "OK");

        httpsServer = NetworkTestUtils.startHttpsServer(sslPort, keystore, NetworkTestUtils.keyPass, httpsResponseHandler);
        httpServer = NetworkTestUtils.startHttpServer(port, httpResponseHandler);
        httpsUrl = "https://localhost:" + sslPort + "/";
        httpUrl = "http://localhost:" + port + "/";
    }

    @After
    public void teardown() throws Exception {
        httpsServer.stop(0);
        httpServer.stop(0);
    }


    @Test
    public void testHttpProxy() throws Exception {
        String host = "localhost";
        System.setProperty(HTTP_HOST_PROPERTY, host);
        System.setProperty(HTTP_PORT_PROPERTY, String.valueOf(port));
        testHttpProxy("http://google.com:80/", port, host, true);
    }

    @Test
    public void testHttpsProxy() throws Exception {
        String host = "localhost";
        System.setProperty(HTTPS_HOST_PROPERTY, host);
        System.setProperty(HTTPS_PORT_PROPERTY, String.valueOf(port));
        testHttpProxy("https://google.com:443/", port, host, false);
    }

    @Test
    public void testHttpIpProxy() throws Exception {
        String ip = "127.0.0.1";
        System.setProperty(HTTP_HOST_PROPERTY, ip);
        System.setProperty(HTTP_PORT_PROPERTY, String.valueOf(port));
        testHttpProxy("http://google.com:80/", port, ip, true);
    }

    @Test
    public void testHttpsIpProxy() throws Exception {
        String ip = "127.0.0.1";
        System.setProperty(HTTPS_HOST_PROPERTY, ip);
        System.setProperty(HTTPS_PORT_PROPERTY, String.valueOf(port));
        testHttpProxy("https://google.com:443/", port, ip, false);
    }

    public void testHttpProxy(String url, int expectedPort, String expectedHost, boolean wantHandlerInvoked) throws Exception {
        HttpClientBuilder builder = UaaHttpRequestUtils.getClientBuilder(true);
        HttpRoutePlanner planner = (HttpRoutePlanner) ReflectionTestUtils.getField(builder.build(), "routePlanner");
        SystemProxyRoutePlanner routePlanner = new SystemProxyRoutePlanner(planner);
        builder.setRoutePlanner(routePlanner);
        RestTemplate template = new RestTemplate(UaaHttpRequestUtils.createRequestFactory(builder));
        try {
            template.getForObject(url,String.class);
        } catch (Exception e) {
        }
        assertEquals(1, routePlanner.routes.size());
        assertEquals(expectedHost, routePlanner.routes.get(0).getProxyHost().getHostName());
        assertEquals(expectedPort, routePlanner.routes.get(0).getProxyHost().getPort());
        assertEquals(wantHandlerInvoked, httpResponseHandler.wasInvoked());
    }

    @Test
    public void skipSslValidation() {
        RestTemplate restTemplate = new RestTemplate(createRequestFactory(true));
        assertEquals(OK, restTemplate.getForEntity(httpsUrl, String.class).getStatusCode());
        restTemplate.setRequestFactory(UaaHttpRequestUtils.createRequestFactory(true));
        assertEquals(OK, restTemplate.getForEntity(httpsUrl, String.class).getStatusCode());
    }


    @Test
    public void trustedOnly() {
        RestTemplate restTemplate = new RestTemplate(UaaHttpRequestUtils.createRequestFactory(false));
        try {
            restTemplate.getForEntity(httpsUrl, String.class);
            fail("We should not reach this step if the above URL is using a self signed certificate");
        } catch (RestClientException e) {
            assertEquals(SSLHandshakeException.class, e.getCause().getClass());
        }
    }


    public static class SystemProxyRoutePlanner implements HttpRoutePlanner {

        private final HttpRoutePlanner delegate;
        public List<HttpRoute> routes = new LinkedList<>();

        public SystemProxyRoutePlanner(HttpRoutePlanner delegate) {
            this.delegate = delegate;
        }

        @Override
        public HttpRoute determineRoute(HttpHost target, HttpRequest request, HttpContext context) throws HttpException {
            HttpRoute route = delegate.determineRoute(target, request, context);
            routes.add(route);
            return route;
        }
    }

}