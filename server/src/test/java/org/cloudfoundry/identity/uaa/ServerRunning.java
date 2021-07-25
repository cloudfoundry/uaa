/*******************************************************************************
 *     Cloud Foundry 
 *     Copyright (c) [2009-2016] Pivotal Software, Inc. All Rights Reserved.
 *
 *     This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *     You may not use this product except in compliance with the License.
 *
 *     This product includes a number of subcomponents with
 *     separate copyright notices and license terms. Your use of these
 *     subcomponents is subject to the terms and conditions of the
 *     subcomponent's license, as noted in the LICENSE file.
 *******************************************************************************/
package org.cloudfoundry.identity.uaa;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.apache.http.client.HttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.cloudfoundry.identity.uaa.test.TestProfileEnvironment;
import org.cloudfoundry.identity.uaa.test.UrlHelper;
import org.junit.Assume;
import org.junit.internal.AssumptionViolatedException;
import org.junit.rules.MethodRule;
import org.junit.runners.model.FrameworkMethod;
import org.junit.runners.model.Statement;
import org.springframework.core.env.Environment;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.http.client.ClientHttpResponse;
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;
import org.springframework.http.client.support.HttpAccessor;
import org.springframework.security.oauth2.client.test.RestTemplateHolder;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.ResponseErrorHandler;
import org.springframework.web.client.RestOperations;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriUtils;

import java.io.IOException;
import java.net.Socket;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.HashMap;
import java.util.Map;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.Assert.assertTrue;

/**
 * <p>
 * A rule that prevents integration tests from failing if the server application
 * is not running or not accessible. If the server is not running in the
 * background all the tests here will simply be skipped because of a violated
 * assumption (showing as successful). Usage:
 * </p>
 * 
 * <pre>
 * &#064;Rule public static ServerRunning brokerIsRunning = ServerRunning.isRunning();
 * 
 * &#064;Test public void testSendAndReceive() throws Exception { // ... test using server etc. }
 * </pre>
 * <p>
 * The rule can be declared as static so that it only has to check once for all
 * tests in the enclosing test case, but there isn't a lot of overhead in making
 * it non-static.
 * </p>
 * 
 * @see Assume
 * @see AssumptionViolatedException
 * 
 * @author Dave Syer
 * 
 */
public class ServerRunning implements MethodRule, RestTemplateHolder, UrlHelper {

    private static Logger logger = LoggerFactory.getLogger(ServerRunning.class);

    private Environment environment;

    // Static so that we only test once on failure: speeds up test suite
    private static Map<Integer, Boolean> serverOnline = new HashMap<Integer, Boolean>();

    private final boolean integrationTest;

    private static int DEFAULT_PORT = 8080;

    private static String DEFAULT_HOST = "localhost";

    private static String DEFAULT_ROOT_PATH = "/uaa";

    private int port;

    private String hostName = DEFAULT_HOST;

    private String rootPath = DEFAULT_ROOT_PATH;

    private RestOperations client;

    /**
     * @return a new rule that assumes an existing running broker
     */
    public static ServerRunning isRunning() {
        return new ServerRunning();
    }

    private ServerRunning() {
        environment = TestProfileEnvironment.getEnvironment();
        integrationTest = environment.getProperty("uaa.integration.test", Boolean.class, false);
        client = getRestTemplate();
        setPort(environment.getProperty("uaa.port", Integer.class, DEFAULT_PORT));
        setRootPath(environment.getProperty("uaa.path", DEFAULT_ROOT_PATH));
        setHostName(environment.getProperty("uaa.host", DEFAULT_HOST));
    }

    /**
     * @param port the port to set
     */
    public void setPort(int port) {
        this.port = port;
    }

    /**
     * @param hostName the hostName to set
     */
    public void setHostName(String hostName) {
        this.hostName = hostName;
    }
    
    public String getHostName() {
        return hostName;
    }

    /**
     * The context root in the application, e.g. "/uaa" for a local deployment.
     * 
     * @param rootPath the rootPath to set
     */
    public void setRootPath(String rootPath) {
        if (rootPath.equals("/")) {
            rootPath = "";
        }
        else {
            if (!rootPath.startsWith("/")) {
                rootPath = "/" + rootPath;
            }
        }
        this.rootPath = rootPath;
    }

    @Override
    public Statement apply(Statement statement, FrameworkMethod frameworkMethod, Object o) {
        assertTrue("Test could not reach the server at " + hostName + ":" + port, getStatus());
        return statement;
    }

    private synchronized Boolean getStatus() {
        Boolean available = serverOnline.get(port);
        if (available == null) {
            available = connectionAvailable();
            serverOnline.put(port, available);
        }
        return available;
    }

    private boolean connectionAvailable() {
        logger.info("Testing connectivity for " + hostName + ":" + port);
        try (Socket socket = new Socket(hostName, port)) {
            logger.info("Connectivity test succeeded for " + hostName + ":" + port);
            return true;

        } catch (IOException e) {
            logger.warn("Connectivity test failed for " + hostName + ":" + port, e);
            return false;
        }
    }

    @Override
    public String getBaseUrl() {
        return "http://" + hostName + (port == 80 ? "" : ":" + port) + rootPath;
    }

    @Override
    public String getAccessTokenUri() {
        return getUrl("/oauth/token");
    }

    @Override
    public String getAuthorizationUri() {
        return getUrl("/oauth/authorize");
    }

    @Override
    public String getClientsUri() {
        return getUrl("/oauth/clients");
    }

    @Override
    public String getUsersUri() {
        return getUrl("/Users");
    }

    @Override
    public String getUserUri() {
        return getUrl("/Users");
    }

    @Override
    public String getUrl(String path) {
        if (path.startsWith("http:")) {
            return path;
        }
        if (!path.startsWith("/")) {
            path = "/" + path;
        }
        return getBaseUrl() + path;
    }

    public ResponseEntity<String> postForString(String path, MultiValueMap<String, String> formData, HttpHeaders headers) {
        if (headers.getContentType() == null) {
            headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        }
        return client.exchange(getUrl(path), HttpMethod.POST, new HttpEntity<>(formData, headers), String.class);
    }

    @SuppressWarnings("rawtypes")
    public ResponseEntity<Map> postForMap(String path, MultiValueMap<String, String> formData, HttpHeaders headers) {
        if (headers.getContentType() == null) {
            headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        }
        return client.exchange(getUrl(path), HttpMethod.POST, new HttpEntity<>(formData, headers), Map.class);
    }

    @SuppressWarnings("rawtypes")
    public ResponseEntity<Map> postForMap(String path, String requestBody, HttpHeaders headers) {
        if (headers.getContentType() == null) {
            headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        }
        return client.exchange(getUrl(path), HttpMethod.POST, new HttpEntity<>(requestBody, headers), Map.class);
    }

    public ResponseEntity<String> getForString(String path) {
        return getForString(path, new HttpHeaders());
    }

    public <T> ResponseEntity<T> getForObject(String path, Class<T> type, final HttpHeaders headers) {
        return client.exchange(getUrl(path), HttpMethod.GET, new HttpEntity<>(null, headers), type);
    }

    public <T> ResponseEntity<T> getForObject(String path, Class<T> type) {
        return getForObject(path, type, new HttpHeaders());
    }

    public ResponseEntity<String> getForString(String path, final HttpHeaders headers) {
        HttpEntity<Void> request = new HttpEntity<>(null, headers);
        return client.exchange(getUrl(path), HttpMethod.GET, request, String.class);
    }

    public ResponseEntity<Void> getForResponse(String path, final HttpHeaders headers, Object... uriVariables) {
        HttpEntity<Void> request = new HttpEntity<>(null, headers);
        return client.exchange(getUrl(path), HttpMethod.GET, request, Void.class, uriVariables);
    }

    public ResponseEntity<Void> postForResponse(String path, HttpHeaders headers, MultiValueMap<String, String> params) {
        HttpHeaders actualHeaders = new HttpHeaders();
        actualHeaders.putAll(headers);
        actualHeaders.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

        return client.exchange(getUrl(path), HttpMethod.POST, new HttpEntity<>(params,
                        actualHeaders), Void.class);
    }

    public ResponseEntity<Void> postForRedirect(String path, HttpHeaders headers, MultiValueMap<String, String> params) {
        ResponseEntity<Void> exchange = postForResponse(path, headers, params);

        if (exchange.getStatusCode() != HttpStatus.FOUND) {
            throw new IllegalStateException("Expected 302 but server returned status code " + exchange.getStatusCode());
        }

        headers.remove("Cookie");
        if (exchange.getHeaders().containsKey("Set-Cookie")) {
            for (String cookie : exchange.getHeaders().get("Set-Cookie")) {
                headers.add("Cookie", cookie);
            }
        }

        String location = exchange.getHeaders().getLocation().toString();

        return client.exchange(location, HttpMethod.GET, new HttpEntity<Void>(null, headers), Void.class);
    }

    @Override
    public RestOperations getRestTemplate() {
        if (client == null) {
            client = createRestTemplate();
        }
        return client;
    }

    @Override
    public void setRestTemplate(RestOperations restTemplate) {
        this.client = restTemplate;
        if (restTemplate instanceof HttpAccessor) {
            ((HttpAccessor) restTemplate).setRequestFactory(new StatelessRequestFactory());
        }
    }

    public RestTemplate createRestTemplate() {
        RestTemplate client = new RestTemplate();
        client.setRequestFactory(new StatelessRequestFactory());
        client.setErrorHandler(new ResponseErrorHandler() {
            // Pass errors through in response entity for status code analysis
            @Override
            public boolean hasError(ClientHttpResponse response) {
                return false;
            }

            @Override
            public void handleError(ClientHttpResponse response) {
            }
        });
        return client;
    }

    public UriBuilder buildUri(String url) {
        return UriBuilder.fromUri(url.startsWith("http:") ? url : getUrl(url));
    }

    private static class StatelessRequestFactory extends HttpComponentsClientHttpRequestFactory {
        @Override
        public HttpClient getHttpClient() {
            return HttpClientBuilder.create()
                    .useSystemProperties()
                    .disableRedirectHandling()
                    .disableCookieManagement()
                    .build();
        }
    }

    public static class UriBuilder {

        private final String url;

        private MultiValueMap<String, String> params = new LinkedMultiValueMap<>();

        public UriBuilder(String url) {
            this.url = url;
        }

        public static UriBuilder fromUri(String url) {
            return new UriBuilder(url);
        }

        public UriBuilder queryParam(String key, String value) {
            params.add(key, value);
            return this;
        }

        public URI build() {
            StringBuilder builder = new StringBuilder(url);
            try {
                if (!params.isEmpty()) {
                    builder.append("?");
                    boolean first = true;
                    for (String key : params.keySet()) {
                        if (!first) {
                            builder.append("&");
                        }
                        else {
                            first = false;
                        }
                        for (String value : params.get(key)) {
                            builder.append(key).append("=").append(UriUtils.encodeQueryParam(value, UTF_8));
                        }
                    }
                }
                return new URI(builder.toString());
            } catch (URISyntaxException ex) {
                throw new IllegalArgumentException("Could not create URI from [" + builder + "]: " + ex, ex);
            }
        }

    }

}
