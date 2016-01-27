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
package org.cloudfoundry.identity.app.integration;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URLDecoder;
import java.util.HashMap;
import java.util.Map;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.cloudfoundry.identity.uaa.test.TestProfileEnvironment;
import org.cloudfoundry.identity.uaa.test.UrlHelper;
import org.junit.Assume;
import org.junit.internal.AssumptionViolatedException;
import org.junit.rules.TestWatchman;
import org.junit.runners.model.FrameworkMethod;
import org.junit.runners.model.Statement;
import org.springframework.core.env.ConfigurableEnvironment;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.http.client.ClientHttpResponse;
import org.springframework.http.client.SimpleClientHttpRequestFactory;
import org.springframework.security.oauth2.client.test.RestTemplateHolder;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.ResponseErrorHandler;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestOperations;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriTemplate;
import org.springframework.web.util.UriUtils;

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
public class ServerRunning extends TestWatchman implements RestTemplateHolder, UrlHelper {

    private static Log logger = LogFactory.getLog(ServerRunning.class);

    // Static so that we only test once on failure: speeds up test suite
    private static Map<String, Boolean> serverOnline = new HashMap<String, Boolean>();

    private static final String DEFAULT_ROOT_PATH = "http://localhost:8080/app";

    private static final String DEFAULT_AUTH_SERVER_PATH = "http://localhost:8080/uaa";

    private String authServerRoot = DEFAULT_AUTH_SERVER_PATH;

    private String rootPath = DEFAULT_ROOT_PATH;

    private RestOperations client;

    private ConfigurableEnvironment environment;

    private Boolean integrationTest;

    /**
     * @return a new rule that assumes an existing running broker
     */
    public static ServerRunning isRunning() {
        return new ServerRunning();
    }

    private ServerRunning() {
        this.environment = TestProfileEnvironment.getEnvironment();
        this.integrationTest = environment.getProperty("uaa.integration.test", Boolean.class, false);
        setRootPath(environment.getProperty("app.path", DEFAULT_ROOT_PATH));
        setAuthServerRoot(environment.getProperty("uaa.path", DEFAULT_AUTH_SERVER_PATH));
        client = createRestTemplate();
    }

    /**
     * @param authServerRoot the authServerRoot to set
     */
    public void setAuthServerRoot(String authServerRoot) {
        this.authServerRoot = authServerRoot;
    }

    /**
     * @param rootPath the rootPath to set
     */
    public void setRootPath(String rootPath) {
        this.rootPath = rootPath;
        if (!serverOnline.containsKey(rootPath)) {
            serverOnline.put(rootPath, true);
        }
    }

    @Override
    public Statement apply(Statement base, FrameworkMethod method, Object target) {

        // Check at the beginning, so this can be used as a static field
        if (!integrationTest) {
            Assume.assumeTrue(serverOnline.get(rootPath));
        }

        RestTemplate client = new RestTemplate();
        boolean online = false;
        try {
            client.getForEntity(new UriTemplate(getAuthServerUrl("/login")).toString(), String.class);
            client.getForEntity(new UriTemplate(getUrl("/login_error.jsp")).toString(), String.class);
            online = true;
            logger.debug("Basic connectivity test passed");
        } catch (RestClientException e) {
            logger.warn(String.format(
                            "Not executing tests because basic connectivity test failed for root=" + rootPath), e);
            if (!integrationTest) {
                Assume.assumeNoException(e);
            }
        } finally {
            if (!online) {
                serverOnline.put(rootPath, false);
            }
        }

        return super.apply(base, method, target);

    }

    @Override
    public String getBaseUrl() {
        return rootPath;
    }

    @Override
    public String getAccessTokenUri() {
        return getAuthServerUrl("/oauth/token");
    }

    @Override
    public String getAuthorizationUri() {
        return getAuthServerUrl("/oauth/authorize");
    }

    @Override
    public String getClientsUri() {
        return getAuthServerUrl("/oauth/clients");
    }

    @Override
    public String getUsersUri() {
        return getAuthServerUrl("/Users");
    }

    @Override
    public String getUserUri() {
        return getAuthServerUrl("/Users");
    }

    public String getAuthServerUrl(String path) {
        return getExternalUrl(authServerRoot, path);
    }

    @Override
    public String getUrl(String path) {
        return getExternalUrl(rootPath, path);
    }

    private String getExternalUrl(String root, String path) {
        if (path.startsWith("http")) {
            try {
                return URLDecoder.decode(path, "UTF-8");
            } catch (UnsupportedEncodingException e) {
                throw new IllegalStateException(e);
            }
        }
        if (!path.startsWith("/")) {
            path = "/" + path;
        }
        return root + path;
    }

    public ResponseEntity<String> postForString(String path, MultiValueMap<String, String> formData) {
        return postForString(path, formData, new HttpHeaders());
    }

    public ResponseEntity<String> postForString(String path, MultiValueMap<String, String> formData, HttpHeaders headers) {
        if (headers.getContentType() == null) {
            headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        }
        return client.exchange(getUrl(path), HttpMethod.POST, new HttpEntity<MultiValueMap<String, String>>(formData,
                        headers), String.class);
    }

    @SuppressWarnings("rawtypes")
    public ResponseEntity<Map> postForMap(String path, MultiValueMap<String, String> formData) {
        return postForMap(path, formData, new HttpHeaders());
    }

    @SuppressWarnings("rawtypes")
    public ResponseEntity<Map> postForMap(String path, MultiValueMap<String, String> formData, HttpHeaders headers) {
        if (headers.getContentType() == null) {
            headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        }
        return client.exchange(getUrl(path), HttpMethod.POST, new HttpEntity<MultiValueMap<String, String>>(formData,
                        headers), Map.class);
    }

    public ResponseEntity<String> getForString(String path) {
        ResponseEntity<String> exchange = client.exchange(getUrl(path), HttpMethod.GET, new HttpEntity<Void>(
                        (Void) null), String.class);
        logger.debug("Response headers: " + exchange.getHeaders());
        return exchange;
    }

    public ResponseEntity<String> getForString(String path, final HttpHeaders headers) {
        HttpEntity<Void> request = new HttpEntity<Void>(null, headers);
        ResponseEntity<String> exchange = client.exchange(getUrl(path), HttpMethod.GET, request, String.class);
        logger.debug("Response headers: " + exchange.getHeaders());
        return exchange;
    }

    public ResponseEntity<Void> getForResponse(String path, final HttpHeaders headers, Object... uriVariables) {
        HttpEntity<Void> request = new HttpEntity<Void>(null, headers);
        ResponseEntity<Void> exchange = client
                        .exchange(getUrl(path), HttpMethod.GET, request, Void.class, uriVariables);
        logger.debug("Response headers: " + exchange.getHeaders());
        return exchange;
    }

    public ResponseEntity<Void> postForResponse(String path, HttpHeaders headers, MultiValueMap<String, String> params) {
        HttpHeaders actualHeaders = new HttpHeaders();
        actualHeaders.putAll(headers);
        actualHeaders.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

        ResponseEntity<Void> exchange = client.exchange(getUrl(path), HttpMethod.POST,
                        new HttpEntity<MultiValueMap<String, String>>(params, actualHeaders), Void.class);
        logger.debug("Response headers: " + exchange.getHeaders());
        return exchange;
    }

    @Override
    public void setRestTemplate(RestOperations restTemplate) {
        client = restTemplate;
    }

    @Override
    public RestOperations getRestTemplate() {
        return client;
    }

    public RestOperations createRestTemplate() {
        RestTemplate client = new RestTemplate(new SimpleClientHttpRequestFactory() {
            @Override
            protected void prepareConnection(HttpURLConnection connection, String httpMethod) throws IOException {
                super.prepareConnection(connection, httpMethod);
                connection.setInstanceFollowRedirects(false);
            }
        });
        client.setErrorHandler(new ResponseErrorHandler() {
            // Pass errors through in response entity for status code analysis
            @Override
            public boolean hasError(ClientHttpResponse response) throws IOException {
                return false;
            }

            @Override
            public void handleError(ClientHttpResponse response) throws IOException {
            }
        });
        return client;
    }

    public UriBuilder buildUri(String url) {
        return UriBuilder.fromUri(url.startsWith("http:") ? url : getUrl(url));
    }

    public static class UriBuilder {

        private final String url;

        private MultiValueMap<String, String> params = new LinkedMultiValueMap<String, String>();

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
                            builder.append(key + "=" + UriUtils.encodeQueryParam(value, "UTF-8"));
                        }
                    }
                }
                return new URI(builder.toString());
            } catch (UnsupportedEncodingException ex) {
                // should not happen, UTF-8 is always supported
                throw new IllegalStateException(ex);
            } catch (URISyntaxException ex) {
                throw new IllegalArgumentException("Could not create URI from [" + builder + "]: " + ex, ex);
            }
        }

    }

}
