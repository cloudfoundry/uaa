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
package org.cloudfoundry.identity.api.web;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.cloudfoundry.identity.uaa.test.UrlHelper;
import org.junit.Assume;
import org.junit.internal.AssumptionViolatedException;
import org.junit.rules.TestWatchman;
import org.junit.runners.model.FrameworkMethod;
import org.junit.runners.model.Statement;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.http.client.ClientHttpResponse;
import org.springframework.http.client.SimpleClientHttpRequestFactory;
import org.springframework.security.oauth2.client.test.RestTemplateHolder;
import org.springframework.web.client.ResponseErrorHandler;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestOperations;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriTemplate;

import java.io.IOException;
import java.net.HttpURLConnection;

import static org.junit.Assert.fail;

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

    private static Logger logger = LoggerFactory.getLogger(ServerRunning.class);

    private static int DEFAULT_PORT = 8080;

    private static int DEFAULT_UAA_PORT = 8080;

    private static String DEFAULT_HOST = "localhost";

    private static final String DEFAULT_AUTH_SERVER_ROOT = "/uaa";

    private String authServerRoot = DEFAULT_AUTH_SERVER_ROOT;

    private int port;

    private int uaaPort;

    private String hostName = DEFAULT_HOST;

    private RestOperations client;

    /**
     * @return a new rule that assumes an existing running broker
     */
    public static ServerRunning isRunning() {
        return new ServerRunning();
    }

    private ServerRunning() {
        setPort(DEFAULT_PORT);
        setUaaPort(DEFAULT_UAA_PORT);
        setHostName(DEFAULT_HOST);
    }

    public void setUaaPort(int uaaPort) {
        this.uaaPort = uaaPort;
    }

    /**
     * @param port the port to set
     */
    public void setPort(int port) {
        this.port = port;
        client = createRestTemplate();
    }

    /**
     * @param hostName the hostName to set
     */
    public void setHostName(String hostName) {
        this.hostName = hostName;
    }

    @Override
    public Statement apply(Statement base, FrameworkMethod method, Object target) {
        try {
            RestTemplate client = new RestTemplate();
            client.getForEntity(new UriTemplate(getUrl("/uaa/login", uaaPort)).toString(), String.class);
            client.getForEntity(new UriTemplate(getUrl("/api/index.html")).toString(), String.class);
            logger.debug("Basic connectivity test passed");
        } catch (RestClientException e) {
            failTest();
        }

        return super.apply(base, method, target);
    }

    private void failTest() {
        fail(String.format("Not executing tests because basic connectivity test failed for hostName=%s, port=%d", hostName, port));
    }

    @Override
    public String getBaseUrl() {
        return "http://" + hostName + ":" + port;
    }

    @Override
    public String getAccessTokenUri() {
        return getUrl(authServerRoot + "/oauth/token");
    }

    @Override
    public String getAuthorizationUri() {
        return getUrl(authServerRoot + "/oauth/authorize");
    }

    @Override
    public String getClientsUri() {
        return getUrl(authServerRoot + "/oauth/clients");
    }

    @Override
    public String getUsersUri() {
        return getUrl(authServerRoot + "/Users");
    }

    @Override
    public String getUserUri() {
        return getUrl(authServerRoot + "/Users");
    }

    @Override
    public String getUrl(String path) {
        return getUrl(path, port);
    }

    public String getUrl(String path, int port) {
        if (path.startsWith("http:")) {
            return path;
        }
        if (!path.startsWith("/")) {
            path = "/" + path;
        }
        return "http://" + hostName + ":" + port + path;
    }

    public ResponseEntity<String> getForString(String path) {
        return getForString(path, new HttpHeaders());
    }

    public ResponseEntity<String> getForString(String path, HttpHeaders headers) {
        HttpEntity<Void> request = new HttpEntity<Void>((Void) null, headers);
        return client.exchange(getUrl(path), HttpMethod.GET, request, String.class);
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
        RestTemplate client = new RestTemplate();
        client.setRequestFactory(new SimpleClientHttpRequestFactory() {
            @Override
            protected void prepareConnection(HttpURLConnection connection, String httpMethod) throws IOException {
                super.prepareConnection(connection, httpMethod);
                connection.setInstanceFollowRedirects(false);
            }
        });
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
}
