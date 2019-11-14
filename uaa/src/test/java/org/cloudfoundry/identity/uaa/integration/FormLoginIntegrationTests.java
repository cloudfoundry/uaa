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
package org.cloudfoundry.identity.uaa.integration;

import org.apache.http.Header;
import org.apache.http.HttpHeaders;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpUriRequest;
import org.apache.http.client.methods.RequestBuilder;
import org.apache.http.impl.client.BasicCookieStore;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.message.BasicHeader;
import org.apache.http.util.EntityUtils;
import org.cloudfoundry.identity.uaa.ServerRunning;
import org.cloudfoundry.identity.uaa.integration.util.IntegrationTestUtils;
import org.cloudfoundry.identity.uaa.test.TestAccountSetup;
import org.cloudfoundry.identity.uaa.test.UaaTestAccounts;
import org.cloudfoundry.identity.uaa.security.web.CookieBasedCsrfTokenRepository;
import org.junit.After;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.springframework.http.MediaType;

import java.util.Collections;
import java.util.List;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.springframework.http.HttpStatus.FOUND;
import static org.springframework.http.HttpStatus.OK;

public class FormLoginIntegrationTests {

    @Rule
    public ServerRunning serverRunning = ServerRunning.isRunning();

    private UaaTestAccounts testAccounts = UaaTestAccounts.standard(serverRunning);

    @Rule
    public TestAccountSetup testAccountSetup = TestAccountSetup.standard(serverRunning, testAccounts);

    Header header = new BasicHeader(HttpHeaders.ACCEPT, MediaType.TEXT_HTML_VALUE);
    List<Header> headers = Collections.singletonList(header);

    BasicCookieStore cookieStore = new BasicCookieStore();
    CloseableHttpClient httpclient;

    @Before
    public void createHttpClient() {
        httpclient = HttpClients.custom()
            .setDefaultRequestConfig(RequestConfig.DEFAULT)
            .setDefaultHeaders(headers)
            .setDefaultCookieStore(cookieStore)
            .build();
    }

    @After
    public void closeClient() throws Exception {
        httpclient.close();
    }


    @Test
    public void testUnauthenticatedRedirect() throws Exception {
        String location = serverRunning.getBaseUrl() + "/";
        HttpGet httpget = new HttpGet(location);
        httpget.setConfig(
            RequestConfig.custom().setRedirectsEnabled(false).build()
        );
        CloseableHttpResponse response = httpclient.execute(httpget);
        assertEquals(FOUND.value(), response.getStatusLine().getStatusCode());
        location = response.getFirstHeader("Location").getValue();
        response.close();
        httpget.completed();
        assertTrue(location.contains("/login"));
    }

    @Test
    public void testSuccessfulAuthenticationFlow() throws Exception {
        //request home page /
        String location = serverRunning.getBaseUrl() + "/";
        HttpGet httpget = new HttpGet(location);
        CloseableHttpResponse response = httpclient.execute(httpget);

        assertEquals(OK.value(), response.getStatusLine().getStatusCode());

        String body = EntityUtils.toString(response.getEntity());
        EntityUtils.consume(response.getEntity());
        response.close();
        httpget.completed();

        assertTrue(body.contains("/login.do"));
        assertTrue(body.contains("username"));
        assertTrue(body.contains("password"));

        String csrf = IntegrationTestUtils.extractCookieCsrf(body);

        HttpUriRequest loginPost = RequestBuilder.post()
            .setUri(serverRunning.getBaseUrl() + "/login.do")
            .addParameter("username",testAccounts.getUserName())
            .addParameter("password",testAccounts.getPassword())
            .addParameter(CookieBasedCsrfTokenRepository.DEFAULT_CSRF_COOKIE_NAME, csrf)
            .build();

        response = httpclient.execute(loginPost);
        assertEquals(FOUND.value(), response.getStatusLine().getStatusCode());
        location = response.getFirstHeader("Location").getValue();
        response.close();

        httpget = new HttpGet(location);
        response = httpclient.execute(httpget);
        assertEquals(OK.value(), response.getStatusLine().getStatusCode());

        body = EntityUtils.toString(response.getEntity());
        response.close();
        assertTrue(body.contains("Sign Out"));
    }

}
