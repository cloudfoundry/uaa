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
import org.apache.hc.client5.http.impl.classic.CloseableHttpResponse;
import org.apache.hc.core5.http.Header;
import org.apache.hc.core5.http.HttpHeaders;
import org.apache.hc.client5.http.config.RequestConfig;
import org.apache.hc.client5.http.classic.methods.HttpGet;
import org.apache.hc.client5.http.classic.methods.HttpUriRequest;
import org.apache.hc.client5.http.cookie.BasicCookieStore;
import org.apache.hc.client5.http.cookie.Cookie;
import org.apache.hc.client5.http.cookie.StandardCookieSpec;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.client5.http.impl.classic.HttpClients;
import org.apache.hc.core5.http.io.entity.EntityUtils;
import org.apache.hc.core5.http.io.support.ClassicRequestBuilder;
import org.apache.hc.core5.http.message.BasicHeader;
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
import static org.junit.Assert.assertNotNull;
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
            .setDefaultRequestConfig(RequestConfig.custom().setCookieSpec(StandardCookieSpec.RELAXED).build())
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
        assertEquals(FOUND.value(), response.getCode());
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

        assertEquals(OK.value(), response.getCode());

        String body = EntityUtils.toString(response.getEntity());
        EntityUtils.consume(response.getEntity());
        response.close();
        httpget.completed();

        assertTrue(body.contains("/login.do"));
        assertTrue(body.contains("username"));
        assertTrue(body.contains("password"));

        String csrf = IntegrationTestUtils.extractCookieCsrf(body);

        HttpUriRequest loginPost = ClassicRequestBuilder.post()
            .setUri(serverRunning.getBaseUrl() + "/login.do")
            .addParameter("username",testAccounts.getUserName())
            .addParameter("password",testAccounts.getPassword())
            .addParameter(CookieBasedCsrfTokenRepository.DEFAULT_CSRF_COOKIE_NAME, csrf)
            .build();

        response = httpclient.execute(loginPost);
        assertEquals(FOUND.value(), response.getCode());
        location = response.getFirstHeader("Location").getValue();
        response.close();

        // This implementation of httpclient would not send the `JSESSIONID` cookie that has `Secure` attribute
        // to the locally-run server via HTTP; the other integration tests use webdriver to simulate web flows, which would make
        // an exception for HTTP on localhost (which is the standard [browser behavior](https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies))
        // As a workaround, manually attach the `JSESSIONID` cookie (obtained via login) to this request.
        Cookie jsessionidCookie = cookieStore.getCookies().stream()
                .filter(cookie -> "JSESSIONID".equals(cookie.getName()))
                .findAny().orElse(null);
        assertNotNull(jsessionidCookie);
        HttpUriRequest getRequestAfterLogin = ClassicRequestBuilder.get()
                .setUri(location)
                .addHeader("Cookie", "JSESSIONID=" + jsessionidCookie.getValue())
                .build();

        response = httpclient.execute(getRequestAfterLogin);
        assertEquals(OK.value(), response.getCode());

        body = EntityUtils.toString(response.getEntity());
        response.close();
        assertTrue(body.contains("Sign Out"));
    }

}
