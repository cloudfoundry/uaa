/*
 * *****************************************************************************
 *      Cloud Foundry
 *      Copyright (c) [2009-2015] Pivotal Software, Inc. All Rights Reserved.
 *
 *      This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *      You may not use this product except in compliance with the License.
 *
 *      This product includes a number of subcomponents with
 *      separate copyright notices and license terms. Your use of these
 *      subcomponents is subject to the terms and conditions of the
 *      subcomponent's license, as noted in the LICENSE file.
 * *****************************************************************************
 */

package org.cloudfoundry.identity.uaa.oauth;

import org.junit.Assert;
import org.junit.Test;
import org.springframework.security.oauth2.common.exceptions.RedirectMismatchException;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;

import static org.hamcrest.Matchers.containsString;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

public class AntPathRedirectResolverTests {

    String requestedRedirectHttp  = "http://subdomain.domain.com/path1/path2?query1=value1&query2=value2";
    String requestedRedirectHttps = "https://subdomain.domain.com/path1/path2?query1=value1&query2=value2";
    AntPathRedirectResolver resolver = new AntPathRedirectResolver();

    @Test
    public void test_Redirect_Matches_Happy_Day() throws Exception {
        String path = "**";
        assertTrue(resolver.redirectMatches(requestedRedirectHttp, path));
        assertTrue(resolver.redirectMatches(requestedRedirectHttps, path));
    }

    @Test
    public void testClientMissingRedirectUri() {
        ClientDetails clientDetails = new BaseClientDetails("client1", "", "openid","authorization_code","");
        try {
            resolver.resolveRedirect(requestedRedirectHttp, clientDetails);
            fail();
        } catch (RedirectMismatchException e) {
            String reason = "Client registration is missing redirect_uri";
            Assert.assertThat(e.getMessage(), containsString(reason));
        }
    }

    @Test
    public void testClientWithInvalidRedirectUri() {
        ClientDetails clientDetails = new BaseClientDetails("client1", "", "openid","authorization_code","", "*, */*");
        try {
            resolver.resolveRedirect(requestedRedirectHttp, clientDetails);
            fail();
        } catch (RedirectMismatchException e) {
            String reason = "Client registration contains invalid redirect_uri";
            Assert.assertThat(e.getMessage(), containsString(reason));
            Assert.assertThat(e.getMessage(), containsString("*,  */*"));
        }
    }

    @Test
    public void test_Redirect_Any_Scheme() throws Exception {
        String path = "http*://subdomain.domain.com/**";
        assertTrue(resolver.redirectMatches(requestedRedirectHttp, path));
        assertTrue(resolver.redirectMatches(requestedRedirectHttps, path));
    }

    @Test
    public void test_Redirect_Http_Only_Scheme() throws Exception {
        String path = "http://subdomain.domain.com/**";
        assertTrue(resolver.redirectMatches(requestedRedirectHttp, path));
        assertFalse(resolver.redirectMatches(requestedRedirectHttps, path));
    }

    @Test
    public void test_Redirect_Https_Only_Scheme() throws Exception {
        String path = "https://subdomain.domain.com/**";
        assertTrue(resolver.redirectMatches(requestedRedirectHttps, path));
        assertFalse(resolver.redirectMatches(requestedRedirectHttp, path));
    }

    @Test
    public void test_Redirect_Query_Path() throws Exception {
        String path = "http*://subdomain.domain.com/path1/path2**";
        assertTrue(resolver.redirectMatches(requestedRedirectHttps, path));
        assertTrue(resolver.redirectMatches(requestedRedirectHttp, path));

        path = "http*://subdomain.domain.com/path1/path3**";
        assertFalse(resolver.redirectMatches(requestedRedirectHttps, path));
        assertFalse(resolver.redirectMatches(requestedRedirectHttp, path));
    }

    @Test
    public void test_Redirect_Subdomain() throws Exception {
        String path = "http*://*.domain.com/path1/path2**";
        assertTrue(resolver.redirectMatches(requestedRedirectHttps, path));
        assertTrue(resolver.redirectMatches(requestedRedirectHttp, path));

        path = "http*://*.domain.com/path1/path3**";
        assertFalse(resolver.redirectMatches(requestedRedirectHttps, path));
        assertFalse(resolver.redirectMatches(requestedRedirectHttp, path));
    }
}