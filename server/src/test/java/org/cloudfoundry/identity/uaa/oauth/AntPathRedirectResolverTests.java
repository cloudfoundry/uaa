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

import org.junit.Test;

import static org.junit.Assert.*;

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