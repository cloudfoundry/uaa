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

import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.springframework.security.oauth2.common.exceptions.RedirectMismatchException;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;

import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_AUTHORIZATION_CODE;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.Assert.*;

public class AntPathRedirectResolverTests {

    private final String requestedRedirectHttp  = "http://subdomain.domain.com/path1/path2?query1=value1&query2=value2";
    private final String requestedRedirectHttps = "https://subdomain.domain.com/path1/path2?query1=value1&query2=value2";
    private final AntPathRedirectResolver resolver = new AntPathRedirectResolver();

    @Test
    public void noTrailingAsterisk() {
        final String clientRedirectUri = "http://subdomain.domain.com/";
        assertTrue(resolver.redirectMatches("http://subdomain.domain.com/", clientRedirectUri));
        assertTrue(resolver.redirectMatches("http://subdomain.domain.com/one", clientRedirectUri));
        assertTrue(resolver.redirectMatches("http://subdomain.domain.com/one/", clientRedirectUri));
        assertTrue(resolver.redirectMatches("http://subdomain.domain.com/one/two", clientRedirectUri));
        assertTrue(resolver.redirectMatches("http://subdomain.domain.com/one/two/three", clientRedirectUri));
    }

    @Test
    public void singleTrailingAsterisk() {
        final String clientRedirectUri = "http://subdomain.domain.com/*";
        assertTrue(resolver.redirectMatches("http://subdomain.domain.com/", clientRedirectUri));
        assertTrue(resolver.redirectMatches("http://subdomain.domain.com/one", clientRedirectUri));
        assertFalse(resolver.redirectMatches("http://subdomain.domain.com/one/", clientRedirectUri));
        assertFalse(resolver.redirectMatches("http://subdomain.domain.com/one/two", clientRedirectUri));
        assertFalse(resolver.redirectMatches("http://subdomain.domain.com/one/two/three", clientRedirectUri));
    }

    @Test
    public void singleTrailingAsterisk_withPath() {
        final String clientRedirectUri = "http://subdomain.domain.com/one*";
        assertFalse(resolver.redirectMatches("http://subdomain.domain.com/", clientRedirectUri));
        assertTrue(resolver.redirectMatches("http://subdomain.domain.com/one", clientRedirectUri));
        assertTrue(resolver.redirectMatches("http://subdomain.domain.com/one-foo-bar", clientRedirectUri));
        assertFalse(resolver.redirectMatches("http://subdomain.domain.com/one/", clientRedirectUri));
        assertFalse(resolver.redirectMatches("http://subdomain.domain.com/one/two", clientRedirectUri));
        assertFalse(resolver.redirectMatches("http://subdomain.domain.com/one/two/three", clientRedirectUri));
    }

    @Test
    public void singleAsterisk_insidePath() {
        String clientRedirectUri = "http://subdomain.domain.com/one/*/four";
        assertFalse(resolver.redirectMatches("http://subdomain.domain.com/one/four", clientRedirectUri));
        assertTrue(resolver.redirectMatches("http://subdomain.domain.com/one/middle/four", clientRedirectUri));
        assertFalse(resolver.redirectMatches("http://subdomain.domain.com/one/two/three/four", clientRedirectUri));
    }

    @Test
    public void redirect_Matches_Happy_Day() {
        String path = "**";
        assertTrue(resolver.redirectMatches(requestedRedirectHttp, path));
        assertTrue(resolver.redirectMatches(requestedRedirectHttps, path));
    }

    @Test
    public void clientWithValidRedirectUri_shouldResolve() {
        ClientDetails clientDetails = new BaseClientDetails("client1", "", "openid", GRANT_TYPE_AUTHORIZATION_CODE,"", requestedRedirectHttp);
        String resolvedRedirect = resolver.resolveRedirect(requestedRedirectHttp, clientDetails);
        assertThat(resolvedRedirect, equalTo(requestedRedirectHttp));
    }

    @Rule
    public ExpectedException expectedException = ExpectedException.none();

    @Test
    public void clientMissingRedirectUri() {
        expectedException.expect(RedirectMismatchException.class);
        expectedException.expectMessage(containsString("Client registration is missing redirect_uri"));

        ClientDetails clientDetails = new BaseClientDetails("client1", "", "openid", GRANT_TYPE_AUTHORIZATION_CODE,"");
        resolver.resolveRedirect(requestedRedirectHttp, clientDetails);
    }

    @Test
    public void clientWithInvalidRedirectUri() {
        expectedException.expect(RedirectMismatchException.class);
        expectedException.expectMessage(containsString("Client registration contains invalid redirect_uri"));
        expectedException.expectMessage(containsString("*,  */*"));

        ClientDetails clientDetails = new BaseClientDetails("client1", "", "openid", GRANT_TYPE_AUTHORIZATION_CODE,"", "*, */*");
        resolver.resolveRedirect(requestedRedirectHttp, clientDetails);
    }

    @Test
    public void redirect_Any_Scheme() {
        String path = "http*://subdomain.domain.com/**";
        assertTrue(resolver.redirectMatches(requestedRedirectHttp, path));
        assertTrue(resolver.redirectMatches(requestedRedirectHttps, path));
    }

    @Test
    public void redirect_Http_Only_Scheme() {
        String path = "http://subdomain.domain.com/**";
        assertTrue(resolver.redirectMatches(requestedRedirectHttp, path));
        assertFalse(resolver.redirectMatches(requestedRedirectHttps, path));
    }

    @Test
    public void redirect_Https_Only_Scheme() {
        String path = "https://subdomain.domain.com/**";
        assertTrue(resolver.redirectMatches(requestedRedirectHttps, path));
        assertFalse(resolver.redirectMatches(requestedRedirectHttp, path));
    }

    @Test
    public void redirect_Query_Path() {
        String path = "http*://subdomain.domain.com/path1/path2**";
        assertTrue(resolver.redirectMatches(requestedRedirectHttps, path));
        assertTrue(resolver.redirectMatches(requestedRedirectHttp, path));

        path = "http*://subdomain.domain.com/path1/path3**";
        assertFalse(resolver.redirectMatches(requestedRedirectHttps, path));
        assertFalse(resolver.redirectMatches(requestedRedirectHttp, path));
    }

    @Test
    public void redirect_Subdomain() {
        String path = "http*://*.domain.com/path1/path2**";
        assertTrue(resolver.redirectMatches(requestedRedirectHttps, path));
        assertTrue(resolver.redirectMatches(requestedRedirectHttp, path));

        path = "http*://*.domain.com/path1/path3**";
        assertFalse(resolver.redirectMatches(requestedRedirectHttps, path));
        assertFalse(resolver.redirectMatches(requestedRedirectHttp, path));
    }
}