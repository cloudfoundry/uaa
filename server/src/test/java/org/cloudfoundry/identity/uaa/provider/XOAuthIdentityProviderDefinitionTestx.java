/*
 * ****************************************************************************
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
 * ****************************************************************************
 */

package org.cloudfoundry.identity.uaa.provider;

import org.cloudfoundry.identity.uaa.util.UaaUrlUtils;
import org.junit.Before;
import org.junit.Test;
import org.springframework.mock.web.MockHttpServletRequest;

import java.io.UnsupportedEncodingException;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLEncoder;
import java.util.Arrays;

import static org.hamcrest.Matchers.startsWith;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThat;
import static org.springframework.http.HttpMethod.GET;


public class XOAuthIdentityProviderDefinitionTestx {

    private OIDCIdentityProviderDefinition oidc;
    private RawXOAuthIdentityProviderDefinition oauth;


    private String baseExpect = "https://oidc10.identity.cf-app.com/oauth/authorize?client_id=%s&response_type=%s&redirect_uri=%s&scope=%s%s";
    private String redirectUri;
    private MockHttpServletRequest request;

    @Before
    public void setup() throws MalformedURLException {
        oidc = new OIDCIdentityProviderDefinition();
        oauth = new RawXOAuthIdentityProviderDefinition();
        request = new MockHttpServletRequest(GET.name(), "/uaa/login");
        request.setContextPath("/uaa");
        request.setServletPath("/login");
        request.setScheme("https");
        request.setServerName("localhost");
        request.setServerPort(8443);

        for (AbstractXOAuthIdentityProviderDefinition def : Arrays.asList(oidc, oauth)) {
            def.setAuthUrl(new URL("https://oidc10.identity.cf-app.com/oauth/authorize"));
            def.setTokenUrl(new URL("https://oidc10.identity.cf-app.com/oauth/token"));
            def.setTokenKeyUrl(new URL("https://oidc10.identity.cf-app.com/token_keys"));
            def.setScopes(Arrays.asList("openid","password.write"));
            def.setRelyingPartyId("clientId");
            if (def == oidc) {
                def.setResponseType("id_token code");
            } else {
                def.setResponseType("code");
            }
        }

        redirectUri = URLEncoder.encode("https://localhost:8443/uaa/login/callback/alias");
    }

    @Test
    public void getParameterizedClass() throws Exception {
        assertEquals(OIDCIdentityProviderDefinition.class, oidc.getParameterizedClass());
        assertEquals(RawXOAuthIdentityProviderDefinition.class, oauth.getParameterizedClass());
    }

    @Test
    public void nonce_included_on_oidc() throws UnsupportedEncodingException {
        String expected = String.format(baseExpect, oidc.getRelyingPartyId(), URLEncoder.encode("id_token code"), redirectUri, URLEncoder.encode("openid password.write"), "&nonce=");
        assertThat(oidc.getCompleteAuthorizationURI(UaaUrlUtils.getBaseURL(request), "alias"), startsWith(expected));
    }

    @Test
    public void nonce_not_included_on_oauth() throws UnsupportedEncodingException {
        String expected = String.format(baseExpect, oauth.getRelyingPartyId(), URLEncoder.encode("code"), redirectUri, URLEncoder.encode("openid password.write"), "");
        assertEquals(oauth.getCompleteAuthorizationURI(UaaUrlUtils.getBaseURL(request), "alias"), expected);
    }
}